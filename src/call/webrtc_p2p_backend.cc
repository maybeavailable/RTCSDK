#include "call/webrtc_p2p_backend.h"

#include <algorithm>
#include <cctype>

#include <openssl/rand.h>

#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {

GoogCcConfig MakeGoogCcConfig(const EngineConfig& cfg) {
  GoogCcConfig g;
  g.min_bitrate = DataRate::BitsPerSec(cfg.min_bitrate_bps);
  g.start_bitrate = DataRate::BitsPerSec(cfg.start_bitrate_bps);
  g.max_bitrate = DataRate::BitsPerSec(cfg.max_bitrate_bps);
  return g;
}

uint32_t GenerateNonZeroSsrc() {
  uint32_t val = 0;
  do {
    RAND_bytes(reinterpret_cast<uint8_t*>(&val), sizeof(val));
    val &= 0x7FFFFFFFu;
  } while (val < 1000);
  return val;
}

}  // namespace

WebRtcP2pBackend::WebRtcP2pBackend(Clock* clock,
                                   SdkTaskQueues* queues,
                                   const EngineConfig& config,
                                   ISessionBackendObserver* observer)
    : clock_(clock),
      queues_(queues),
      config_(config),
      observer_(observer),
      sig_checker_(queues->signaling()),
      work_checker_(queues->worker()),
      negotiated_codec_(static_cast<VideoCodec>(config.publish_codec)),
      negotiated_has_flexfec_(config.enable_flexfec),
      sctp_dc_(clock, this),
      goog_cc_(MakeGoogCcConfig(config)),
      sig_safety_(PendingTaskSafetyFlag::CreateDetached()),
      work_safety_(PendingTaskSafetyFlag::CreateDetached()),
      net_safety_(PendingTaskSafetyFlag::CreateDetached()) {
  EnsureLibsrtpInitialized();
  local_cert_ = DtlsCertificate::GenerateEcdsaP256();

  outbound_.media_ssrc = GenerateNonZeroSsrc();
  outbound_.rtx_ssrc = outbound_.media_ssrc + 1;
  outbound_.flexfec_ssrc =
      config_.enable_flexfec ? (outbound_.media_ssrc + 2) : 0;
  if (config_.enable_flexfec) {
    outbound_.flexfec = std::make_unique<FlexfecSender>(
        negotiated_flexfec_pt_, outbound_.flexfec_ssrc, outbound_.media_ssrc,
        negotiated_mid_);
  }

  paced_sender_ =
      std::make_unique<TaskQueuePacedSender>(clock_, this, queues_->pacer());
}

WebRtcP2pBackend::~WebRtcP2pBackend() { StopSession(); }

std::string WebRtcP2pBackend::GenerateRandomToken(size_t length) {
  static constexpr char kChars[] =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  std::vector<uint8_t> rnd(length);
  RAND_bytes(rnd.data(), static_cast<int>(rnd.size()));
  std::string out(length, '0');
  for (size_t i = 0; i < length; ++i) {
    out[i] = kChars[rnd[i] % (sizeof(kChars) - 1)];
  }
  return out;
}

bool WebRtcP2pBackend::ParseIceServerUri(const IceServerConfig& cfg,
                                         TurnServerSpec* out_spec) {
  return IceTransportChannel::ParseIceServerUri(cfg.uri, cfg.username,
                                                cfg.password, out_spec);
}

bool WebRtcP2pBackend::EnsureTransportInitializedOnSigQueue() {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  if (transport_initialized_) {
    return true;
  }

  std::vector<TurnServerSpec> turn_specs;
  for (const auto& s : config_.ice_servers) {
    TurnServerSpec spec;
    if (ParseIceServerUri(s, &spec)) {
      turn_specs.push_back(std::move(spec));
    }
  }

  IceParameters local_ice;
  local_ice.ufrag = GenerateRandomToken(8);
  local_ice.pwd = GenerateRandomToken(24);
  local_ice.ice_lite = false;

  ice_ = std::make_unique<IceTransportChannel>(clock_, queues_->network(),
                                               nullptr, true);
  dtls_srtp_ = std::make_unique<DtlsSrtpTransport>(
      clock_, queues_->network(), ice_.get(), local_cert_, this);
  ice_->set_observer(dtls_srtp_.get());

  dtls_srtp_->set_on_candidate_gathered([this](const IceCandidate& cand) {
    const std::string cand_attr = cand.ToSdpAttribute();
    queues_->signaling()->PostTask(
        SafeTask(sig_safety_.flag(), [this, cand_attr]() {
          RTC_DCHECK_RUN_ON(&sig_checker_);
          if (observer_ != nullptr) {
            observer_->OnBackendLocalIceCandidate(negotiated_mid_, 0, cand_attr);
          }
          if (signaling_ && signaling_joined_) {
            JsonObject msg;
            msg.SetString("type", "candidate");
            msg.SetString("room_id", room_id_);
            msg.SetString("peer_id", local_peer_id_);
            msg.SetString("sdpMid", negotiated_mid_);
            msg.SetUint32("sdpMLineIndex", 0);
            msg.SetString("candidate", cand_attr);
            signaling_->SendText(msg.Serialize());
          }
        }));
  });

  ice_->SetLocalIceParameters(local_ice);
  ice_->ConfigureServers(turn_specs);
  if (!ice_->StartGatheringAndBind(0)) {
    return false;
  }

  queues_->worker()->PostTask(SafeTask(work_safety_.flag(), [this]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    inbound_ = std::make_unique<InboundStreamState>(
        negotiated_codec_, clock_->CurrentTime(), config_.zero_playout_delay);
    RtpDemuxCriteria crit;
    crit.mid = negotiated_mid_;
    demuxer_.AddSink(crit, this);
    demuxer_.SetDefaultSink(this);

    paced_sender_->EnsureStarted();
    const auto init_upd = goog_cc_.OnProcessInterval(clock_->CurrentTime());
    ApplyNetworkControlUpdate(init_upd);
    OnWorkerPeriodicTick();
  }));

  transport_initialized_ = true;
  return true;
}

int WebRtcP2pBackend::StartSession(const std::string& room_id,
                                   const std::string& local_peer_id) {
  queues_->signaling()->PostTask(
      SafeTask(sig_safety_.flag(), [this, room_id, local_peer_id]() {
        RTC_DCHECK_RUN_ON(&sig_checker_);
        room_id_ = room_id;
        local_peer_id_ = local_peer_id;
        if (observer_ != nullptr) {
          observer_->OnBackendConnectionState(RTC_CONN_STATE_CONNECTING, 0);
        }
        if (!EnsureTransportInitializedOnSigQueue()) {
          if (observer_ != nullptr) {
            observer_->OnBackendConnectionState(RTC_CONN_STATE_FAILED, -1);
          }
          return;
        }

        if (!config_.signaling_or_moq_url.empty()) {
          signaling_ = std::make_unique<BoostBeastSignalingClient>(
              queues_->signaling());
          signaling_->set_on_connected([this]() { OnSignalingConnected(); });
          signaling_->set_on_message(
              [this](const std::string& m) { OnSignalingMessage(m); });
          signaling_->set_on_closed(
              [this](int c, const std::string& r) { OnSignalingClosed(c, r); });
          signaling_->Connect(config_.signaling_or_moq_url);
        }
      }));
  return RTC_OK;
}

void WebRtcP2pBackend::StopSession() {
  media_ready_.store(false, std::memory_order_release);

  if (!queues_->signaling()->IsStopped()) {
    queues_->signaling()->Invoke([this]() {
      RTC_DCHECK_RUN_ON(&sig_checker_);
      sig_safety_.flag()->SetNotAlive();
      if (signaling_) {
        if (signaling_joined_) {
          JsonObject leave_msg;
          leave_msg.SetString("type", "leave");
          leave_msg.SetString("room_id", room_id_);
          leave_msg.SetString("peer_id", local_peer_id_);
          signaling_->SendText(leave_msg.Serialize());
          signaling_joined_ = false;
        }
        signaling_->Close();
      }
    });
  }
  if (!queues_->network()->IsStopped()) {
    queues_->network()->Invoke([this]() {
      net_safety_.flag()->SetNotAlive();
      if (ice_) {
        ice_->set_observer(nullptr);
      }
    });
  }
  if (!queues_->worker()->IsStopped()) {
    queues_->worker()->Invoke([this]() {
      RTC_DCHECK_RUN_ON(&work_checker_);
      work_safety_.flag()->SetNotAlive();
      sctp_dc_.Shutdown();
      demuxer_.RemoveSink(this);
      inbound_.reset();
    });
  }
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    valid_dc_ids_.clear();
  }
  paced_sender_.reset();
  dtls_srtp_.reset();
  ice_.reset();
  signaling_.reset();
}

void WebRtcP2pBackend::SetSimulatedRxDropRate(double drop_probability) {
  queues_->signaling()->Invoke([this, drop_probability]() {
    RTC_DCHECK_RUN_ON(&sig_checker_);
    if (ice_) {
      ice_->SetSimulatedRxDropRate(drop_probability);
    }
  });
}

PureVideoSdpDescription WebRtcP2pBackend::BuildLocalSdpOnSigQueue(
    const std::string& session_type,
    const std::string& dtls_setup,
    bool direction_send,
    bool direction_recv) const {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  if (!config_.ice_servers.empty() && config_.signaling_or_moq_url.empty()) {
    // 直连 W3C SDP 模式下无 Trickle ICE 后续增量通道，短暂等待异步 DNS 解析与 STUN 反射收集落盘。
    ice_->WaitForServerReflexiveGathering(TimeDelta::Millis(300));
  }
  PureVideoSdpDescription desc;
  desc.session_type = session_type;
  desc.ice_params = ice_->local_parameters();
  desc.dtls_fingerprint_sha256 = local_cert_->sha256_fingerprint();
  desc.dtls_setup = dtls_setup;
  desc.candidates = ice_->LocalCandidatesSnapshot();

  if (session_type == "offer" || negotiated_has_video_) {
    VideoMediaTrackDesc m;
    m.mid = negotiated_mid_;
    m.stream_id = local_peer_id_;
    m.track_id = local_peer_id_ + "_video0";
    m.cname = local_peer_id_;
    m.codec = negotiated_codec_;
    m.direction_send = direction_send;
    m.direction_recv = direction_recv;
    m.video_pt = negotiated_video_pt_;
    m.rtx_pt = negotiated_rtx_pt_;
    m.flexfec_pt = negotiated_flexfec_pt_;
    m.has_rtx = negotiated_has_rtx_;
    m.has_flexfec = negotiated_has_flexfec_ && config_.enable_flexfec;
    m.primary_ssrc = outbound_.media_ssrc;
    m.primary_rtx_ssrc = m.has_rtx ? outbound_.rtx_ssrc : 0;
    m.flexfec_ssrc = m.has_flexfec ? outbound_.flexfec_ssrc : 0;
    m.ext_map = negotiated_ext_map_;

    desc.video_m_sections.push_back(std::move(m));
  }

  if (config_.enable_datachannel &&
      (session_type == "offer" || negotiated_has_datachannel_)) {
    DataChannelMediaDesc dm;
    dm.mid = negotiated_data_mid_;
    if (!desc.video_m_sections.empty() && dm.mid == negotiated_mid_) {
      dm.mid = (negotiated_mid_ == "1") ? "data" : "1";
    }
    dm.sctp_port = local_sctp_port_;
    dm.max_message_size = 262144;
    desc.data_m_section = dm;
  }
  if (session_type == "answer" && !negotiated_m_order_.empty()) {
    desc.m_section_order = negotiated_m_order_;
  }
  return desc;
}

bool WebRtcP2pBackend::ApplyRemoteSdpOnSigQueue(
    const PureVideoSdpDescription& remote_desc,
    bool remote_is_offer,
    std::string* out_answer_sdp) {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  if ((remote_desc.video_m_sections.empty() &&
       !remote_desc.data_m_section.has_value()) ||
      remote_desc.dtls_fingerprint_sha256.empty()) {
    RTC_LOG(kError)
        << "Rejected remote SDP missing media/datachannel m= or fingerprint";
    return false;
  }

  negotiated_has_video_ = !remote_desc.video_m_sections.empty();
  negotiated_has_datachannel_ =
      config_.enable_datachannel && remote_desc.data_m_section.has_value();
  negotiated_m_order_ = remote_desc.m_section_order;
  if (negotiated_has_datachannel_) {
    negotiated_data_mid_ = remote_desc.data_m_section->mid.empty()
                               ? "1"
                               : remote_desc.data_m_section->mid;
    remote_sctp_port_ = remote_desc.data_m_section->sctp_port;
  }

  bool remote_sends = false;
  bool remote_recvs = false;
  std::string r_peer = remote_peer_id_;
  std::string r_track = remote_peer_id_ + "_video0";
  uint32_t r_media_ssrc = 0;
  uint32_t r_rtx_ssrc = 0;
  if (negotiated_has_video_) {
    const auto& rm = remote_desc.video_m_sections.front();
    negotiated_mid_ = rm.mid.empty() ? "0" : rm.mid;
    negotiated_codec_ = rm.codec;
    negotiated_video_pt_ = rm.video_pt;
    negotiated_has_rtx_ = rm.has_rtx;
    if (rm.has_rtx) {
      negotiated_rtx_pt_ = rm.rtx_pt;
    }
    negotiated_has_flexfec_ = rm.has_flexfec && config_.enable_flexfec;
    if (negotiated_has_flexfec_) {
      negotiated_flexfec_pt_ = rm.flexfec_pt;
    }
    negotiated_ext_map_ = rm.ext_map;
    remote_sends = rm.direction_send;
    remote_recvs = rm.direction_recv;
    if (!rm.stream_id.empty()) {
      r_peer = rm.stream_id;
    }
    if (!rm.track_id.empty()) {
      r_track = rm.track_id;
    } else {
      r_track = r_peer + "_video0";
    }
    r_media_ssrc = rm.primary_ssrc;
    r_rtx_ssrc = rm.primary_rtx_ssrc;
  }

  ice_->SetIceControlling(!remote_is_offer);
  ice_->SetRemoteIceParameters(remote_desc.ice_params);
  for (const auto& cand : remote_desc.candidates) {
    ice_->AddRemoteCandidate(cand);
  }

  // RFC 5763 第 5 节 DTLS 角色协商（`actpass` / `active` / `passive`）：
  DtlsRole local_dtls_role = DtlsRole::kClient;
  std::string answer_dtls_setup = "active";
  if (remote_is_offer) {
    if (remote_desc.dtls_setup == "active") {
      local_dtls_role = DtlsRole::kServer;
      answer_dtls_setup = "passive";
    } else {
      local_dtls_role = DtlsRole::kClient;
      answer_dtls_setup = "active";
    }
  } else {
    local_dtls_role = (remote_desc.dtls_setup == "active") ? DtlsRole::kServer
                                                           : DtlsRole::kClient;
  }

  dtls_srtp_->SetRtpHeaderExtensionMap(negotiated_ext_map_);
  dtls_srtp_->SetDtlsRoleAndRemoteFingerprint(
      local_dtls_role, remote_desc.dtls_fingerprint_sha256);

  const VideoCodec r_codec = negotiated_codec_;
  const std::string mid_copy = negotiated_mid_;
  const uint8_t f_pt = negotiated_flexfec_pt_;
  const bool has_fec = negotiated_has_flexfec_;
  const bool has_vid = negotiated_has_video_;
  const bool has_dc = negotiated_has_datachannel_;
  const uint16_t r_sctp_port = remote_sctp_port_;

  queues_->worker()->PostTask(SafeTask(
      work_safety_.flag(),
      [this, r_peer, r_track, r_media_ssrc, r_rtx_ssrc, r_codec, mid_copy, f_pt,
       has_fec, has_vid, remote_sends, has_dc, local_dtls_role,
       r_sctp_port]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        worker_dtls_role_ = local_dtls_role;
        worker_has_datachannel_ = has_dc;
        worker_remote_sctp_port_ = r_sctp_port;
        if (has_dc && media_ready_.load(std::memory_order_acquire)) {
          sctp_dc_.ConfigureAndStart(worker_dtls_role_, local_sctp_port_,
                                     worker_remote_sctp_port_);
        }

        if (has_vid) {
          if (has_fec) {
            outbound_.flexfec = std::make_unique<FlexfecSender>(
                f_pt, outbound_.flexfec_ssrc, outbound_.media_ssrc, mid_copy);
          } else {
            outbound_.flexfec.reset();
          }

          inbound_ = std::make_unique<InboundStreamState>(
              r_codec, clock_->CurrentTime(), config_.zero_playout_delay);
          inbound_->remote_peer_id = r_peer;
          inbound_->remote_track_id = r_track;
          inbound_->media_ssrc = r_media_ssrc;
          inbound_->rtx_ssrc = r_rtx_ssrc;
          if (r_media_ssrc != 0) {
            inbound_->flexfec_rx =
                std::make_unique<FlexfecReceiver>(0, r_media_ssrc);
          }

          demuxer_.RemoveSink(this);
          RtpDemuxCriteria crit;
          crit.mid = mid_copy;
          if (r_media_ssrc != 0) {
            crit.ssrcs.push_back(r_media_ssrc);
          }
          if (r_rtx_ssrc != 0) {
            crit.ssrcs.push_back(r_rtx_ssrc);
          }
          demuxer_.AddSink(crit, this);
          demuxer_.SetDefaultSink(this);

          if (remote_sends && !inbound_->track_announced &&
              observer_ != nullptr) {
            inbound_->track_announced = true;
            observer_->OnBackendRemoteTrackPublished(r_peer, r_track, r_codec);
          }
        }
      }));

  if (remote_is_offer) {
    // RFC 3264 第 6.1 节 SDP Answer 媒体传输方向匹配：
    const bool answer_send = remote_recvs;
    const bool answer_recv = remote_sends;
    const auto answer = BuildLocalSdpOnSigQueue("answer", answer_dtls_setup,
                                                answer_send, answer_recv);
    if (out_answer_sdp != nullptr) {
      *out_answer_sdp = answer.Serialize();
    }
  }
  return true;
}

int WebRtcP2pBackend::CreateLocalOffer(std::string* out_sdp) {
  if (out_sdp == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  int result = RTC_ERR_INTERNAL;
  queues_->signaling()->Invoke([this, out_sdp, &result]() {
    RTC_DCHECK_RUN_ON(&sig_checker_);
    if (!EnsureTransportInitializedOnSigQueue()) {
      result = RTC_ERR_NOT_INITIALIZED;
      return;
    }
    ice_->SetIceControlling(true);
    negotiated_codec_ = static_cast<VideoCodec>(config_.publish_codec);
    negotiated_ext_map_ = RtpHeaderExtensionMap::BrowserDefault();
    dtls_srtp_->SetRtpHeaderExtensionMap(negotiated_ext_map_);
    const auto offer = BuildLocalSdpOnSigQueue("offer", "actpass", true, true);
    *out_sdp = offer.Serialize();
    offer_sent_ = true;
    result = RTC_OK;
  });
  return result;
}

int WebRtcP2pBackend::SetRemoteDescription(std::string_view sdp_type,
                                           std::string_view remote_sdp,
                                           std::string* out_answer_sdp) {
  if (remote_sdp.empty()) {
    return RTC_ERR_INVALID_ARG;
  }
  const bool is_offer = (sdp_type == "offer");
  const bool is_answer = (sdp_type == "answer");
  if (!is_offer && !is_answer) {
    return RTC_ERR_INVALID_ARG;
  }

  int result = RTC_ERR_PROTOCOL;
  queues_->signaling()->Invoke(
      [this, is_offer, remote_sdp, out_answer_sdp, &result]() {
        RTC_DCHECK_RUN_ON(&sig_checker_);
        if (!EnsureTransportInitializedOnSigQueue()) {
          result = RTC_ERR_NOT_INITIALIZED;
          return;
        }
        const auto parsed = PureVideoSdpDescription::Parse(
            remote_sdp, static_cast<VideoCodec>(config_.publish_codec));
        if (!parsed.has_value()) {
          result = RTC_ERR_PROTOCOL;
          return;
        }
        if (ApplyRemoteSdpOnSigQueue(*parsed, is_offer, out_answer_sdp)) {
          result = RTC_OK;
        }
      });
  return result;
}

int WebRtcP2pBackend::AddRemoteIceCandidate(std::string_view candidate_sdp) {
  if (candidate_sdp.empty()) {
    // 来自 W3C 浏览器的空字符串候选结束通知（end-of-candidates）为合法空操作。
    return RTC_OK;
  }
  const auto parsed = IceCandidate::FromSdpAttribute(candidate_sdp);
  if (!parsed.has_value()) {
    // 优雅忽略非 UDP 或 mDNS .local 候选地址（浏览器局域网端点可通过对端反射
    // STUN 连通性检查自动发现）。
    return RTC_OK;
  }
  queues_->signaling()->PostTask(
      SafeTask(sig_safety_.flag(), [this, cand = *parsed]() {
        RTC_DCHECK_RUN_ON(&sig_checker_);
        if (ice_) {
          ice_->AddRemoteCandidate(cand);
        }
      }));
  return RTC_OK;
}

void WebRtcP2pBackend::OnSignalingConnected() {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  JsonObject join_msg;
  join_msg.SetString("type", "join");
  join_msg.SetString("room_id", room_id_);
  join_msg.SetString("peer_id", local_peer_id_);
  join_msg.SetString("token", config_.auth_token);
  signaling_->SendText(join_msg.Serialize());
  signaling_joined_ = true;
}

void WebRtcP2pBackend::OnSignalingMessage(const std::string& json_text) {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  const auto msg = JsonObject::Parse(json_text);
  if (!msg.has_value()) {
    return;
  }
  const std::string type = msg->GetString("type");

  if (type == "peer_joined") {
    const std::string peer = msg->GetString("peer_id");
    if (peer.empty() || peer == local_peer_id_) {
      return;
    }
    remote_peer_id_ = peer;
    const uint32_t default_init = (local_peer_id_ < remote_peer_id_) ? 1u : 0u;
    const bool should_initiate =
        (msg->GetUint32("initiator", default_init) != 0u);
    if (should_initiate && !offer_sent_) {
      ice_->SetIceControlling(true);
      const auto offer = BuildLocalSdpOnSigQueue("offer", "actpass", true, true);
      offer_sent_ = true;

      JsonObject offer_msg;
      offer_msg.SetString("type", "offer");
      offer_msg.SetString("room_id", room_id_);
      offer_msg.SetString("peer_id", local_peer_id_);
      offer_msg.SetString("target_peer_id", remote_peer_id_);
      offer_msg.SetString("sdp", offer.Serialize());
      signaling_->SendText(offer_msg.Serialize());
      RTC_LOG(kInfo) << "Sent WebRTC P2P SDP Offer to peer=" << remote_peer_id_;
    }
  } else if (type == "offer") {
    const std::string from_peer = msg->GetString("peer_id");
    if (!from_peer.empty() && from_peer != local_peer_id_) {
      remote_peer_id_ = from_peer;
    }
    const auto remote_offer = PureVideoSdpDescription::Parse(
        msg->GetString("sdp"), static_cast<VideoCodec>(config_.publish_codec));
    if (!remote_offer.has_value()) {
      return;
    }
    std::string answer_sdp;
    if (ApplyRemoteSdpOnSigQueue(*remote_offer, /*remote_is_offer=*/true,
                                 &answer_sdp)) {
      JsonObject ans_msg;
      ans_msg.SetString("type", "answer");
      ans_msg.SetString("room_id", room_id_);
      ans_msg.SetString("peer_id", local_peer_id_);
      ans_msg.SetString("target_peer_id", remote_peer_id_);
      ans_msg.SetString("sdp", answer_sdp);
      signaling_->SendText(ans_msg.Serialize());
      RTC_LOG(kInfo) << "Sent WebRTC P2P SDP Answer to peer=" << remote_peer_id_;
    }
  } else if (type == "answer") {
    const std::string from_peer = msg->GetString("peer_id");
    if (!from_peer.empty() && from_peer != local_peer_id_) {
      remote_peer_id_ = from_peer;
    }
    const auto remote_ans = PureVideoSdpDescription::Parse(
        msg->GetString("sdp"), static_cast<VideoCodec>(config_.publish_codec));
    if (remote_ans.has_value()) {
      ApplyRemoteSdpOnSigQueue(*remote_ans, /*remote_is_offer=*/false, nullptr);
      RTC_LOG(kInfo) << "Applied WebRTC P2P SDP Answer from peer="
                     << remote_peer_id_;
    }
  } else if (type == "candidate") {
    const std::string cand_str = msg->GetString("candidate");
    if (!cand_str.empty()) {
      if (auto c = IceCandidate::FromSdpAttribute(cand_str)) {
        ice_->AddRemoteCandidate(*c);
      }
    }
  } else if (type == "peer_left") {
    const std::string peer = msg->GetString("peer_id", remote_peer_id_);
    if (observer_ != nullptr) {
      observer_->OnBackendRemoteTrackUnpublished(peer, peer + "_video0");
    }
  }
}

void WebRtcP2pBackend::OnSignalingClosed(int code,
                                         const std::string& /*reason*/) {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  signaling_joined_ = false;
  if (!media_ready_.load(std::memory_order_acquire) && observer_ != nullptr) {
    observer_->OnBackendConnectionState(RTC_CONN_STATE_RECONNECTING, code);
  }
}

void WebRtcP2pBackend::OnDtlsSrtpHandshakeComplete() {
  media_ready_.store(true, std::memory_order_release);
  queues_->worker()->PostTask(SafeTask(work_safety_.flag(), [this]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    // 在 DTLS-SRTP 握手完成且媒体通道就绪后再触发初始带宽探测簇（3x / 6x），避免探测包在就绪前被丢弃。
    ApplyNetworkControlUpdate(
        goog_cc_.OnNetworkAvailability(clock_->CurrentTime(), true));
    if (worker_has_datachannel_) {
      sctp_dc_.ConfigureAndStart(worker_dtls_role_, local_sctp_port_,
                                 worker_remote_sctp_port_);
    }
  }));
  if (observer_ != nullptr) {
    observer_->OnBackendConnectionState(RTC_CONN_STATE_CONNECTED, 0);
    observer_->OnBackendForceKeyFrame(SpatialLayer::kHigh);
  }
}

void WebRtcP2pBackend::OnDtlsApplicationData(ArrayView<const uint8_t> payload,
                                             Timestamp receive_time) {
  if (!config_.enable_datachannel || payload.empty()) {
    return;
  }
  std::vector<uint8_t> pkt(payload.begin(), payload.end());
  queues_->worker()->PostTask(SafeTask(
      work_safety_.flag(),
      [this, p = std::move(pkt), receive_time]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        if (worker_has_datachannel_) {
          sctp_dc_.ConfigureAndStart(worker_dtls_role_, local_sctp_port_,
                                     worker_remote_sctp_port_);
        }
        sctp_dc_.OnInboundSctpPacket(p, receive_time);
      }));
}

bool WebRtcP2pBackend::SendSctpPacketOverDtls(ArrayView<const uint8_t> packet) {
  if (packet.empty() || !dtls_srtp_) {
    return false;
  }
  std::vector<uint8_t> wire(packet.begin(), packet.end());
  queues_->network()->PostTask(
      SafeTask(net_safety_.flag(), [this, w = std::move(wire)]() {
        if (dtls_srtp_) {
          dtls_srtp_->SendDtlsApplicationData(w);
        }
      }));
  return true;
}

void WebRtcP2pBackend::OnSctpDataChannelState(int channel_id,
                                              const std::string& label,
                                              rtc_data_channel_state_e state) {
  RTC_DCHECK_RUN_ON(&work_checker_);
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    if (state == RTC_DATA_CHANNEL_CLOSED) {
      valid_dc_ids_.erase(channel_id);
    } else {
      valid_dc_ids_.insert(channel_id);
    }
  }
  if (observer_ != nullptr) {
    const std::string peer =
        inbound_ ? inbound_->remote_peer_id : remote_peer_id_;
    observer_->OnBackendDataChannelState(peer, channel_id, label, state);
  }
}

void WebRtcP2pBackend::OnSctpDataChannelMessage(int channel_id,
                                                bool is_binary,
                                                std::vector<uint8_t> payload) {
  RTC_DCHECK_RUN_ON(&work_checker_);
  if (observer_ != nullptr) {
    const std::string peer =
        inbound_ ? inbound_->remote_peer_id : remote_peer_id_;
    observer_->OnBackendDataChannelMessage(peer, channel_id, is_binary,
                                           std::move(payload));
  }
}

void WebRtcP2pBackend::OnDtlsSrtpError(std::string_view reason) {
  RTC_LOG(kError) << "WebRtcP2pBackend DTLS-SRTP error: " << reason;
  media_ready_.store(false, std::memory_order_release);
  if (observer_ != nullptr) {
    observer_->OnBackendConnectionState(RTC_CONN_STATE_FAILED, -2);
  }
}

int WebRtcP2pBackend::SendEncodedFrame(EncodedVideoFrame frame) {
  if (!media_ready_.load(std::memory_order_acquire)) {
    return RTC_OK;
  }

  queues_->worker()->PostTask(
      SafeTask(work_safety_.flag(), [this, f = std::move(frame)]() mutable {
        RTC_DCHECK_RUN_ON(&work_checker_);
        bool detected_kf = f.dep.is_keyframe;
        std::vector<PacketizedPayload> payloads;
        if (negotiated_codec_ == VideoCodec::kH265) {
          payloads =
              outbound_.h265_packetizer.PacketizeAnnexB(f.data, &detected_kf);
        } else {
          payloads =
              outbound_.h264_packetizer.PacketizeAnnexB(f.data, &detected_kf);
        }
        if (payloads.empty()) {
          return;
        }
        f.dep.is_keyframe = detected_kf;

        if (outbound_.flexfec) {
          outbound_.flexfec->SetProtectionParameters(
              detected_kf ? fec_controller_.keyframe_params()
                          : fec_controller_.delta_params());
        }

        std::vector<std::pair<RtpPacketMediaType, std::unique_ptr<RtpPacket>>>
            batch;
        batch.reserve(payloads.size() + 4);

        for (size_t i = 0; i < payloads.size(); ++i) {
          auto pkt = std::make_unique<RtpPacket>();
          pkt->set_extension_map(negotiated_ext_map_);
          pkt->set_payload_type(negotiated_video_pt_);
          pkt->set_ssrc(outbound_.media_ssrc);
          pkt->set_sequence_number(outbound_.next_rtp_seq++);
          pkt->set_timestamp(f.rtp_timestamp);
          pkt->set_marker(payloads[i].is_last_in_frame);

          if (negotiated_ext_map_.mid_id != 0) {
            pkt->SetMid(negotiated_mid_);
          }
          if (config_.zero_playout_delay && payloads[i].is_first_in_frame &&
              negotiated_ext_map_.playout_delay_id != 0) {
            pkt->set_playout_delay(PlayoutDelayLimits{0, 0});
          }

          *pkt->mutable_payload() = std::move(payloads[i].bytes);

          if (outbound_.flexfec) {
            outbound_.flexfec->AddRtpPacketAndGenerateFec(*pkt);
          }
          batch.emplace_back(detected_kf ? RtpPacketMediaType::kVideoKeyFrame
                                         : RtpPacketMediaType::kVideoDelta,
                             std::move(pkt));
        }

        if (outbound_.flexfec) {
          for (auto& fec_pkt : outbound_.flexfec->GetFecPackets()) {
            fec_pkt.set_extension_map(negotiated_ext_map_);
            batch.emplace_back(RtpPacketMediaType::kForwardErrorCorrection,
                               std::make_unique<RtpPacket>(std::move(fec_pkt)));
          }
        }

        paced_sender_->EnqueuePackets(std::move(batch));
      }));
  return RTC_OK;
}

void WebRtcP2pBackend::SendPacedPacket(std::unique_ptr<RtpPacket> packet,
                                       const PacedPacketInfo& cluster_info) {
  if (!media_ready_.load(std::memory_order_acquire) || !dtls_srtp_) {
    return;
  }

  const Timestamp send_time = clock_->CurrentTime();
  const uint16_t twcc_seq = next_twcc_seq_++;
  if (packet->extension_map().transport_sequence_number_id != 0) {
    packet->set_transport_sequence_number(twcc_seq);
  }
  if (packet->extension_map().absolute_send_time_id != 0) {
    packet->SetAbsoluteSendTime(send_time);
  }

  const DataSize pkt_size = DataSize::Bytes(packet->SerializedSize());
  const bool is_video_media = (packet->ssrc() == outbound_.media_ssrc &&
                               packet->payload_type() == negotiated_video_pt_);
  const bool is_rtx = (packet->ssrc() == outbound_.rtx_ssrc &&
                       packet->padding_size() == 0);
  const bool is_fec = (outbound_.flexfec_ssrc != 0 &&
                       packet->ssrc() == outbound_.flexfec_ssrc);
  RtpPacket raw_copy = *packet;

  queues_->network()->PostTask(
      SafeTask(net_safety_.flag(), [this, pkt = std::move(packet)]() {
        if (dtls_srtp_) {
          dtls_srtp_->SendRtpPacket(*pkt);
        }
      }));

  stat_pkts_sent_.fetch_add(1, std::memory_order_relaxed);
  if (is_rtx) {
    stat_pkts_rtx_.fetch_add(1, std::memory_order_relaxed);
  } else if (is_fec) {
    stat_fec_sent_.fetch_add(1, std::memory_order_relaxed);
  }

  queues_->worker()->PostTask(SafeTask(
      work_safety_.flag(),
      [this, raw_copy = std::move(raw_copy), is_video_media, twcc_seq, pkt_size,
       cluster_info, send_time]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        if (is_video_media) {
          outbound_.history.PutRtpPacket(raw_copy, send_time);
        }
        twcc_adapter_.AddPacket(twcc_seq, pkt_size, cluster_info, send_time);
        if (auto sent = twcc_adapter_.ProcessSentPacket(twcc_seq, send_time)) {
          ApplyNetworkControlUpdate(goog_cc_.OnSentPacket(*sent));
        }
        paced_sender_->UpdateOutstandingData(twcc_adapter_.outstanding_data());
      }));
}

std::vector<std::unique_ptr<RtpPacket>> WebRtcP2pBackend::GeneratePadding(
    DataSize target_size) {
  std::vector<std::unique_ptr<RtpPacket>> pad_pkts;
  int64_t rem = target_size.bytes();
  while (rem > 24) {
    auto p = std::make_unique<RtpPacket>();
    p->set_extension_map(negotiated_ext_map_);
    p->set_payload_type(negotiated_has_rtx_ ? negotiated_rtx_pt_
                                            : negotiated_video_pt_);
    p->set_ssrc(negotiated_has_rtx_ ? outbound_.rtx_ssrc : outbound_.media_ssrc);
    p->set_sequence_number(outbound_.next_rtx_seq++);
    p->set_timestamp(
        static_cast<uint32_t>((clock_->CurrentTime().us() * 90) / 1000));
    const size_t pad = static_cast<size_t>(std::min<int64_t>(rem - 12, 224));
    p->set_padding_size(pad);
    rem -= static_cast<int64_t>(p->SerializedSize());
    pad_pkts.push_back(std::move(p));
  }
  return pad_pkts;
}

void WebRtcP2pBackend::OnDecryptedRtpPacket(const RtpPacket& packet,
                                            Timestamp receive_time) {
  RtpPacket copy = packet;
  queues_->worker()->PostTask(SafeTask(
      work_safety_.flag(), [this, pkt = std::move(copy), receive_time]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        if (auto tseq = pkt.transport_sequence_number()) {
          rx_twcc_records_.emplace_back(*tseq, receive_time);
        }
        demuxer_.OnRtpPacket(pkt, receive_time);
      }));
}

void WebRtcP2pBackend::OnRtpPacket(const RtpPacket& packet,
                                   Timestamp receive_time) {
  RTC_DCHECK_RUN_ON(&work_checker_);
  if (!inbound_ || packet.payload().empty()) {
    return;
  }

  // 1. 处理 FlexFEC 前向纠错冗余包（`flexfec-03`）。
  if (negotiated_has_flexfec_ &&
      packet.payload_type() == negotiated_flexfec_pt_) {
    if (!inbound_->flexfec_rx && inbound_->media_ssrc != 0) {
      inbound_->flexfec_rx =
          std::make_unique<FlexfecReceiver>(packet.ssrc(), inbound_->media_ssrc);
    }
    if (inbound_->flexfec_rx) {
      for (const auto& rec : inbound_->flexfec_rx->OnRtpPacket(packet)) {
        HandleMediaRtpPacketOnWorker(rec, receive_time, /*已纠错恢复=*/true);
      }
    }
    return;
  }

  // 2. 处理符合 RFC 4588 的 RTX 重传包（按 Payload Type 或 SSRC 匹配）。
  if ((negotiated_has_rtx_ && packet.payload_type() == negotiated_rtx_pt_) ||
      (inbound_->rtx_ssrc != 0 && packet.ssrc() == inbound_->rtx_ssrc)) {
    if (inbound_->media_ssrc == 0) {
      return;
    }
    auto recovered = RtxCodec::ParseRtxPacket(packet, inbound_->media_ssrc,
                                              negotiated_video_pt_);
    if (recovered.has_value()) {
      HandleMediaRtpPacketOnWorker(*recovered, receive_time,
                                   /*已纠错恢复=*/true);
      // 将 RTX 重传恢复出的媒体包继续送入 FlexFEC 异或解码器，实现混合 ARQ+FEC 级联恢复同一纠错组内其余丢包。
      if (inbound_->flexfec_rx) {
        for (const auto& cascade_rec :
             inbound_->flexfec_rx->OnRtpPacket(*recovered)) {
          HandleMediaRtpPacketOnWorker(cascade_rec, receive_time,
                                       /*已纠错恢复=*/true);
        }
      }
    }
    return;
  }

  // 3. 主视频媒体流 RTP 包（支持未在信令中预声明的浏览器动态 SSRC）。
  if (inbound_->media_ssrc == 0) {
    inbound_->media_ssrc = packet.ssrc();
    inbound_->flexfec_rx =
        std::make_unique<FlexfecReceiver>(0, inbound_->media_ssrc);
    if (!inbound_->track_announced && observer_ != nullptr) {
      inbound_->track_announced = true;
      observer_->OnBackendRemoteTrackPublished(
          inbound_->remote_peer_id, inbound_->remote_track_id, inbound_->codec);
    }
  }
  if (inbound_->flexfec_rx) {
    (void)inbound_->flexfec_rx->OnRtpPacket(packet);
  }
  HandleMediaRtpPacketOnWorker(packet, receive_time);
}

void WebRtcP2pBackend::HandleMediaRtpPacketOnWorker(const RtpPacket& media_pkt,
                                                    Timestamp receive_time,
                                                    bool is_recovered) {
  if (!inbound_) {
    return;
  }
  ++inbound_->packets_received;
  inbound_->highest_seq_received = std::max<uint32_t>(
      inbound_->highest_seq_received, media_pkt.sequence_number());

  bool kf_req = false;
  auto nacks = inbound_->nack_module.OnReceivedPacket(
      media_pkt.sequence_number(), false, is_recovered, receive_time, &kf_req);
  if (!nacks.empty()) {
    RtcpNack nack_pkt;
    nack_pkt.sender_ssrc = outbound_.media_ssrc;
    nack_pkt.media_ssrc = media_pkt.ssrc();
    nack_pkt.packet_ids = std::move(nacks);
    auto wire = nack_pkt.Build();
    queues_->network()->PostTask(
        SafeTask(net_safety_.flag(), [this, w = std::move(wire)]() {
          if (dtls_srtp_) {
            dtls_srtp_->SendRtcpPacket(w);
          }
        }));
  }
  if (kf_req) {
    SendPliForRemoteStream(receive_time);
  }

  auto assembled = inbound_->packet_buffer.InsertPacket(media_pkt, receive_time);
  for (auto& raw_f : assembled) {
    const DataSize fsize = DataSize::Bytes(raw_f.annexb_bitstream.size());
    if (inbound_->prev_frame_arrival.has_value() &&
        inbound_->prev_frame_size.has_value()) {
      inbound_->jitter_estimator.UpdateEstimate(
          receive_time - *inbound_->prev_frame_arrival,
          fsize - *inbound_->prev_frame_size, fsize, false);
    }
    inbound_->prev_frame_arrival = receive_time;
    inbound_->prev_frame_size = fsize;
    const TimeDelta ice_rtt = ice_ ? ice_->last_rtt() : TimeDelta::Millis(30);
    inbound_->vcm_timing.SetJitterDelay(
        inbound_->jitter_estimator.GetJitterEstimate(1.0, ice_rtt));
    inbound_->vcm_timing.IncomingTimestamp(raw_f.rtp_timestamp, receive_time);

    for (auto& resolved : inbound_->ref_finder.ManageFrame(std::move(raw_f))) {
      inbound_->frame_buffer.InsertFrame(std::move(resolved));
    }
  }

  while (auto dec = inbound_->frame_buffer.ExtractNextDecodableFrame()) {
    if (dec->dep.is_keyframe) {
      // 当全新可解码关键帧就绪后，清理该关键帧首包序列号之前的陈旧 NACK 与分片槽位，防止滞后误触发 PLI。
      inbound_->nack_module.ClearUpTo(dec->first_seq_num);
      inbound_->packet_buffer.ClearTo(dec->first_seq_num);
    }
    stat_frames_decoded_.fetch_add(1, std::memory_order_relaxed);
    EncodedVideoFrame out;
    out.data = std::move(dec->annexb_bitstream);
    out.capture_time = dec->received_time;
    out.rtp_timestamp = dec->rtp_timestamp;
    out.codec = dec->codec;
    out.layer = SpatialLayer::kHigh;
    out.dep = dec->dep;
    if (observer_ != nullptr) {
      observer_->OnBackendDecodableFrame(inbound_->remote_peer_id,
                                         inbound_->remote_track_id,
                                         std::move(out));
    }
  }
}

void WebRtcP2pBackend::OnDecryptedRtcpPacket(
    ArrayView<const uint8_t> compound_rtcp,
    Timestamp receive_time) {
  std::vector<uint8_t> copy(compound_rtcp.begin(), compound_rtcp.end());
  queues_->worker()->PostTask(SafeTask(
      work_safety_.flag(), [this, buf = std::move(copy), receive_time]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const ParsedCompoundRtcp parsed = ParseCompoundRtcp(buf);

        for (const auto& twcc : parsed.transport_feedbacks) {
          if (auto msg =
                  twcc_adapter_.ProcessTransportFeedback(twcc, receive_time)) {
            ApplyNetworkControlUpdate(
                goog_cc_.OnTransportPacketsFeedback(*msg));
          }
        }

        for (const auto& rr : parsed.receiver_reports) {
          for (const auto& rb : rr.report_blocks) {
            latest_uplink_loss_ =
                static_cast<double>(rb.fraction_lost) / 256.0;
            const TimeDelta ice_rtt =
                ice_ ? ice_->last_rtt() : TimeDelta::Millis(30);
            ApplyNetworkControlUpdate(goog_cc_.OnReceiverReport(
                receive_time, rb.fraction_lost, ice_rtt));
          }
        }

        for (const auto& nack : parsed.nacks) {
          if (nack.media_ssrc != outbound_.media_ssrc) {
            continue;
          }
          std::vector<std::pair<RtpPacketMediaType, std::unique_ptr<RtpPacket>>>
              rtx_batch;
          for (uint16_t lost_seq : nack.packet_ids) {
            if (auto orig = outbound_.history.GetPacketAndMarkAsSent(
                    lost_seq, receive_time)) {
              if (negotiated_has_rtx_) {
                RtpPacket rtx = RtxCodec::BuildRtxPacket(
                    *orig, outbound_.rtx_ssrc, negotiated_rtx_pt_,
                    outbound_.next_rtx_seq++);
                rtx.set_extension_map(negotiated_ext_map_);
                rtx_batch.emplace_back(
                    RtpPacketMediaType::kRetransmission,
                    std::make_unique<RtpPacket>(std::move(rtx)));
              } else {
                rtx_batch.emplace_back(
                    RtpPacketMediaType::kRetransmission,
                    std::make_unique<RtpPacket>(std::move(*orig)));
              }
            }
          }
          if (!rtx_batch.empty()) {
            paced_sender_->EnqueuePackets(std::move(rtx_batch));
          }
        }

        if (!parsed.plis.empty() || !parsed.firs.empty()) {
          if (observer_ != nullptr) {
            observer_->OnBackendForceKeyFrame(SpatialLayer::kHigh);
          }
        }
      }));
}

void WebRtcP2pBackend::ApplyNetworkControlUpdate(
    const NetworkControlUpdate& update) {
  if (update.congestion_window.has_value()) {
    paced_sender_->SetCongestionWindow(*update.congestion_window);
  }
  if (update.pacer_config.has_value()) {
    latest_pacing_rate_ = update.pacer_config->data_rate();
    paced_sender_->SetPacingRates(update.pacer_config->data_rate(),
                                  update.pacer_config->pad_rate());
  }
  if (!update.probe_cluster_configs.empty()) {
    paced_sender_->CreateProbeClusters(update.probe_cluster_configs);
  }
  if (update.target_rate.has_value()) {
    latest_target_rate_ = update.target_rate->target_rate;
    latest_uplink_loss_ = update.target_rate->loss_rate_ratio;
    fec_controller_.UpdateNetworkMetrics(update.target_rate->target_rate,
                                         update.target_rate->rtt,
                                         update.target_rate->loss_rate_ratio);
    if (observer_ != nullptr) {
      observer_->OnBackendTargetTransferRate(*update.target_rate);
    }
  }
}

void WebRtcP2pBackend::OnWorkerPeriodicTick() {
  RTC_DCHECK_RUN_ON(&work_checker_);
  const Timestamp now = clock_->CurrentTime();

  if (media_ready_.load(std::memory_order_acquire)) {
    sctp_dc_.OnPeriodicTick(now);
    const TimeDelta ice_rtt = ice_ ? ice_->last_rtt() : TimeDelta::Millis(30);
    outbound_.history.SetRtt(ice_rtt);
    twcc_adapter_.CullExpiredInFlight(now);
    paced_sender_->UpdateOutstandingData(twcc_adapter_.outstanding_data());
    ApplyNetworkControlUpdate(goog_cc_.OnProcessInterval(now));

    if (inbound_) {
      inbound_->nack_module.UpdateRtt(ice_rtt);
      bool need_kf = false;
      auto nacks = inbound_->nack_module.ProcessNacks(now, &need_kf);
      if (!nacks.empty() && inbound_->media_ssrc != 0) {
        RtcpNack nack_pkt;
        nack_pkt.sender_ssrc = outbound_.media_ssrc;
        nack_pkt.media_ssrc = inbound_->media_ssrc;
        nack_pkt.packet_ids = std::move(nacks);
        auto wire = nack_pkt.Build();
        queues_->network()->PostTask(
            SafeTask(net_safety_.flag(), [this, w = std::move(wire)]() {
              if (dtls_srtp_) {
                dtls_srtp_->SendRtcpPacket(w);
              }
            }));
      }
      const TimeDelta stall_thresh =
          std::max(TimeDelta::Millis(250), ice_rtt * 2);
      if (need_kf ||
          inbound_->frame_buffer.IsCorruptedOrStalled(now, stall_thresh)) {
        SendPliForRemoteStream(now);
      }
    }

    SendCompoundRtcpFeedback(now);

    if (last_sr_rr_sent_.IsMinusInfinity() ||
        (now - last_sr_rr_sent_) >= TimeDelta::Millis(1000)) {
      last_sr_rr_sent_ = now;
      rtc_network_stats_t s{};
      s.rtt_ms = ice_rtt.ms();
      s.target_bitrate_bps = static_cast<uint32_t>(latest_target_rate_.bps());
      s.pacing_bitrate_bps = static_cast<uint32_t>(latest_pacing_rate_.bps());
      s.uplink_packet_loss = static_cast<float>(latest_uplink_loss_);
      s.packets_sent = stat_pkts_sent_.load(std::memory_order_relaxed);
      s.packets_retransmitted = stat_pkts_rtx_.load(std::memory_order_relaxed);
      s.fec_packets_sent = stat_fec_sent_.load(std::memory_order_relaxed);
      s.frames_decoded = stat_frames_decoded_.load(std::memory_order_relaxed);
      s.keyframe_requests_sent = stat_pli_sent_.load(std::memory_order_relaxed);
      if (observer_ != nullptr) {
        observer_->OnBackendStatsSnapshot(s);
      }
    }
  }

  queues_->worker()->PostDelayedTask(
      SafeTask(work_safety_.flag(), [this]() { OnWorkerPeriodicTick(); }),
      TimeDelta::Millis(25));
}

void WebRtcP2pBackend::SendCompoundRtcpFeedback(Timestamp now) {
  if (!rx_twcc_records_.empty() &&
      (last_twcc_sent_.IsMinusInfinity() ||
       (now - last_twcc_sent_) >= TimeDelta::Millis(40) ||
       rx_twcc_records_.size() >= 32)) {
    last_twcc_sent_ = now;
    // 采用模 2^16 序列号比较，防止 TWCC 序列号在 65535 -> 0 回绕时乱序。
    std::sort(rx_twcc_records_.begin(), rx_twcc_records_.end(),
              [](const auto& a, const auto& b) {
                return a.first != b.first &&
                       static_cast<uint16_t>(b.first - a.first) < 0x8000u;
              });

    RtcpTransportFeedback fb;
    fb.sender_ssrc = outbound_.media_ssrc;
    fb.media_ssrc = inbound_ ? inbound_->media_ssrc : 0;
    fb.feedback_seq = twcc_fb_pkt_count_++;
    uint16_t base_seq = rx_twcc_records_.front().first;
    // 衔接上一次 TWCC 反馈的末尾序列号，使两次反馈之间的尾部丢包能以“未收到”状态显式上报给发送端。
    if (next_expected_twcc_seq_.has_value()) {
      const uint16_t gap =
          static_cast<uint16_t>(base_seq - *next_expected_twcc_seq_);
      if (gap > 0 && gap < 512) {
        base_seq = *next_expected_twcc_seq_;
      }
    }
    fb.SetBase(base_seq, rx_twcc_records_.front().second);
    for (const auto& [seq, ts] : rx_twcc_records_) {
      fb.AddReceivedPacket(seq, ts);
    }
    next_expected_twcc_seq_ =
        static_cast<uint16_t>(fb.base_seq_no() + fb.num_seq_no());
    rx_twcc_records_.clear();

    auto wire = fb.Build();
    queues_->network()->PostTask(
        SafeTask(net_safety_.flag(), [this, w = std::move(wire)]() {
          if (dtls_srtp_) {
            dtls_srtp_->SendRtcpPacket(w);
          }
        }));
  }
}

void WebRtcP2pBackend::SendPliForRemoteStream(Timestamp now) {
  if (!inbound_ || inbound_->media_ssrc == 0) {
    return;
  }
  const TimeDelta pli_cooldown = std::max(
      TimeDelta::Millis(150), ice_ ? ice_->last_rtt() : TimeDelta::Millis(150));
  if (inbound_->last_pli_sent.IsFinite() &&
      (now - inbound_->last_pli_sent) < pli_cooldown) {
    return;
  }
  inbound_->last_pli_sent = now;
  stat_pli_sent_.fetch_add(1, std::memory_order_relaxed);

  RtcpPli pli;
  pli.sender_ssrc = outbound_.media_ssrc;
  pli.media_ssrc = inbound_->media_ssrc;
  auto wire = pli.Build();
  queues_->network()->PostTask(
      SafeTask(net_safety_.flag(), [this, w = std::move(wire)]() {
        if (dtls_srtp_) {
          dtls_srtp_->SendRtcpPacket(w);
        }
      }));
}

int WebRtcP2pBackend::SubscribeRemoteTrack(const std::string& /*track_id*/,
                                           SpatialLayer /*preferred_layer*/) {
  // 在一对一 WebRTC P2P 模式下，SDP/ICE 协商完成后入站媒体流将自动传输；
  // 返回 RTC_OK 以保持上层调用代码与传输模式解耦。
  return RTC_OK;
}

int WebRtcP2pBackend::SwitchSubscribedLayer(const std::string& /*track_id*/,
                                            SpatialLayer /*preferred_layer*/) {
  return RTC_OK;
}

int WebRtcP2pBackend::UnsubscribeRemoteTrack(const std::string& /*track_id*/) {
  return RTC_OK;
}

int WebRtcP2pBackend::RequestRemoteKeyFrame(const std::string& /*track_id*/) {
  queues_->worker()->PostTask(SafeTask(work_safety_.flag(), [this]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    SendPliForRemoteStream(clock_->CurrentTime());
  }));
  return RTC_OK;
}

int WebRtcP2pBackend::CreateDataChannel(const DataChannelConfig& config) {
  if (!config_.enable_datachannel) {
    return RTC_ERR_PROTOCOL;
  }
  int cid = RTC_ERR_INTERNAL;
  queues_->worker()->Invoke([this, &config, &cid]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    cid = sctp_dc_.CreateDataChannel(config);
    if (cid >= 0) {
      std::lock_guard<std::mutex> lock(dc_handles_mu_);
      valid_dc_ids_.insert(cid);
    }
  });
  return cid;
}

int WebRtcP2pBackend::SendData(int channel_id,
                               ArrayView<const uint8_t> payload,
                               bool is_binary) {
  if (!config_.enable_datachannel) {
    return RTC_ERR_PROTOCOL;
  }
  if (channel_id < 0 || (payload.size() > 0 && payload.data() == nullptr)) {
    return RTC_ERR_INVALID_ARG;
  }
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    if (valid_dc_ids_.find(channel_id) == valid_dc_ids_.end()) {
      return RTC_ERR_INVALID_ARG;
    }
  }
  std::vector<uint8_t> copy(payload.begin(), payload.end());
  queues_->worker()->PostTask(SafeTask(
      work_safety_.flag(),
      [this, channel_id, buf = std::move(copy), is_binary]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        sctp_dc_.SendData(channel_id, buf, is_binary);
      }));
  return RTC_OK;
}

int WebRtcP2pBackend::CloseDataChannel(int channel_id) {
  if (!config_.enable_datachannel) {
    return RTC_ERR_PROTOCOL;
  }
  if (channel_id < 0) {
    return RTC_ERR_INVALID_ARG;
  }
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    if (valid_dc_ids_.find(channel_id) == valid_dc_ids_.end()) {
      return RTC_ERR_INVALID_ARG;
    }
  }
  int rc = RTC_OK;
  queues_->worker()->Invoke([this, channel_id, &rc]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    rc = sctp_dc_.CloseDataChannel(channel_id);
  });
  return rc;
}

}  // namespace rtc