#include "call/webrtc_p2p_backend.h"

#include <algorithm>
#include <cctype>
#include <cmath>

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

std::string NormalizeFingerprintUpper(std::string s) {
  while (!s.empty() &&
         (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' ||
          s.front() == '\n')) {
    s.erase(s.begin());
  }
  while (!s.empty() &&
         (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' ||
          s.back() == '\n')) {
    s.pop_back();
  }
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  return s;
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
      negotiated_has_datachannel_(config.enable_datachannel),
      negotiated_codec_(static_cast<VideoCodec>(config.publish_codec)),
      negotiated_has_flexfec_(config.enable_flexfec),
      worker_codec_(static_cast<VideoCodec>(config.publish_codec)),
      worker_has_flexfec_(config.enable_flexfec),
      sctp_dc_(clock, this),
      goog_cc_(
          std::make_unique<GoogCcNetworkController>(MakeGoogCcConfig(config))),
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
    outbound_.flexfec_mid = negotiated_mid_;
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
  if (!local_cert_) {
    local_cert_ = DtlsCertificate::GenerateEcdsaP256();
    if (!local_cert_) {
      return false;
    }
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
            if (has_paired_remote_peer_ && !remote_peer_id_.empty()) {
              msg.SetString("target_peer_id", remote_peer_id_);
            }
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
    ice_->set_observer(nullptr);
    dtls_srtp_.reset();
    ice_.reset();
    return false;
  }

  if (!paced_sender_) {
    paced_sender_ =
        std::make_unique<TaskQueuePacedSender>(clock_, this, queues_->pacer());
  }

  const VideoCodec init_codec = negotiated_codec_;
  const std::string init_mid = negotiated_mid_;
  const RtpHeaderExtensionMap init_ext = negotiated_ext_map_;
  const bool init_rtx = negotiated_has_rtx_;
  const bool init_fec = negotiated_has_flexfec_ && config_.enable_flexfec;
  const uint8_t init_fec_pt = negotiated_flexfec_pt_;
  const uint32_t init_fec_rw = negotiated_flexfec_rw_us_;
  pacer_has_rtx_.store(init_rtx, std::memory_order_release);

  queues_->worker()->PostTask(SafeTask(
      work_safety_.flag(),
      [this, init_codec, init_mid, init_ext, init_rtx, init_fec, init_fec_pt,
       init_fec_rw]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        worker_codec_ = init_codec;
        worker_codec_negotiated_ = false;
        worker_has_video_ = true;
        worker_mid_ = init_mid;
        worker_ext_map_ = init_ext;
        worker_has_rtx_ = init_rtx;
        worker_has_flexfec_ = init_fec;
        worker_flexfec_pt_ = init_fec_pt;
        worker_flexfec_rw_us_ = init_fec_rw;
        if (init_fec && outbound_.flexfec_ssrc != 0) {
          if (!outbound_.flexfec ||
              outbound_.flexfec->ssrc() != outbound_.flexfec_ssrc ||
              outbound_.flexfec->payload_type() != init_fec_pt ||
              outbound_.flexfec_mid != init_mid) {
            outbound_.flexfec = std::make_unique<FlexfecSender>(
                init_fec_pt, outbound_.flexfec_ssrc, outbound_.media_ssrc,
                init_mid, init_fec_rw);
            outbound_.flexfec_mid = init_mid;
          } else {
            outbound_.flexfec->set_repair_window_us(init_fec_rw);
          }
        }
        inbound_ = std::make_unique<InboundStreamState>(
            worker_codec_, clock_->CurrentTime(), config_.zero_playout_delay);
        RtpDemuxCriteria crit;
        crit.mid = worker_mid_;
        demuxer_.AddSink(crit, this);
        demuxer_.SetDefaultSink(this);

        if (paced_sender_) {
          paced_sender_->EnsureStarted();
        }
        const auto init_upd = goog_cc_->OnProcessInterval(clock_->CurrentTime());
        ApplyNetworkControlUpdate(init_upd);
        OnWorkerPeriodicTick();
      }));

  transport_initialized_ = true;
  return true;
}

void WebRtcP2pBackend::ConnectSignalingOnSigQueue() {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  if (config_.signaling_or_moq_url.empty()) {
    return;
  }
  signaling_ = std::make_unique<BoostBeastSignalingClient>(queues_->signaling());
  const bool verify_chain = config_.tls_verify_peer ||
                            !config_.tls_ca_cert_path.empty() ||
                            config_.tls_pinned_cert_sha256.empty();
  signaling_->SetTlsOptions(verify_chain, config_.tls_ca_cert_path,
                            config_.tls_pinned_cert_sha256);
  signaling_->set_on_connected([this]() { OnSignalingConnected(); });
  signaling_->set_on_message(
      [this](const std::string& m) { OnSignalingMessage(m); });
  signaling_->set_on_closed(
      [this](int c, const std::string& r) { OnSignalingClosed(c, r); });
  signaling_->Connect(config_.signaling_or_moq_url);
}

int WebRtcP2pBackend::StartSession(const std::string& room_id,
                                   const std::string& local_peer_id) {
  video_muted_.store(false, std::memory_order_release);
  queues_->signaling()->PostTask(
      SafeTask(sig_safety_.flag(), [this, room_id, local_peer_id]() {
        RTC_DCHECK_RUN_ON(&sig_checker_);
        session_active_ = true;
        sig_reconnect_attempts_ = 0;
        sig_connected_at_ = Timestamp::MinusInfinity();
        ++sig_conn_gen_;
        offer_sent_ = false;
        has_paired_remote_peer_ = false;
        remote_peer_id_ = "remote_peer";
        negotiated_remote_track_id_.clear();
        room_id_ = room_id;
        local_peer_id_ = local_peer_id;
        if (observer_ != nullptr) {
          observer_->OnBackendConnectionState(RTC_CONN_STATE_CONNECTING, 0);
        }
        if (!EnsureTransportInitializedOnSigQueue()) {
          session_active_ = false;
          if (observer_ != nullptr) {
            observer_->OnBackendConnectionState(RTC_CONN_STATE_FAILED, -1);
          }
          return;
        }
        ConnectSignalingOnSigQueue();
      }));
  return RTC_OK;
}

void WebRtcP2pBackend::StopSession() {
  media_ready_.store(false, std::memory_order_release);
  video_muted_.store(false, std::memory_order_release);

  // 1. 最先排空并停止 signaling 队列（严格遵循 Invoke 拓扑序 sig -> net -> work），
  // 确保 EnsureTransportInitializedOnSigQueue / ApplyRemoteSdpOnSigQueue 不再并发访问 ice_ / dtls_srtp_ / paced_sender_。
  queues_->signaling()->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&sig_checker_);
    sig_safety_.flag()->SetNotAlive();
    session_active_ = false;
    signaling_joined_ = false;
    has_paired_remote_peer_ = false;
    remote_peer_id_ = "remote_peer";
    negotiated_remote_track_id_.clear();
    sig_reconnect_attempts_ = 0;
    sig_connected_at_ = Timestamp::MinusInfinity();
    ++sig_conn_gen_;
    offer_sent_ = false;
    transport_initialized_ = false;

    negotiated_mid_ = "0";
    negotiated_data_mid_ = "1";
    negotiated_has_video_ = true;
    negotiated_has_datachannel_ = config_.enable_datachannel;
    local_sctp_port_ = 5000;
    remote_sctp_port_ = 5000;
    negotiated_m_order_.clear();
    negotiated_rejected_m_.clear();
    negotiated_codec_ = static_cast<VideoCodec>(config_.publish_codec);
    negotiated_h264_profile_level_id_ = "42e01f";
    negotiated_dtls_role_ = DtlsRole::kClient;
    negotiated_remote_fp_.clear();
    negotiated_video_pt_.store(96, std::memory_order_relaxed);
    negotiated_rtx_pt_.store(97, std::memory_order_relaxed);
    pacer_has_rtx_.store(true, std::memory_order_release);
    cached_ice_rtt_us_.store(30'000, std::memory_order_relaxed);
    negotiated_flexfec_pt_ = 118;
    negotiated_has_rtx_ = true;
    negotiated_has_flexfec_ = config_.enable_flexfec;
    negotiated_flexfec_subtype_ = "flexfec";
    negotiated_flexfec_rw_us_ = 10'000'000;
    negotiated_ext_map_ = RtpHeaderExtensionMap::BrowserDefault();
    {
      std::lock_guard<std::mutex> lk(pacer_ext_mu_);
      pacer_ext_map_ = negotiated_ext_map_;
    }

    if (signaling_) {
      signaling_->Close();
      signaling_.reset();
    }
  });

  // 2. 停止 network 队列，切断底层 UDP 收包向 worker / signaling 队列投递新任务。
  queues_->network()->Invoke([this]() {
    net_safety_.flag()->SetNotAlive();
    if (ice_) {
      ice_->set_observer(nullptr);
    }
    dtls_srtp_.reset();
    ice_.reset();
  });

  // 3. 停止 worker 与 pacer 队列并完整重置会话级统计与编解码状态。
  queues_->worker()->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    work_safety_.flag()->SetNotAlive();
    paced_sender_.reset();
    sctp_dc_.Shutdown();
    demuxer_.RemoveSink(this);
    inbound_.reset();
    outbound_.history.Clear();
    outbound_.media_ssrc = GenerateNonZeroSsrc();
    outbound_.rtx_ssrc = outbound_.media_ssrc + 1;
    outbound_.flexfec_ssrc =
        config_.enable_flexfec ? (outbound_.media_ssrc + 2) : 0;
    outbound_.next_rtp_seq = 1000;
    outbound_.next_rtx_seq.store(20000, std::memory_order_relaxed);
    if (config_.enable_flexfec) {
      outbound_.flexfec = std::make_unique<FlexfecSender>(
          118, outbound_.flexfec_ssrc, outbound_.media_ssrc, "0");
      outbound_.flexfec_mid = "0";
    } else {
      outbound_.flexfec.reset();
      outbound_.flexfec_mid.clear();
    }

    worker_codec_ = static_cast<VideoCodec>(config_.publish_codec);
    worker_codec_negotiated_ = false;
    worker_has_video_ = true;
    worker_mid_ = "0";
    worker_ext_map_ = RtpHeaderExtensionMap::BrowserDefault();
    worker_has_rtx_ = true;
    worker_has_flexfec_ = config_.enable_flexfec;
    worker_flexfec_pt_ = 118;
    worker_flexfec_rw_us_ = 10'000'000;
    worker_remote_peer_id_ = "remote_peer";
    worker_dtls_role_ = DtlsRole::kClient;
    worker_has_datachannel_ = false;
    worker_remote_sctp_port_ = 5000;

    next_twcc_seq_ = 1;
    twcc_fb_pkt_count_ = 0;
    rx_twcc_records_.clear();
    next_expected_twcc_seq_.reset();
    pending_rr_wire_.clear();
    twcc_rtt_samples_.clear();
    last_fir_seq_by_ssrc_.clear();
    last_idr_forced_at_ = Timestamp::MinusInfinity();
    has_received_twcc_ = false;
    last_twcc_sent_ = Timestamp::MinusInfinity();
    last_sr_rr_sent_ = Timestamp::MinusInfinity();
    latest_target_rate_ = DataRate::Zero();
    latest_pacing_rate_ = DataRate::Zero();
    latest_uplink_loss_ = 0.0;

    stat_pkts_sent_.store(0, std::memory_order_relaxed);
    stat_pkts_rtx_.store(0, std::memory_order_relaxed);
    stat_fec_sent_.store(0, std::memory_order_relaxed);
    stat_frames_decoded_.store(0, std::memory_order_relaxed);
    stat_pli_sent_.store(0, std::memory_order_relaxed);

    goog_cc_ =
        std::make_unique<GoogCcNetworkController>(MakeGoogCcConfig(config_));
    twcc_adapter_ = TransportFeedbackAdapter();
    fec_controller_ = FecControllerDefault();
  });

  // 4. 在三条队列全部完成排空后统一重新挂载安全标志，支持 LeaveRoom -> JoinRoom 二次会话。
  sig_safety_.Reset(PendingTaskSafetyFlag::CreateDetached());
  net_safety_.Reset(PendingTaskSafetyFlag::CreateDetached());
  work_safety_.Reset(PendingTaskSafetyFlag::CreateDetached());

  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    valid_dc_ids_.clear();
  }
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
    // 直连 W3C SDP 模式下无 Trickle ICE 后续增量通道，等待异步 DNS 解析与 STUN/TURN 分配收集落盘（正常仅耗时数毫秒，高负载下兼容 RTO 重传）。
    ice_->WaitForServerReflexiveGathering(TimeDelta::Millis(1500));
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
    m.h264_profile_level_id = negotiated_h264_profile_level_id_;
    m.direction_send = direction_send;
    m.direction_recv = direction_recv;
    m.video_pt = negotiated_video_pt_.load(std::memory_order_relaxed);
    m.rtx_pt = negotiated_rtx_pt_.load(std::memory_order_relaxed);
    m.flexfec_pt = negotiated_flexfec_pt_;
    m.has_rtx = negotiated_has_rtx_;
    m.has_flexfec = negotiated_has_flexfec_ && config_.enable_flexfec;
    m.flexfec_subtype = negotiated_flexfec_subtype_;
    m.flexfec_repair_window_us = negotiated_flexfec_rw_us_;
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
    desc.rejected_m_sections = negotiated_rejected_m_;
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

  // RFC 5763 §5：Answer 严禁携带 `a=setup:actpass`（仅允许 `active` 或 `passive`）。
  if (!remote_is_offer) {
    if (remote_desc.dtls_setup != "active" &&
        remote_desc.dtls_setup != "passive") {
      RTC_LOG(kError) << "Rejected remote SDP Answer with invalid a=setup:"
                      << remote_desc.dtls_setup;
      return false;
    }
  } else {
    if (remote_desc.dtls_setup != "actpass" &&
        remote_desc.dtls_setup != "active" &&
        remote_desc.dtls_setup != "passive") {
      RTC_LOG(kError) << "Rejected remote SDP Offer with invalid a=setup:"
                      << remote_desc.dtls_setup;
      return false;
    }
  }

  negotiated_has_video_ = !remote_desc.video_m_sections.empty();
  negotiated_has_datachannel_ =
      config_.enable_datachannel && remote_desc.data_m_section.has_value();

  // 严格按 Offer 中 m= 出现顺序重建 Answer m= 列表（将第 2 条及之后的附加 m=video 或未启用 DataChannel 置端口 0 拒绝）。
  negotiated_m_order_.clear();
  negotiated_rejected_m_.clear();
  size_t src_vid_idx = 0;
  size_t src_rej_idx = 0;
  bool kept_first_video = false;
  bool kept_first_app = false;
  for (SdpMediaKind kind : remote_desc.m_section_order) {
    if (kind == SdpMediaKind::kVideo) {
      const size_t cur_vi = src_vid_idx++;
      if (!kept_first_video && cur_vi < remote_desc.video_m_sections.size()) {
        kept_first_video = true;
        negotiated_m_order_.push_back(SdpMediaKind::kVideo);
      } else {
        negotiated_m_order_.push_back(SdpMediaKind::kUnsupported);
        std::string extra_mid;
        std::string extra_fmt = "96";
        if (cur_vi < remote_desc.video_m_sections.size()) {
          extra_mid = remote_desc.video_m_sections[cur_vi].mid;
          extra_fmt =
              std::to_string(remote_desc.video_m_sections[cur_vi].video_pt);
        }
        negotiated_rejected_m_.push_back(
            RejectedMediaDesc{"video", "UDP/TLS/RTP/SAVPF", extra_fmt,
                              extra_mid});
      }
    } else if (kind == SdpMediaKind::kApplication) {
      if (negotiated_has_datachannel_ && !kept_first_app) {
        kept_first_app = true;
        negotiated_m_order_.push_back(SdpMediaKind::kApplication);
      } else {
        negotiated_m_order_.push_back(SdpMediaKind::kUnsupported);
        negotiated_rejected_m_.push_back(RejectedMediaDesc{
            "application", "UDP/DTLS/SCTP", "webrtc-datachannel",
            remote_desc.data_m_section.has_value()
                ? remote_desc.data_m_section->mid
                : ""});
      }
    } else {
      negotiated_m_order_.push_back(SdpMediaKind::kUnsupported);
      if (src_rej_idx < remote_desc.rejected_m_sections.size()) {
        negotiated_rejected_m_.push_back(
            remote_desc.rejected_m_sections[src_rej_idx++]);
      }
    }
  }

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
  uint32_t r_fec_ssrc = 0;
  if (negotiated_has_video_) {
    const auto& rm = remote_desc.video_m_sections.front();
    negotiated_mid_ = rm.mid.empty() ? "0" : rm.mid;
    negotiated_codec_ = rm.codec;
    negotiated_h264_profile_level_id_ =
        rm.h264_profile_level_id.empty() ? "42e01f" : rm.h264_profile_level_id;
    negotiated_video_pt_.store(rm.video_pt, std::memory_order_relaxed);
    negotiated_has_rtx_ = rm.has_rtx;
    pacer_has_rtx_.store(rm.has_rtx, std::memory_order_release);
    if (rm.has_rtx) {
      negotiated_rtx_pt_.store(rm.rtx_pt, std::memory_order_relaxed);
    }
    negotiated_has_flexfec_ = rm.has_flexfec && config_.enable_flexfec;
    if (negotiated_has_flexfec_) {
      negotiated_flexfec_pt_ = rm.flexfec_pt;
      negotiated_flexfec_subtype_ = rm.flexfec_subtype;
      negotiated_flexfec_rw_us_ = rm.flexfec_repair_window_us;
    }
    negotiated_ext_map_ = rm.ext_map;
    {
      std::lock_guard<std::mutex> lk(pacer_ext_mu_);
      pacer_ext_map_ = negotiated_ext_map_;
    }
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
    negotiated_remote_track_id_ = r_track;
    r_media_ssrc = rm.primary_ssrc;
    r_rtx_ssrc = rm.primary_rtx_ssrc;
    r_fec_ssrc = rm.flexfec_ssrc;
  }

  // RFC 5763 §5 / RFC 8829 §5.3.1 DTLS 角色协商（重协商时若指纹未变且 DTLS 已连通则保持既有角色不断连）：
  const std::string norm_fp =
      NormalizeFingerprintUpper(remote_desc.dtls_fingerprint_sha256);
  const bool same_dtls_transport =
      dtls_srtp_ && dtls_srtp_->IsDtlsConnected() &&
      !negotiated_remote_fp_.empty() && norm_fp == negotiated_remote_fp_;

  DtlsRole local_dtls_role = DtlsRole::kClient;
  std::string answer_dtls_setup = "active";
  if (remote_is_offer) {
    if (remote_desc.dtls_setup == "active") {
      local_dtls_role = DtlsRole::kServer;
      answer_dtls_setup = "passive";
    } else if (remote_desc.dtls_setup == "passive") {
      local_dtls_role = DtlsRole::kClient;
      answer_dtls_setup = "active";
    } else {
      if (same_dtls_transport) {
        local_dtls_role = negotiated_dtls_role_;
        answer_dtls_setup =
            (local_dtls_role == DtlsRole::kClient) ? "active" : "passive";
      } else {
        local_dtls_role = DtlsRole::kClient;
        answer_dtls_setup = "active";
      }
    }
  } else {
    local_dtls_role = (remote_desc.dtls_setup == "active") ? DtlsRole::kServer
                                                           : DtlsRole::kClient;
  }
  negotiated_dtls_role_ = local_dtls_role;
  negotiated_remote_fp_ = norm_fp;

  if (!same_dtls_transport) {
    ice_->SetIceControlling(!remote_is_offer);
  }
  ice_->SetRemoteIceParameters(remote_desc.ice_params);
  if (!remote_desc.raw_candidate_lines.empty()) {
    for (const auto& raw_cand : remote_desc.raw_candidate_lines) {
      ice_->AddRemoteCandidateOrHostname(raw_cand);
    }
  } else {
    for (const auto& cand : remote_desc.candidates) {
      ice_->AddRemoteCandidate(cand);
    }
  }

  dtls_srtp_->SetRtpHeaderExtensionMap(negotiated_ext_map_);
  dtls_srtp_->SetDtlsRoleAndRemoteFingerprint(
      local_dtls_role, remote_desc.dtls_fingerprint_sha256);

  const VideoCodec r_codec = negotiated_codec_;
  const std::string mid_copy = negotiated_mid_;
  const uint8_t f_pt = negotiated_flexfec_pt_;
  const uint32_t f_rw_us = negotiated_flexfec_rw_us_;
  const bool use_fec03 = (negotiated_flexfec_subtype_ == "flexfec-03");
  const bool has_rtx = negotiated_has_rtx_;
  const bool has_fec = negotiated_has_flexfec_;
  const RtpHeaderExtensionMap ext_map_copy = negotiated_ext_map_;
  const bool has_vid = negotiated_has_video_;
  const bool has_dc = negotiated_has_datachannel_;
  const uint16_t r_sctp_port = remote_sctp_port_;
  const uint32_t r_sctp_max_msg =
      has_dc ? remote_desc.data_m_section->max_message_size : 0u;

  queues_->worker()->PostTask(SafeTask(
      work_safety_.flag(),
      [this, r_peer, r_track, r_media_ssrc, r_rtx_ssrc, r_fec_ssrc, r_codec,
       mid_copy, f_pt, f_rw_us, use_fec03, has_rtx, has_fec, ext_map_copy,
       has_vid, remote_sends, has_dc, local_dtls_role, r_sctp_port,
       r_sctp_max_msg, same_dtls_transport]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        worker_remote_peer_id_ = r_peer;
        worker_dtls_role_ = local_dtls_role;
        worker_has_datachannel_ = has_dc;
        worker_remote_sctp_port_ = r_sctp_port;
        worker_has_video_ = has_vid;
        if (has_dc) {
          sctp_dc_.set_remote_max_message_size(r_sctp_max_msg);
          if (media_ready_.load(std::memory_order_acquire)) {
            sctp_dc_.ConfigureAndStart(worker_dtls_role_, local_sctp_port_,
                                       worker_remote_sctp_port_);
          }
        }

        if (has_vid) {
          worker_codec_ = r_codec;
          worker_codec_negotiated_ = true;
          worker_mid_ = mid_copy;
          worker_ext_map_ = ext_map_copy;
          worker_has_rtx_ = has_rtx;
          worker_has_flexfec_ = has_fec;
          worker_flexfec_pt_ = f_pt;
          worker_flexfec_rw_us_ = f_rw_us;

          if (has_fec && outbound_.flexfec_ssrc != 0) {
            if (!outbound_.flexfec ||
                outbound_.flexfec->ssrc() != outbound_.flexfec_ssrc ||
                outbound_.flexfec->payload_type() != f_pt ||
                outbound_.flexfec_mid != mid_copy) {
              outbound_.flexfec = std::make_unique<FlexfecSender>(
                  f_pt, outbound_.flexfec_ssrc, outbound_.media_ssrc, mid_copy,
                  f_rw_us);
              outbound_.flexfec_mid = mid_copy;
            } else {
              outbound_.flexfec->set_repair_window_us(f_rw_us);
            }
            outbound_.flexfec->set_use_flexfec_03(use_fec03);
          } else {
            outbound_.flexfec.reset();
            outbound_.flexfec_mid.clear();
          }

          const bool can_preserve_inbound =
              same_dtls_transport && inbound_ != nullptr &&
              inbound_->codec == r_codec &&
              (r_media_ssrc == 0 || inbound_->media_ssrc == 0 ||
               inbound_->media_ssrc == r_media_ssrc);
          if (!can_preserve_inbound) {
            inbound_ = std::make_unique<InboundStreamState>(
                r_codec, clock_->CurrentTime(), config_.zero_playout_delay);
          }
          inbound_->remote_peer_id = r_peer;
          inbound_->remote_track_id = r_track;
          if (r_media_ssrc != 0) {
            inbound_->media_ssrc = r_media_ssrc;
          }
          if (r_rtx_ssrc != 0 || !has_rtx) {
            inbound_->rtx_ssrc = has_rtx ? r_rtx_ssrc : 0;
          }
          if (inbound_->media_ssrc != 0) {
            if (!inbound_->flexfec_rx || !can_preserve_inbound) {
              inbound_->flexfec_rx = std::make_unique<FlexfecReceiver>(
                  r_fec_ssrc, inbound_->media_ssrc, f_rw_us);
            } else {
              inbound_->flexfec_rx->set_repair_window_us(f_rw_us);
            }
            inbound_->flexfec_rx->set_extension_map(ext_map_copy);
          }

          demuxer_.RemoveSink(this);
          RtpDemuxCriteria crit;
          crit.mid = mid_copy;
          if (inbound_->media_ssrc != 0) {
            crit.ssrcs.push_back(inbound_->media_ssrc);
          }
          if (inbound_->rtx_ssrc != 0) {
            crit.ssrcs.push_back(inbound_->rtx_ssrc);
          }
          if (r_fec_ssrc != 0) {
            crit.ssrcs.push_back(r_fec_ssrc);
          }
          demuxer_.AddSink(crit, this);
          demuxer_.SetDefaultSink(this);

          if (remote_sends && !inbound_->track_announced &&
              observer_ != nullptr) {
            inbound_->track_announced = true;
            observer_->OnBackendRemoteTrackPublished(r_peer, r_track, r_codec);
          }
        } else {
          demuxer_.RemoveSink(this);
          inbound_.reset();
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
    if (!dtls_srtp_ || !dtls_srtp_->IsDtlsConnected()) {
      ice_->SetIceControlling(true);
    }
    if (negotiated_remote_fp_.empty()) {
      negotiated_codec_ = static_cast<VideoCodec>(config_.publish_codec);
      negotiated_h264_profile_level_id_ = "42e01f";
      negotiated_ext_map_ = RtpHeaderExtensionMap::BrowserDefault();
      {
        std::lock_guard<std::mutex> lk(pacer_ext_mu_);
        pacer_ext_map_ = negotiated_ext_map_;
      }
      const VideoCodec offer_codec = negotiated_codec_;
      const RtpHeaderExtensionMap offer_ext = negotiated_ext_map_;
      queues_->worker()->PostTask(
          SafeTask(work_safety_.flag(), [this, offer_codec, offer_ext]() {
            RTC_DCHECK_RUN_ON(&work_checker_);
            worker_codec_ = offer_codec;
            worker_ext_map_ = offer_ext;
          }));
      dtls_srtp_->SetRtpHeaderExtensionMap(negotiated_ext_map_);
    }
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
  std::string cand_copy(candidate_sdp);
  queues_->signaling()->PostTask(
      SafeTask(sig_safety_.flag(), [this, cand_str = std::move(cand_copy)]() {
        RTC_DCHECK_RUN_ON(&sig_checker_);
        if (ice_) {
          ice_->AddRemoteCandidateOrHostname(cand_str);
        }
      }));
  return RTC_OK;
}

void WebRtcP2pBackend::OnSignalingConnected() {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  // 严禁在 WS 握手完成瞬间清零 sig_reconnect_attempts_，防止鉴权拒绝秒断时陷入无限 200ms 重连风暴。
  sig_connected_at_ = clock_->CurrentTime();
  const uint64_t conn_gen = ++sig_conn_gen_;
  JsonObject join_msg;
  join_msg.SetString("type", "join");
  join_msg.SetString("room_id", room_id_);
  join_msg.SetString("peer_id", local_peer_id_);
  join_msg.SetString("token", config_.auth_token);
  signaling_->SendText(join_msg.Serialize());
  signaling_joined_ = true;

  queues_->signaling()->PostDelayedTask(
      SafeTask(sig_safety_.flag(),
               [this, conn_gen]() {
                 RTC_DCHECK_RUN_ON(&sig_checker_);
                 if (session_active_ && signaling_joined_ &&
                     sig_conn_gen_ == conn_gen) {
                   sig_reconnect_attempts_ = 0;
                 }
               }),
      TimeDelta::Seconds(2));
}

void WebRtcP2pBackend::OnSignalingMessage(const std::string& json_text) {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  const auto msg = JsonObject::Parse(json_text);
  if (!msg.has_value()) {
    return;
  }
  const std::string type = msg->GetString("type");
  const std::string target_peer = msg->GetString("target_peer_id");
  if (!target_peer.empty() && target_peer != local_peer_id_) {
    return;
  }

  if (type == "peer_joined") {
    const std::string peer = msg->GetString("peer_id");
    if (peer.empty() || peer == local_peer_id_) {
      return;
    }
    sig_reconnect_attempts_ = 0;
    if (has_paired_remote_peer_ && peer != remote_peer_id_) {
      RTC_LOG(kWarning) << "Ignoring 3rd-party peer_joined from '" << peer
                        << "' while paired with '" << remote_peer_id_ << "'";
      return;
    }
    remote_peer_id_ = peer;
    has_paired_remote_peer_ = true;
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
    if (from_peer == local_peer_id_) {
      return;
    }
    if (has_paired_remote_peer_ && !from_peer.empty() &&
        from_peer != remote_peer_id_) {
      return;
    }
    sig_reconnect_attempts_ = 0;
    if (!from_peer.empty()) {
      remote_peer_id_ = from_peer;
      has_paired_remote_peer_ = true;
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
    if (from_peer == local_peer_id_) {
      return;
    }
    if (has_paired_remote_peer_ && !from_peer.empty() &&
        from_peer != remote_peer_id_) {
      return;
    }
    sig_reconnect_attempts_ = 0;
    if (!from_peer.empty()) {
      remote_peer_id_ = from_peer;
      has_paired_remote_peer_ = true;
    }
    const auto remote_ans = PureVideoSdpDescription::Parse(
        msg->GetString("sdp"), static_cast<VideoCodec>(config_.publish_codec));
    if (remote_ans.has_value()) {
      ApplyRemoteSdpOnSigQueue(*remote_ans, /*remote_is_offer=*/false, nullptr);
      RTC_LOG(kInfo) << "Applied WebRTC P2P SDP Answer from peer="
                     << remote_peer_id_;
    }
  } else if (type == "candidate") {
    const std::string from_peer = msg->GetString("peer_id");
    if (from_peer == local_peer_id_) {
      return;
    }
    if (has_paired_remote_peer_ && !from_peer.empty() &&
        from_peer != remote_peer_id_) {
      return;
    }
    const std::string cand_str = msg->GetString("candidate");
    if (!cand_str.empty() && ice_) {
      ice_->AddRemoteCandidateOrHostname(cand_str);
    }
  } else if (type == "peer_left") {
    const std::string peer = msg->GetString("peer_id");
    if (!has_paired_remote_peer_ || peer.empty() || peer != remote_peer_id_) {
      return;
    }
    const std::string track_to_unpub =
        negotiated_remote_track_id_.empty() ? (peer + "_video0")
                                            : negotiated_remote_track_id_;
    has_paired_remote_peer_ = false;
    remote_peer_id_ = "remote_peer";
    negotiated_remote_track_id_.clear();
    negotiated_remote_fp_.clear();
    offer_sent_ = false;
    if (observer_ != nullptr) {
      observer_->OnBackendRemoteTrackUnpublished(peer, track_to_unpub);
    }
  }
}

void WebRtcP2pBackend::OnSignalingClosed(int code,
                                         const std::string& /*reason*/) {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  signaling_joined_ = false;
  ++sig_conn_gen_;
  if (sig_connected_at_.IsFinite() &&
      (clock_->CurrentTime() - sig_connected_at_) >= TimeDelta::Seconds(2)) {
    sig_reconnect_attempts_ = 0;
  }
  sig_connected_at_ = Timestamp::MinusInfinity();
  if (!session_active_ || config_.signaling_or_moq_url.empty()) {
    return;
  }

  constexpr uint32_t kMaxSigReconnects = 4;
  if (sig_reconnect_attempts_ < kMaxSigReconnects) {
    const uint32_t attempt = ++sig_reconnect_attempts_;
    const int64_t backoff_ms = 200LL << (attempt - 1);
    if (!media_ready_.load(std::memory_order_acquire) && observer_ != nullptr) {
      observer_->OnBackendConnectionState(RTC_CONN_STATE_RECONNECTING, code);
    }
    RTC_LOG(kWarning) << "Signaling closed (code=" << code
                      << "), scheduling reconnect attempt " << attempt << "/"
                      << kMaxSigReconnects << " in " << backoff_ms << "ms";
    queues_->signaling()->PostDelayedTask(
        SafeTask(sig_safety_.flag(),
                 [this]() {
                   RTC_DCHECK_RUN_ON(&sig_checker_);
                   if (session_active_ && !signaling_joined_) {
                     offer_sent_ = false;
                     ConnectSignalingOnSigQueue();
                   }
                 }),
        TimeDelta::Millis(backoff_ms));
    return;
  }

  if (!media_ready_.load(std::memory_order_acquire) && observer_ != nullptr) {
    observer_->OnBackendConnectionState(RTC_CONN_STATE_FAILED,
                                        code != 0 ? code : -3);
  }
}

void WebRtcP2pBackend::OnDtlsSrtpHandshakeComplete() {
  if (ice_) {
    cached_ice_rtt_us_.store(ice_->last_rtt().us(), std::memory_order_relaxed);
  }
  const bool was_ready = media_ready_.exchange(true, std::memory_order_acq_rel);
  queues_->worker()->PostTask(SafeTask(work_safety_.flag(), [this]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    // 在 DTLS-SRTP 握手完成且媒体通道就绪后再触发初始带宽探测簇（3x / 6x），避免探测包在就绪前被丢弃。
    ApplyNetworkControlUpdate(
        goog_cc_->OnNetworkAvailability(clock_->CurrentTime(), true));
    if (worker_has_datachannel_) {
      sctp_dc_.ConfigureAndStart(worker_dtls_role_, local_sctp_port_,
                                 worker_remote_sctp_port_);
    }
  }));
  if (!was_ready && observer_ != nullptr) {
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
  if (packet.empty() || !media_ready_.load(std::memory_order_acquire)) {
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
        inbound_ ? inbound_->remote_peer_id : worker_remote_peer_id_;
    observer_->OnBackendDataChannelState(peer, channel_id, label, state);
  }
}

void WebRtcP2pBackend::OnSctpDataChannelMessage(int channel_id,
                                                bool is_binary,
                                                std::vector<uint8_t> payload) {
  RTC_DCHECK_RUN_ON(&work_checker_);
  if (observer_ != nullptr) {
    const std::string peer =
        inbound_ ? inbound_->remote_peer_id : worker_remote_peer_id_;
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

void WebRtcP2pBackend::OnIceTransportState(IceTransportState state) {
  if (ice_) {
    cached_ice_rtt_us_.store(ice_->last_rtt().us(), std::memory_order_relaxed);
  }
  if (state == IceTransportState::kConnected ||
      state == IceTransportState::kCompleted) {
    if (dtls_srtp_ && dtls_srtp_->IsDtlsConnected()) {
      if (!media_ready_.exchange(true, std::memory_order_acq_rel)) {
        queues_->worker()->PostTask(SafeTask(work_safety_.flag(), [this]() {
          RTC_DCHECK_RUN_ON(&work_checker_);
          ApplyNetworkControlUpdate(
              goog_cc_->OnNetworkAvailability(clock_->CurrentTime(), true));
        }));
        if (observer_ != nullptr) {
          observer_->OnBackendConnectionState(RTC_CONN_STATE_CONNECTED, 0);
          observer_->OnBackendForceKeyFrame(SpatialLayer::kHigh);
        }
      }
    }
  } else if (state == IceTransportState::kFailed) {
    media_ready_.store(false, std::memory_order_release);
    if (observer_ != nullptr) {
      observer_->OnBackendConnectionState(RTC_CONN_STATE_FAILED, -4);
    }
  } else if (state == IceTransportState::kDisconnected) {
    if (media_ready_.exchange(false, std::memory_order_acq_rel)) {
      queues_->worker()->PostTask(SafeTask(work_safety_.flag(), [this]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        ApplyNetworkControlUpdate(
            goog_cc_->OnNetworkAvailability(clock_->CurrentTime(), false));
      }));
      if (observer_ != nullptr) {
        observer_->OnBackendConnectionState(RTC_CONN_STATE_DISCONNECTED, -5);
      }
    }
  }
}

int WebRtcP2pBackend::SendEncodedFrame(EncodedVideoFrame frame) {
  if (!media_ready_.load(std::memory_order_acquire)) {
    return RTC_ERR_NOT_CONNECTED;
  }

  queues_->worker()->PostTask(
      SafeTask(work_safety_.flag(), [this, f = std::move(frame)]() mutable {
        RTC_DCHECK_RUN_ON(&work_checker_);
        if (!worker_has_video_) {
          return;
        }
        if (worker_codec_negotiated_ && f.codec != worker_codec_) {
          RTC_LOG(kWarning)
              << "Dropping outbound video frame due to codec mismatch with "
                 "negotiated SDP";
          return;
        }
        bool detected_kf = f.dep.is_keyframe;
        std::vector<PacketizedPayload> payloads;
        if (f.codec == VideoCodec::kH265) {
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

        const uint8_t vid_pt =
            negotiated_video_pt_.load(std::memory_order_relaxed);
        for (size_t i = 0; i < payloads.size(); ++i) {
          auto pkt = std::make_unique<RtpPacket>();
          pkt->set_extension_map(worker_ext_map_);
          pkt->set_payload_type(vid_pt);
          pkt->set_ssrc(outbound_.media_ssrc);
          pkt->set_sequence_number(outbound_.next_rtp_seq++);
          pkt->set_timestamp(f.rtp_timestamp);
          pkt->set_marker(payloads[i].is_last_in_frame);

          if (worker_ext_map_.mid_id != 0) {
            pkt->SetMid(worker_mid_);
          }
          if (config_.zero_playout_delay && payloads[i].is_first_in_frame &&
              worker_ext_map_.playout_delay_id != 0) {
            pkt->set_playout_delay(PlayoutDelayLimits{0, 0});
          }

          *pkt->mutable_payload() = std::move(payloads[i].bytes);
          batch.emplace_back(detected_kf ? RtpPacketMediaType::kVideoKeyFrame
                                         : RtpPacketMediaType::kVideoDelta,
                             std::move(pkt));
        }

        paced_sender_->EnqueuePackets(std::move(batch));
      }));
  return RTC_OK;
}

void WebRtcP2pBackend::SendPacedPacket(std::unique_ptr<RtpPacket> packet,
                                       const PacedPacketInfo& cluster_info) {
  if (!media_ready_.load(std::memory_order_acquire)) {
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
  const bool is_video_media =
      (packet->ssrc() == outbound_.media_ssrc &&
       packet->payload_type() ==
           negotiated_video_pt_.load(std::memory_order_relaxed) &&
       packet->payload_size() > 0);
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
          // 在 TWCC 与 AbsSendTime 扩展头均已最终打标后生成 RFC 8627 FlexFEC 校验包，
          // 确保发送端异或输入的线速字节与接收端 SRTP 解密后的线速字节 100% 逐比特一致。
          if (outbound_.flexfec) {
            outbound_.flexfec->AddRtpPacketAndGenerateFec(raw_copy);
            auto fec_pkts = outbound_.flexfec->GetFecPackets();
            if (!fec_pkts.empty()) {
              std::vector<
                  std::pair<RtpPacketMediaType, std::unique_ptr<RtpPacket>>>
                  fec_batch;
              fec_batch.reserve(fec_pkts.size());
              for (auto& fp : fec_pkts) {
                fp.set_extension_map(worker_ext_map_);
                fec_batch.emplace_back(
                    RtpPacketMediaType::kForwardErrorCorrection,
                    std::make_unique<RtpPacket>(std::move(fp)));
              }
              paced_sender_->EnqueuePackets(std::move(fec_batch));
            }
          }
        }
        twcc_adapter_.AddPacket(twcc_seq, pkt_size, cluster_info, send_time);
        if (auto sent = twcc_adapter_.ProcessSentPacket(twcc_seq, send_time)) {
          ApplyNetworkControlUpdate(goog_cc_->OnSentPacket(*sent));
        }
        paced_sender_->UpdateOutstandingData(twcc_adapter_.outstanding_data());
      }));
}

std::vector<std::unique_ptr<RtpPacket>> WebRtcP2pBackend::GeneratePadding(
    DataSize target_size) {
  std::vector<std::unique_ptr<RtpPacket>> pad_pkts;
  if (!pacer_has_rtx_.load(std::memory_order_relaxed)) {
    return pad_pkts;
  }
  RtpHeaderExtensionMap ext_map;
  {
    std::lock_guard<std::mutex> lk(pacer_ext_mu_);
    ext_map = pacer_ext_map_;
  }
  const uint8_t rtx_pt = negotiated_rtx_pt_.load(std::memory_order_relaxed);
  int64_t rem = target_size.bytes();
  while (rem > 0) {
    auto p = std::make_unique<RtpPacket>();
    p->set_extension_map(ext_map);
    // 探测填充包固定使用独立的 rtx_ssrc 与原子递增 next_rtx_seq，严禁借用 media_ssrc 发送乱序空包污染 SRTP 防重放窗口。
    p->set_payload_type(rtx_pt);
    p->set_ssrc(outbound_.rtx_ssrc);
    p->set_sequence_number(
        outbound_.next_rtx_seq.fetch_add(1, std::memory_order_relaxed));
    p->set_timestamp(MicrosToRtp90kHz(clock_->CurrentTime().us()));
    const size_t pad = static_cast<size_t>(std::clamp<int64_t>(rem - 12, 1, 224));
    p->set_padding_size(pad);
    rem -= static_cast<int64_t>(p->SerializedSize());
    pad_pkts.push_back(std::move(p));
  }
  return pad_pkts;
}

void WebRtcP2pBackend::OnDecryptedRtpPacket(const RtpPacket& packet,
                                            Timestamp receive_time) {
  if (ice_) {
    cached_ice_rtt_us_.store(ice_->last_rtt().us(), std::memory_order_relaxed);
  }
  RtpPacket copy = packet;
  queues_->worker()->PostTask(SafeTask(
      work_safety_.flag(), [this, pkt = std::move(copy), receive_time]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        if (auto tseq = pkt.transport_sequence_number()) {
          if (rx_twcc_records_.size() >= 512) {
            SendCompoundRtcpFeedback(receive_time);
          }
          rx_twcc_records_.emplace_back(*tseq, receive_time);
        }
        demuxer_.OnRtpPacket(pkt, receive_time);
      }));
}

void WebRtcP2pBackend::OnRtpPacket(const RtpPacket& packet,
                                   Timestamp receive_time) {
  RTC_DCHECK_RUN_ON(&work_checker_);
  if (!inbound_) {
    return;
  }

  const uint8_t pkt_pt = packet.payload_type();
  const uint8_t rtx_pt = negotiated_rtx_pt_.load(std::memory_order_relaxed);
  const uint8_t vid_pt = negotiated_video_pt_.load(std::memory_order_relaxed);

  // 1. 处理符合 RFC 8627 的 FlexFEC 前向纠错修复包。
  if (worker_has_flexfec_ && pkt_pt == worker_flexfec_pt_) {
    if (packet.payload().empty()) {
      return;
    }
    if (!inbound_->flexfec_rx && inbound_->media_ssrc != 0) {
      inbound_->flexfec_rx = std::make_unique<FlexfecReceiver>(
          packet.ssrc(), inbound_->media_ssrc, worker_flexfec_rw_us_);
      inbound_->flexfec_rx->set_extension_map(worker_ext_map_);
    }
    if (inbound_->flexfec_rx) {
      for (const auto& rec : inbound_->flexfec_rx->OnRtpPacket(packet)) {
        if (rec.payload().empty()) {
          HandleMediaPaddingPacketOnWorker(rec.sequence_number(), rec.ssrc(),
                                           receive_time,
                                           /*is_recovered=*/true);
        } else {
          HandleMediaRtpPacketOnWorker(rec, receive_time,
                                       /*is_recovered=*/true);
        }
      }
    }
    return;
  }

  // 2. 处理符合 RFC 4588 的 RTX 重传包（严格过滤 RTX Payload Type）。
  if (worker_has_rtx_ && pkt_pt == rtx_pt) {
    if (packet.payload().empty() || inbound_->media_ssrc == 0) {
      return;
    }
    auto recovered =
        RtxCodec::ParseRtxPacket(packet, inbound_->media_ssrc, vid_pt);
    if (recovered.has_value()) {
      if (recovered->payload().empty()) {
        HandleMediaPaddingPacketOnWorker(recovered->sequence_number(),
                                         recovered->ssrc(), receive_time,
                                         /*is_recovered=*/true);
      } else {
        HandleMediaRtpPacketOnWorker(*recovered, receive_time,
                                     /*is_recovered=*/true);
      }
    }
    return;
  }

  // 3. 过滤非协商主视频 PT 的未知 RTP 流（如混入的音频/冗余探测负载类型）。
  if (pkt_pt != vid_pt) {
    return;
  }

  // 4. 处理主媒体流上的空负载 RTP Padding 包（推进 NACK 与连续序列号桥接，防止 ReferenceFinder 永久卡顿）。
  if (packet.payload().empty()) {
    if (inbound_->media_ssrc != 0 && packet.ssrc() == inbound_->media_ssrc) {
      const int64_t wire_uw =
          inbound_->wire_seq_unwrapper.Unwrap(packet.sequence_number());
      if (!inbound_->max_wire_unwrapped_seq.has_value() ||
          wire_uw > *inbound_->max_wire_unwrapped_seq) {
        inbound_->max_wire_unwrapped_seq = wire_uw;
      }
      ++inbound_->wire_media_packets_received;
      HandleMediaPaddingPacketOnWorker(packet.sequence_number(), packet.ssrc(),
                                       receive_time, /*is_recovered=*/false);
    }
    return;
  }

  // 5. 主视频媒体流非空 RTP 包（支持未在信令中预声明的浏览器动态 SSRC）。
  if (inbound_->media_ssrc == 0) {
    inbound_->media_ssrc = packet.ssrc();
    inbound_->flexfec_rx = std::make_unique<FlexfecReceiver>(
        0, inbound_->media_ssrc, worker_flexfec_rw_us_);
    inbound_->flexfec_rx->set_extension_map(worker_ext_map_);
    if (!inbound_->track_announced && observer_ != nullptr) {
      inbound_->track_announced = true;
      observer_->OnBackendRemoteTrackPublished(
          inbound_->remote_peer_id, inbound_->remote_track_id, inbound_->codec);
    }
  }
  if (packet.ssrc() == inbound_->media_ssrc) {
    const int64_t wire_uw =
        inbound_->wire_seq_unwrapper.Unwrap(packet.sequence_number());
    if (!inbound_->max_wire_unwrapped_seq.has_value() ||
        wire_uw > *inbound_->max_wire_unwrapped_seq) {
      inbound_->max_wire_unwrapped_seq = wire_uw;
    }
    ++inbound_->wire_media_packets_received;
    if (inbound_->flexfec_rx) {
      (void)inbound_->flexfec_rx->OnRtpPacket(packet);
    }
    HandleMediaRtpPacketOnWorker(packet, receive_time);
  }
}

void WebRtcP2pBackend::HandleMediaPaddingPacketOnWorker(uint16_t seq_num,
                                                        uint32_t ssrc,
                                                        Timestamp receive_time,
                                                        bool is_recovered) {
  if (!inbound_) {
    return;
  }
  ++inbound_->packets_received;
  inbound_->highest_seq_received =
      std::max<uint32_t>(inbound_->highest_seq_received, seq_num);
  inbound_->MarkPaddingSeq(seq_num);

  bool kf_req = false;
  auto nacks = inbound_->nack_module.OnReceivedPacket(
      seq_num, false, is_recovered, receive_time, &kf_req);
  if (!nacks.empty()) {
    RtcpNack nack_pkt;
    nack_pkt.sender_ssrc = outbound_.media_ssrc;
    nack_pkt.media_ssrc = ssrc;
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

  DrainPendingAssembledFramesOnWorker();
  DrainDecodableFramesOnWorker();
}

void WebRtcP2pBackend::DrainPendingAssembledFramesOnWorker() {
  if (!inbound_ || !inbound_->last_continuous_seq_end.has_value() ||
      inbound_->pending_assembled_frames.empty()) {
    return;
  }
  bool progressed = true;
  while (progressed && inbound_ && !inbound_->pending_assembled_frames.empty() &&
         inbound_->last_continuous_seq_end.has_value()) {
    progressed = false;
    uint16_t expected_next =
        static_cast<uint16_t>(*inbound_->last_continuous_seq_end + 1);
    uint16_t bridged_next = expected_next;
    size_t pad_steps = 0;
    while (pad_steps < InboundStreamState::kPaddingSeqRingSize &&
           inbound_->IsPaddingSeq(bridged_next)) {
      ++bridged_next;
      ++pad_steps;
    }

    for (auto it = inbound_->pending_assembled_frames.begin();
         it != inbound_->pending_assembled_frames.end();) {
      if (AheadOf<uint16_t>(*inbound_->last_continuous_seq_end,
                            it->last_seq_num)) {
        it = inbound_->pending_assembled_frames.erase(it);
        continue;
      }
      if (it->first_seq_num == bridged_next) {
        AssembledRtpFrame ready_frame = std::move(*it);
        it = inbound_->pending_assembled_frames.erase(it);
        ready_frame.first_seq_num = expected_next;
        inbound_->last_continuous_seq_end = ready_frame.last_seq_num;
        for (auto& resolved :
             inbound_->ref_finder.ManageFrame(std::move(ready_frame))) {
          inbound_->frame_buffer.InsertFrame(std::move(resolved));
        }
        progressed = true;
        break;
      }
      ++it;
    }
  }
}

void WebRtcP2pBackend::DrainDecodableFramesOnWorker() {
  if (!inbound_) {
    return;
  }
  while (inbound_) {
    auto dec = inbound_->frame_buffer.ExtractNextDecodableFrame();
    if (!dec.has_value()) {
      break;
    }
    if (dec->dep.is_keyframe) {
      // 当全新可解码关键帧就绪后，清理包含该关键帧末包序列号在内的旧 NACK 与分片槽位，防止滞后误触发 PLI。
      inbound_->nack_module.ClearUpTo(
          static_cast<uint16_t>(dec->last_seq_num + 1));
      inbound_->packet_buffer.ClearTo(dec->last_seq_num);
    }

    // 通过 90kHz RTP 时间戳展开计算严格单调不减的采集时间，避免乱序重传恢复导致乱序 received_time 倒退。
    const int64_t unwrapped_ts =
        inbound_->rtp_ts_unwrapper.Unwrap(dec->rtp_timestamp);
    if (!inbound_->base_unwrapped_rtp_ts.has_value()) {
      inbound_->base_unwrapped_rtp_ts = unwrapped_ts;
      inbound_->base_capture_time =
          (dec->received_time.IsFinite() && dec->received_time.us() > 0)
              ? dec->received_time
              : Timestamp::Micros(1'000'000);
    }
    const int64_t delta_ticks = unwrapped_ts - *inbound_->base_unwrapped_rtp_ts;
    const int64_t delta_us =
        (delta_ticks / 90) * 1000 + ((delta_ticks % 90) * 1000) / 90;
    int64_t cap_us =
        std::max<int64_t>(0, inbound_->base_capture_time.us() + delta_us);
    if (cap_us < inbound_->last_emitted_capture_us) {
      cap_us = inbound_->last_emitted_capture_us;
    }
    inbound_->last_emitted_capture_us = cap_us;

    if (!video_muted_.load(std::memory_order_acquire)) {
      stat_frames_decoded_.fetch_add(1, std::memory_order_relaxed);
      EncodedVideoFrame out;
      out.data = std::move(dec->annexb_bitstream);
      out.capture_time = Timestamp::Micros(cap_us);
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
}

void WebRtcP2pBackend::HandleMediaRtpPacketOnWorker(const RtpPacket& media_pkt,
                                                    Timestamp receive_time,
                                                    bool is_recovered) {
  if (!inbound_) {
    return;
  }
  inbound_->ClearPaddingSeq(media_pkt.sequence_number());
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
  const TimeDelta ice_rtt =
      TimeDelta::Micros(cached_ice_rtt_us_.load(std::memory_order_relaxed));
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
    if (raw_f.playout_delay.has_value()) {
      inbound_->vcm_timing.SetPlayoutDelay(*raw_f.playout_delay);
    }
    inbound_->vcm_timing.SetJitterDelay(
        inbound_->jitter_estimator.GetJitterEstimate(1.0, ice_rtt));
    inbound_->vcm_timing.IncomingTimestamp(raw_f.rtp_timestamp, receive_time);

    if (raw_f.dependency_ext.has_value()) {
      for (auto& resolved : inbound_->ref_finder.ManageFrame(std::move(raw_f))) {
        inbound_->frame_buffer.InsertFrame(std::move(resolved));
      }
    } else if (raw_f.is_keyframe) {
      const uint16_t kf_end_seq = raw_f.last_seq_num;
      for (auto it = inbound_->pending_assembled_frames.begin();
           it != inbound_->pending_assembled_frames.end();) {
        if (AheadOrAt<uint16_t>(kf_end_seq, it->last_seq_num)) {
          it = inbound_->pending_assembled_frames.erase(it);
        } else {
          ++it;
        }
      }
      inbound_->last_continuous_seq_end = kf_end_seq;
      for (auto& resolved : inbound_->ref_finder.ManageFrame(std::move(raw_f))) {
        inbound_->frame_buffer.InsertFrame(std::move(resolved));
      }
      DrainPendingAssembledFramesOnWorker();
    } else {
      inbound_->pending_assembled_frames.push_back(std::move(raw_f));
      while (inbound_->pending_assembled_frames.size() > 64) {
        inbound_->pending_assembled_frames.pop_front();
      }
      DrainPendingAssembledFramesOnWorker();
    }
  }

  DrainDecodableFramesOnWorker();
}

void WebRtcP2pBackend::OnDecryptedRtcpPacket(
    ArrayView<const uint8_t> compound_rtcp,
    Timestamp receive_time) {
  if (ice_) {
    cached_ice_rtt_us_.store(ice_->last_rtt().us(), std::memory_order_relaxed);
  }
  std::vector<uint8_t> copy(compound_rtcp.begin(), compound_rtcp.end());
  queues_->worker()->PostTask(SafeTask(
      work_safety_.flag(), [this, buf = std::move(copy), receive_time]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const ParsedCompoundRtcp parsed = ParseCompoundRtcp(buf);

        for (const auto& twcc : parsed.transport_feedbacks) {
          has_received_twcc_ = true;
          if (auto msg =
                  twcc_adapter_.ProcessTransportFeedback(twcc, receive_time)) {
            Timestamp max_send = Timestamp::MinusInfinity();
            for (const auto& pkt_res : msg->packet_feedbacks) {
              if (pkt_res.IsReceived() &&
                  pkt_res.sent_packet.send_time.IsFinite()) {
                max_send = std::max(max_send, pkt_res.sent_packet.send_time);
              }
            }
            if (max_send.IsFinite() && receive_time > max_send) {
              twcc_rtt_samples_.emplace_back(receive_time,
                                             receive_time - max_send);
              while (!twcc_rtt_samples_.empty() &&
                     (receive_time - twcc_rtt_samples_.front().first) >
                         TimeDelta::Millis(1500)) {
                twcc_rtt_samples_.pop_front();
              }
            }
            ApplyNetworkControlUpdate(
                goog_cc_->OnTransportPacketsFeedback(*msg));
          }
        }

        if (!has_received_twcc_ &&
            worker_ext_map_.transport_sequence_number_id == 0) {
          const TimeDelta ice_rtt = TimeDelta::Micros(
              cached_ice_rtt_us_.load(std::memory_order_relaxed));
          auto apply_report_blocks =
              [&](const std::vector<RtcpReportBlock>& blocks) {
                for (const auto& rb : blocks) {
                  if (rb.source_ssrc != 0 &&
                      rb.source_ssrc != outbound_.media_ssrc) {
                    continue;
                  }
                  latest_uplink_loss_ =
                      static_cast<double>(rb.fraction_lost) / 256.0;
                  ApplyNetworkControlUpdate(goog_cc_->OnReceiverReport(
                      receive_time, rb.fraction_lost, ice_rtt));
                }
              };
          for (const auto& sr : parsed.sender_reports) {
            apply_report_blocks(sr.report_blocks);
          }
          for (const auto& rr : parsed.receiver_reports) {
            apply_report_blocks(rr.report_blocks);
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
              if (worker_has_rtx_) {
                RtpPacket rtx = RtxCodec::BuildRtxPacket(
                    *orig, outbound_.rtx_ssrc,
                    negotiated_rtx_pt_.load(std::memory_order_relaxed),
                    outbound_.next_rtx_seq.fetch_add(
                        1, std::memory_order_relaxed));
                rtx.set_extension_map(worker_ext_map_);
                rtx_batch.emplace_back(
                    RtpPacketMediaType::kRetransmission,
                    std::make_unique<RtpPacket>(std::move(rtx)));
              } else if (outbound_.flexfec) {
                // 未协商 RFC 4588 RTX 时，遵循 RFC 8627 第 4.2.2.3 节使用 FlexFEC R=1,F=0 单包重传封装，
                // 严禁在原媒体 SSRC 上复用旧序列号（否则违反 SRTP AES-GCM Nonce 唯一性并触发重放拒绝）。
                if (auto fec_rtx =
                        outbound_.flexfec->BuildRetransmissionPacket(*orig)) {
                  fec_rtx->set_extension_map(worker_ext_map_);
                  rtx_batch.emplace_back(
                      RtpPacketMediaType::kRetransmission,
                      std::make_unique<RtpPacket>(std::move(*fec_rtx)));
                }
              }
            }
          }
          if (!rtx_batch.empty()) {
            paced_sender_->EnqueuePackets(std::move(rtx_batch));
          }
        }

        // RFC 5104 §4.3.1.2 FIR (sender_ssrc, seq) 去重 + 150ms IDR 节流保护，抵御 PLI/FIR 洪水攻击。
        bool should_force_idr = false;
        for (const auto& pli : parsed.plis) {
          if (pli.media_ssrc == 0 || pli.media_ssrc == outbound_.media_ssrc) {
            should_force_idr = true;
            break;
          }
        }
        for (const auto& fir : parsed.firs) {
          if (fir.media_ssrc != 0 && fir.media_ssrc != outbound_.media_ssrc) {
            continue;
          }
          const auto fit = last_fir_seq_by_ssrc_.find(fir.sender_ssrc);
          if (fit != last_fir_seq_by_ssrc_.end() &&
              fit->second == fir.command_seq_num) {
            continue;
          }
          if (fit == last_fir_seq_by_ssrc_.end() &&
              last_fir_seq_by_ssrc_.size() >= 32) {
            last_fir_seq_by_ssrc_.erase(last_fir_seq_by_ssrc_.begin());
          }
          last_fir_seq_by_ssrc_[fir.sender_ssrc] = fir.command_seq_num;
          should_force_idr = true;
        }
        if (should_force_idr &&
            (!last_idr_forced_at_.IsFinite() ||
             (receive_time - last_idr_forced_at_) >= TimeDelta::Millis(150))) {
          last_idr_forced_at_ = receive_time;
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
    const TimeDelta ice_rtt =
        TimeDelta::Micros(cached_ice_rtt_us_.load(std::memory_order_relaxed));
    TimeDelta effective_rtt = ice_rtt;
    while (!twcc_rtt_samples_.empty() &&
           (now - twcc_rtt_samples_.front().first) > TimeDelta::Millis(1500)) {
      twcc_rtt_samples_.pop_front();
    }
    if (!twcc_rtt_samples_.empty()) {
      TimeDelta min_twcc_rtt = Timestamp::PlusInfinity() - Timestamp::Zero();
      for (const auto& [ts, sample] : twcc_rtt_samples_) {
        (void)ts;
        min_twcc_rtt = std::min(min_twcc_rtt, sample);
      }
      if (min_twcc_rtt.IsFinite()) {
        effective_rtt = std::max(ice_rtt, min_twcc_rtt);
      }
    }
    outbound_.history.SetRtt(effective_rtt);
    twcc_adapter_.CullExpiredInFlight(now);
    paced_sender_->UpdateOutstandingData(twcc_adapter_.outstanding_data());
    ApplyNetworkControlUpdate(goog_cc_->OnRoundTripTimeUpdate(now, effective_rtt));
    ApplyNetworkControlUpdate(goog_cc_->OnProcessInterval(now));

    if (inbound_) {
      inbound_->nack_module.UpdateRtt(effective_rtt);
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
          std::max(TimeDelta::Millis(250), effective_rtt * 2);
      bool pending_stalled = false;
      for (const auto& pf : inbound_->pending_assembled_frames) {
        if (pf.received_time.IsFinite() &&
            (now - pf.received_time) >= stall_thresh) {
          pending_stalled = true;
          break;
        }
      }
      if (need_kf || pending_stalled ||
          inbound_->ref_finder.HasStalledFrames(now, stall_thresh) ||
          inbound_->frame_buffer.IsCorruptedOrStalled(now, stall_thresh)) {
        SendPliForRemoteStream(now);
      }
    }

    if (last_sr_rr_sent_.IsMinusInfinity() ||
        (now - last_sr_rr_sent_) >= TimeDelta::Millis(1000)) {
      last_sr_rr_sent_ = now;
      queues_->network()->PostTask(SafeTask(net_safety_.flag(), [this]() {
        if (ice_) {
          cached_ice_rtt_us_.store(ice_->last_rtt().us(),
                                   std::memory_order_relaxed);
        }
      }));
      float downlink_loss = 0.0f;
      if (inbound_ && inbound_->media_ssrc != 0 &&
          inbound_->max_wire_unwrapped_seq.has_value()) {
        const int64_t cur_max = *inbound_->max_wire_unwrapped_seq;
        const uint64_t cur_pkts = inbound_->wire_media_packets_received;
        if (inbound_->prev_rr_max_seq >= 0 &&
            cur_max > inbound_->prev_rr_max_seq) {
          const int64_t expected_interval = cur_max - inbound_->prev_rr_max_seq;
          const int64_t rx_interval =
              static_cast<int64_t>(cur_pkts - inbound_->prev_rr_pkts);
          const int64_t lost_interval =
              std::max<int64_t>(0, expected_interval - rx_interval);
          downlink_loss = std::clamp(
              static_cast<float>(lost_interval) /
                  static_cast<float>(expected_interval),
              0.0f, 1.0f);
          inbound_->latest_downlink_loss = downlink_loss;

          RtcpReceiverReport rr;
          rr.sender_ssrc = outbound_.media_ssrc;
          RtcpReportBlock rb;
          rb.source_ssrc = inbound_->media_ssrc;
          rb.fraction_lost =
              static_cast<uint8_t>(std::lround(downlink_loss * 255.0f));
          rb.extended_high_seq_num = static_cast<uint32_t>(cur_max & 0xFFFFFFFF);
          rr.report_blocks.push_back(rb);
          auto rr_wire = rr.Build();
          if (worker_ext_map_.transport_sequence_number_id != 0) {
            // 协商了 TWCC 时按 RFC 3550 §6.1 将 RR 置于下一复合 RTCP 包最前端发送。
            pending_rr_wire_ = std::move(rr_wire);
          } else {
            queues_->network()->PostTask(
                SafeTask(net_safety_.flag(), [this, w = std::move(rr_wire)]() {
                  if (dtls_srtp_) {
                    dtls_srtp_->SendRtcpPacket(w);
                  }
                }));
          }
        } else {
          downlink_loss = inbound_->latest_downlink_loss;
        }
        inbound_->prev_rr_max_seq = cur_max;
        inbound_->prev_rr_pkts = cur_pkts;
      }

      rtc_network_stats_t s{};
      s.rtt_ms = ice_rtt.ms();
      s.target_bitrate_bps = static_cast<uint32_t>(latest_target_rate_.bps());
      s.pacing_bitrate_bps = static_cast<uint32_t>(latest_pacing_rate_.bps());
      s.uplink_packet_loss = static_cast<float>(latest_uplink_loss_);
      s.downlink_packet_loss = downlink_loss;
      s.packets_sent = stat_pkts_sent_.load(std::memory_order_relaxed);
      s.packets_retransmitted = stat_pkts_rtx_.load(std::memory_order_relaxed);
      s.fec_packets_sent = stat_fec_sent_.load(std::memory_order_relaxed);
      s.frames_decoded = stat_frames_decoded_.load(std::memory_order_relaxed);
      s.keyframe_requests_sent = stat_pli_sent_.load(std::memory_order_relaxed);
      if (observer_ != nullptr) {
        observer_->OnBackendStatsSnapshot(s);
      }
    }

    SendCompoundRtcpFeedback(now);
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
    // 以本批最小模 2^16 序列号为固定锚点投影排序，严格满足传递性与严格弱序（避免 std::sort 越界 UB）。
    uint16_t min_seq = rx_twcc_records_.front().first;
    for (const auto& kv : rx_twcc_records_) {
      if (static_cast<uint16_t>(kv.first - min_seq) >= 0x8000u) {
        min_seq = kv.first;
      }
    }
    std::sort(rx_twcc_records_.begin(), rx_twcc_records_.end(),
              [min_seq](const auto& a, const auto& b) {
                const uint16_t da = static_cast<uint16_t>(a.first - min_seq);
                const uint16_t db = static_cast<uint16_t>(b.first - min_seq);
                return (da != db) ? (da < db) : (a.second < b.second);
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

    // RFC 3550 §6.1：复合 RTCP 报文首包必须为 SR 或 RR（且仅末包可置 P 填充位）。
    std::vector<uint8_t> wire;
    if (!pending_rr_wire_.empty()) {
      wire = std::move(pending_rr_wire_);
      pending_rr_wire_.clear();
    } else {
      RtcpReceiverReport empty_rr;
      empty_rr.sender_ssrc = outbound_.media_ssrc;
      wire = empty_rr.Build();
    }
    const auto fb_wire = fb.Build();
    wire.insert(wire.end(), fb_wire.begin(), fb_wire.end());
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
  const TimeDelta ice_rtt =
      TimeDelta::Micros(cached_ice_rtt_us_.load(std::memory_order_relaxed));
  const TimeDelta pli_cooldown = std::max(TimeDelta::Millis(150), ice_rtt);
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
  if (video_muted_.exchange(false, std::memory_order_acq_rel)) {
    queues_->worker()->PostTask(SafeTask(work_safety_.flag(), [this]() {
      RTC_DCHECK_RUN_ON(&work_checker_);
      SendPliForRemoteStream(clock_->CurrentTime());
    }));
  }
  return RTC_OK;
}

int WebRtcP2pBackend::SwitchSubscribedLayer(const std::string& /*track_id*/,
                                            SpatialLayer /*preferred_layer*/) {
  return RTC_OK;
}

int WebRtcP2pBackend::UnsubscribeRemoteTrack(const std::string& /*track_id*/) {
  video_muted_.store(true, std::memory_order_release);
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
  if (channel_id < 0 || (payload.size() > 0 && payload.data() == nullptr) ||
      payload.size() > SctpDataChannelManager::kMaxSctpMessageSize) {
    return RTC_ERR_INVALID_ARG;
  }
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    if (valid_dc_ids_.find(channel_id) == valid_dc_ids_.end()) {
      return RTC_ERR_INVALID_ARG;
    }
  }
  int rc = RTC_OK;
  queues_->worker()->Invoke([this, channel_id, payload, is_binary, &rc]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    rc = sctp_dc_.SendData(channel_id, payload, is_binary);
  });
  return rc;
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
