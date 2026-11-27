#include "server/embedded_moq_relay.h"

#include <algorithm>
#include <limits>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {

constexpr size_t kMaxRelayClientRequestStreams = 256;
constexpr size_t kMaxRelayInboundUniStreams = 1024;
constexpr size_t kMaxRelayControlOrHeaderBufBytes = 256 * 1024;
constexpr size_t kMaxPreSetupBufferedUniBytes = 2 * 1024 * 1024;
constexpr int64_t kSlowConsumerMaxUnsentBytes = 2 * 1024 * 1024;
constexpr uint64_t kMaxSafeMoqGroupId = uint64_t{1} << 45;
constexpr uint64_t kMaxSafeMoqSubgroupId = uint64_t{1} << 30;
constexpr uint64_t kMaxQuicVarIntValue = (uint64_t{1} << 62) - 1;

bool ConstantTimeTokenEquals(std::string_view candidate,
                             std::string_view expected) {
  unsigned char d1[SHA256_DIGEST_LENGTH];
  unsigned char d2[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(candidate.data()),
         candidate.size(), d1);
  SHA256(reinterpret_cast<const unsigned char*>(expected.data()),
         expected.size(), d2);
  const int digest_eq = (CRYPTO_memcmp(d1, d2, SHA256_DIGEST_LENGTH) == 0);
  const int len_eq = (candidate.size() == expected.size());
  return (digest_eq & len_eq) != 0;
}

bool VerifyEncodedMoqtAuthToken(ArrayView<const uint8_t> raw,
                                std::string_view expected) {
  bool matched = false;
  // 1) 解析 draft-17 图 5 Token 结构：USE_VALUE (0x03) 或 REGISTER (0x01)。
  size_t off = 0;
  uint64_t alias_type = 0;
  if (MoqtVarInt::Read(raw, &off, &alias_type)) {
    uint64_t tok_type = 0;
    if (alias_type == 0x03 && MoqtVarInt::Read(raw, &off, &tok_type)) {
      const std::string_view val(
          reinterpret_cast<const char*>(raw.data() + off), raw.size() - off);
      matched = ConstantTimeTokenEquals(val, expected) || matched;
    } else if (alias_type == 0x01) {
      uint64_t alias_id = 0;
      if (MoqtVarInt::Read(raw, &off, &alias_id) &&
          MoqtVarInt::Read(raw, &off, &tok_type)) {
        const std::string_view val(
            reinterpret_cast<const char*>(raw.data() + off), raw.size() - off);
        matched = ConstantTimeTokenEquals(val, expected) || matched;
      }
    }
  }
  // 2) 兼容直接携带原始 UTF-8 令牌字节的简化客户端。
  const std::string_view raw_str(reinterpret_cast<const char*>(raw.data()),
                                 raw.size());
  matched = ConstantTimeTokenEquals(raw_str, expected) || matched;
  return matched;
}

uint64_t RemapPublisherDataGroupId(uint64_t publisher_tag,
                                   uint64_t orig_group_id) {
  const uint64_t shifted_sid = (publisher_tag & 0xFFFFFFULL) << 16;
  return shifted_sid ^ orig_group_id;
}

}  // namespace

EmbeddedMoqRelayServer::EmbeddedMoqRelayServer(std::string bind_ip)
    : clock_(Clock::GetRealTimeClock()),
      bind_ip_(std::move(bind_ip)),
      net_queue_(std::make_unique<TaskQueueBoost>("moq-relay",
                                                  TaskQueuePriority::kHigh)),
      net_checker_(net_queue_.get()),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {
  // 同时开放原生 QUIC（moqt-17）与 HTTP/3 + WebTransport（h3）双协议协商。
  quic_server_ = std::make_unique<AsioQuicServer>(
      clock_, net_queue_.get(), this, bind_ip_,
      std::vector<std::string>{kMoqtDraft17Alpn, kHttp3Alpn});
}

EmbeddedMoqRelayServer::~EmbeddedMoqRelayServer() { Stop(); }

bool EmbeddedMoqRelayServer::Start(uint16_t udp_port) {
  if (!quic_server_->Start(udp_port)) {
    RTC_LOG(kError) << "EmbeddedMoqRelayServer failed to bind UDP " << bind_ip_
                    << ":" << udp_port;
    return false;
  }
  stopped_.store(false, std::memory_order_release);
  RTC_LOG(kInfo) << "EmbeddedMoqRelayServer (MOQT draft-17 + HTTP/3 + "
                    "WebTransport) started on UDP "
                 << bind_ip_ << ":" << quic_server_->local_port();
  return true;
}

void EmbeddedMoqRelayServer::Stop() {
  bool expected = false;
  if (!stopped_.compare_exchange_strong(expected, true,
                                        std::memory_order_acq_rel)) {
    return;
  }
  if (quic_server_) {
    quic_server_->Stop();
  }
  net_queue_->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    safety_.flag()->SetNotAlive();
    h3_conns_.clear();
    sessions_.clear();
  });
  net_queue_->Shutdown();
  RTC_LOG(kInfo) << "EmbeddedMoqRelayServer stopped";
}

void EmbeddedMoqRelayServer::SetHttp3RequestHandler(
    Http3ServerConnection::Http3RequestHandler handler) {
  net_queue_->Invoke([this, h = std::move(handler)]() mutable {
    RTC_DCHECK_RUN_ON(&net_checker_);
    custom_h3_handler_ = std::move(h);
  });
}

void EmbeddedMoqRelayServer::SetRequiredAuthToken(std::string token) {
  std::lock_guard<std::mutex> lock(auth_mu_);
  required_auth_token_ = std::move(token);
}

std::string EmbeddedMoqRelayServer::GetRequiredAuthTokenCopy() const {
  std::lock_guard<std::mutex> lock(auth_mu_);
  return required_auth_token_;
}

bool EmbeddedMoqRelayServer::VerifyAuthTokenList(
    const std::vector<std::vector<uint8_t>>& raw_tokens,
    std::string_view required_token) const {
  bool any_match = false;
  for (const auto& tok : raw_tokens) {
    if (VerifyEncodedMoqtAuthToken(tok, required_token)) {
      any_match = true;
    }
  }
  return any_match;
}

bool EmbeddedMoqRelayServer::IsNamespaceStillPublishedByAnyPeer(
    const MoqtTrackNamespace& full_ns) const {
  for (const auto& [sid, sess] : sessions_) {
    (void)sid;
    for (const auto& [bsid, ns] : sess->published_namespaces) {
      (void)bsid;
      if (ns == full_ns) {
        return true;
      }
    }
  }
  return false;
}

EmbeddedMoqRelayServer::PeerSession*
EmbeddedMoqRelayServer::FindNewestVideoPublisher(
    const MoqtTrackNamespace& target_peer_ns) {
  for (auto it = sessions_.rbegin(); it != sessions_.rend(); ++it) {
    PeerSession* p = it->second.get();
    if (p->is_video_publisher && p->video_peer_namespace == target_peer_ns &&
        p->quic) {
      return p;
    }
  }
  return nullptr;
}

void EmbeddedMoqRelayServer::SupersedeStalePublisherSessions(
    PeerSession* new_pub,
    const MoqtTrackNamespace& published_ns) {
  if (new_pub == nullptr) {
    return;
  }
  std::vector<std::pair<uint64_t, uint64_t>> stale_downstream_resets;
  for (auto& [other_id, other] : sessions_) {
    if (other_id == new_pub->session_id) {
      continue;
    }
    for (auto pub_it = other->published_namespaces.begin();
         pub_it != other->published_namespaces.end();) {
      const bool same_ns = (pub_it->second == published_ns);
      const bool same_video_peer =
          (new_pub->is_video_publisher && pub_it->second.fields.size() >= 4 &&
           pub_it->second.fields[3] == "video" &&
           other->video_peer_namespace == new_pub->video_peer_namespace);
      if (same_ns || same_video_peer) {
        pub_it = other->published_namespaces.erase(pub_it);
      } else {
        ++pub_it;
      }
    }

    if (new_pub->is_video_publisher && other->is_video_publisher &&
        other->video_peer_namespace == new_pub->video_peer_namespace) {
      other->is_video_publisher = false;
      other->video_peer_namespace = MoqtTrackNamespace{};
      if (other->upstream_low_sub_sid.has_value()) {
        if (other->quic) {
          other->quic->ResetStream(*other->upstream_low_sub_sid, 0);
        }
        other->upstream_sub_rx_bufs.erase(*other->upstream_low_sub_sid);
        other->upstream_low_sub_sid.reset();
      }
      if (other->upstream_high_sub_sid.has_value()) {
        if (other->quic) {
          other->quic->ResetStream(*other->upstream_high_sub_sid, 0);
        }
        other->upstream_sub_rx_bufs.erase(*other->upstream_high_sub_sid);
        other->upstream_high_sub_sid.reset();
      }
      for (auto& [in_sid, fanout] : other->inbound_uni_streams) {
        (void)in_sid;
        if (fanout.kind == UpstreamSubgroupFanout::Kind::kSubgroup &&
            fanout.header.track_alias != kMoqUpstreamDataTrackAlias) {
          for (const auto& target : fanout.downstream_targets) {
            stale_downstream_resets.push_back(target);
          }
          fanout.downstream_targets.clear();
        }
      }
    }
  }

  for (const auto& [sub_sess_id, down_sid] : stale_downstream_resets) {
    const auto sub_it = sessions_.find(sub_sess_id);
    if (sub_it != sessions_.end() && sub_it->second->quic) {
      sub_it->second->quic->ResetStream(down_sid, 0);
    }
  }

  if (new_pub->is_video_publisher) {
    for (auto& [sub_id, sub_peer] : sessions_) {
      (void)sub_id;
      const auto grp_it =
          sub_peer->video_subscriptions.find(new_pub->video_peer_namespace);
      if (grp_it != sub_peer->video_subscriptions.end()) {
        grp_it->second.active_group_id = 0;
        grp_it->second.switch_epoch_min_group[0] = 0;
        grp_it->second.switch_epoch_min_group[1] = 0;
      }
    }
  }
}

void EmbeddedMoqRelayServer::SetSimulatedDropRates(double rx_drop_prob,
                                                   double tx_drop_prob) {
  if (quic_server_) {
    quic_server_->SetSimulatedDropRates(rx_drop_prob, tx_drop_prob);
  }
}

void EmbeddedMoqRelayServer::SetQuicCongestionControl(rtc_quic_cc_algo_e algo) {
  if (quic_server_) {
    auto factory = CreateBuiltinQuicCcFactory(algo);
    if (factory) {
      quic_server_->SetCongestionControllerFactory(std::move(factory));
    }
  }
}

void EmbeddedMoqRelayServer::SetCustomQuicCongestionController(
    std::shared_ptr<IQuicCongestionControllerFactory> factory) {
  if (quic_server_ && factory) {
    quic_server_->SetCongestionControllerFactory(std::move(factory));
  }
}

uint64_t EmbeddedMoqRelayServer::AllocateServerRequestId(PeerSession* peer) {
  const uint64_t id = peer->next_server_request_id;
  peer->next_server_request_id += 2;
  return id;
}

void EmbeddedMoqRelayServer::OnServerSessionConnected(
    std::shared_ptr<QuicServerSessionHandle> session) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const uint64_t sid = session->session_id();
  if (session->negotiated_alpn() == kHttp3Alpn && !IsWtVirtualSessionId(sid)) {
    // 挂载 HTTP/3 + WebTransport 多路复用器；普通 HTTP/3 请求返回实时中继遥测状态，
    // Extended CONNECT(:protocol=webtransport) 将升级为虚拟 MOQT 会话回调至本实例。
    auto h3_handler = [this](const Http3Request& req) -> Http3Response {
      if (custom_h3_handler_) {
        return custom_h3_handler_(req);
      }
      Http3Response resp;
      resp.status = 200;
      resp.headers.push_back({"content-type", "application/json"});
      resp.headers.push_back({"server", "RTCSDK-MoQ-Relay-draft17"});
      JsonObject status_obj;
      status_obj.SetString("protocol", "draft-ietf-moq-transport-17");
      status_obj.SetString("path", req.path);
      status_obj.SetUint32("http3", 1);
      status_obj.SetUint32("webtransport", 1);
      status_obj.SetUint32("active_moq_sessions",
                           static_cast<uint32_t>(sessions_.size()));
      const std::string json = status_obj.Serialize();
      resp.body.assign(json.begin(), json.end());
      return resp;
    };
    auto h3_conn = std::make_shared<Http3ServerConnection>(
        std::move(session), this, std::vector<std::string>{kMoqtDraft17Alpn},
        std::move(h3_handler));
    h3_conns_[sid] = h3_conn;
    h3_conn->Start();
    return;
  }

  auto ctx = std::make_unique<PeerSession>();
  ctx->session_id = sid;
  ctx->publisher_tag = ++next_publisher_tag_;
  ctx->is_webtransport = IsWtVirtualSessionId(sid);
  ctx->authenticated = GetRequiredAuthTokenCopy().empty();
  ctx->quic = std::move(session);

  // draft-17 第 3.3 节：服务端主动打开单向控制流并发送 SETUP (0x2F00)。
  ctx->server_control_stream_id = ctx->quic->OpenUnidirectionalStream(
      /*publisher_priority=*/0, std::numeric_limits<int64_t>::max());
  MoqControlMessage srv_setup;
  srv_setup.type = MoqControlMessageType::kSetup;
  srv_setup.setup_options.push_back(MoqtKeyValuePair::MakeString(
      kMoqtSetupOptionImplementation, "RTCSDK-Relay-moqt-17"));
  ctx->quic->WriteStream(ctx->server_control_stream_id, srv_setup.Encode(),
                         /*fin=*/false);

  sessions_.emplace(sid, std::move(ctx));

  if (!GetRequiredAuthTokenCopy().empty()) {
    net_queue_->PostDelayedTask(
        SafeTask(safety_.flag(), [this, sid]() {
          RTC_DCHECK_RUN_ON(&net_checker_);
          const auto sit = sessions_.find(sid);
          if (sit != sessions_.end() && !sit->second->authenticated) {
            CloseAndEraseSession(sid, kMoqtErrUnauthorized);
          }
        }),
        TimeDelta::Millis(3000));
  }
}

void EmbeddedMoqRelayServer::CloseAndEraseSession(uint64_t session_id,
                                                  uint64_t error_code) {
  std::shared_ptr<QuicServerSessionHandle> quic_handle;
  const auto it = sessions_.find(session_id);
  if (it != sessions_.end()) {
    quic_handle = it->second->quic;
  }
  OnServerSessionDisconnected(session_id, static_cast<int>(error_code));
  if (quic_handle) {
    quic_handle->Close(error_code);
  }
}

void EmbeddedMoqRelayServer::OnServerSessionDisconnected(uint64_t session_id,
                                                         int error_code) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto h3_it = h3_conns_.find(session_id);
  if (h3_it != h3_conns_.end()) {
    auto conn = h3_it->second;
    h3_conns_.erase(h3_it);
    conn->OnQuicDisconnected(error_code);
    return;
  }

  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  std::vector<std::pair<uint64_t, uint64_t>> open_downstream;
  for (const auto& [in_sid, fanout] : it->second->inbound_uni_streams) {
    (void)in_sid;
    for (const auto& target : fanout.downstream_targets) {
      open_downstream.push_back(target);
    }
  }
  std::vector<MoqtTrackNamespace> active_ns;
  for (const auto& [bsid, ns] : it->second->published_namespaces) {
    (void)bsid;
    active_ns.push_back(ns);
  }
  sessions_.erase(it);

  for (const auto& [sub_sess_id, down_sid] : open_downstream) {
    const auto sub_it = sessions_.find(sub_sess_id);
    if (sub_it != sessions_.end() && sub_it->second->quic) {
      sub_it->second->quic->ResetStream(down_sid, 0);
    }
  }
  for (const auto& ns : active_ns) {
    if (!IsNamespaceStillPublishedByAnyPeer(ns)) {
      BroadcastNamespaceChange(session_id, ns, /*is_done=*/true);
    }
  }
}

void EmbeddedMoqRelayServer::OnServerStreamOpened(uint64_t session_id,
                                                  uint64_t stream_id,
                                                  bool unidirectional) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto h3_it = h3_conns_.find(session_id);
  if (h3_it != h3_conns_.end()) {
    h3_it->second->OnQuicStreamOpened(stream_id, unidirectional);
    return;
  }
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  if (unidirectional) {
    if (it->second->inbound_uni_streams.size() >= kMaxRelayInboundUniStreams &&
        it->second->inbound_uni_streams.find(stream_id) ==
            it->second->inbound_uni_streams.end()) {
      if (it->second->quic) {
        it->second->quic->StopSending(stream_id, kMoqtErrProtocolViolation);
      }
      return;
    }
    it->second->inbound_uni_streams.try_emplace(stream_id);
  } else if (it->second->upstream_sub_rx_bufs.find(stream_id) ==
             it->second->upstream_sub_rx_bufs.end()) {
    if (it->second->client_request_streams.size() >=
            kMaxRelayClientRequestStreams &&
        it->second->client_request_streams.find(stream_id) ==
            it->second->client_request_streams.end()) {
      if (it->second->quic) {
        it->second->quic->ResetStream(stream_id, kMoqtErrProtocolViolation);
      }
      return;
    }
    it->second->client_request_streams.try_emplace(stream_id);
  }
}

void EmbeddedMoqRelayServer::OnServerStreamData(uint64_t session_id,
                                                uint64_t stream_id,
                                                ArrayView<const uint8_t> data,
                                                bool fin) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto h3_it = h3_conns_.find(session_id);
  if (h3_it != h3_conns_.end()) {
    h3_it->second->OnQuicStreamData(stream_id, data, fin);
    return;
  }
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  PeerSession* peer = it->second.get();
  const bool is_uni = (stream_id & 0x02u) != 0;
  if (is_uni) {
    HandleUnidirectionalBytes(peer, stream_id, data, fin);
    return;
  }
  if (peer->upstream_sub_rx_bufs.find(stream_id) !=
      peer->upstream_sub_rx_bufs.end()) {
    HandleUpstreamSubResponseBytes(peer, stream_id, data, fin);
    return;
  }
  HandleClientRequestBytes(peer, stream_id, data, fin);
}

void EmbeddedMoqRelayServer::OnServerStreamReset(uint64_t session_id,
                                                 uint64_t stream_id,
                                                 uint64_t app_error_code) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto h3_it = h3_conns_.find(session_id);
  if (h3_it != h3_conns_.end()) {
    h3_it->second->OnQuicStreamReset(stream_id, app_error_code);
    return;
  }
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  PeerSession* peer = it->second.get();
  const bool is_uni = (stream_id & 0x02u) != 0;
  if (is_uni) {
    if (peer->client_control_stream_id.has_value() &&
        *peer->client_control_stream_id == stream_id) {
      CloseAndEraseSession(session_id, kMoqtErrProtocolViolation);
      return;
    }
    const auto fan_it = peer->inbound_uni_streams.find(stream_id);
    if (fan_it == peer->inbound_uni_streams.end()) {
      return;
    }
    for (const auto& [sub_sess_id, down_sid] :
         fan_it->second.downstream_targets) {
      const auto sub_it = sessions_.find(sub_sess_id);
      if (sub_it != sessions_.end() && sub_it->second->quic) {
        sub_it->second->quic->ResetStream(down_sid, app_error_code);
      }
    }
    peer->inbound_uni_streams.erase(fan_it);
    return;
  }

  RemoveClientRequestStream(peer, stream_id);
}

void EmbeddedMoqRelayServer::OnServerStreamStopSending(
    uint64_t session_id,
    uint64_t stream_id,
    uint64_t app_error_code) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto h3_it = h3_conns_.find(session_id);
  if (h3_it != h3_conns_.end()) {
    h3_it->second->OnQuicStreamStopSending(stream_id, app_error_code);
    return;
  }
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  if (stream_id == it->second->server_control_stream_id) {
    CloseAndEraseSession(session_id, kMoqtErrProtocolViolation);
    return;
  }
  RemoveClientRequestStream(it->second.get(), stream_id);
}

void EmbeddedMoqRelayServer::OnServerDatagramReceived(
    uint64_t session_id,
    ArrayView<const uint8_t> data) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto h3_it = h3_conns_.find(session_id);
  if (h3_it != h3_conns_.end()) {
    h3_it->second->OnQuicDatagramReceived(data);
    return;
  }
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  PeerSession* pub_peer = it->second.get();
  bool violation = false;
  uint64_t decode_err = kMoqtErrProtocolViolation;
  auto dg = MoqtObjectDatagram::Decode(data, &violation, &decode_err);
  if (violation) {
    CloseAndEraseSession(session_id, decode_err != kMoqtErrNoError
                                         ? decode_err
                                         : kMoqtErrProtocolViolation);
    return;
  }
  if (!pub_peer->peer_setup_received) {
    // 早期 QUIC 包乱序到达的数据报在 SETUP 完成前安全丢弃，不误伤正在握手的会话。
    return;
  }
  if (!pub_peer->authenticated) {
    CloseAndEraseSession(session_id, kMoqtErrUnauthorized);
    return;
  }
  if (!dg.has_value()) {
    return;
  }
  if (dg->track_alias == kMoqUpstreamDataTrackAlias) {
    const uint64_t remapped_gid =
        RemapPublisherDataGroupId(pub_peer->publisher_tag, dg->group_id);
    for (auto& [other_id, sub_peer] : sessions_) {
      if (other_id == pub_peer->session_id || !sub_peer->quic ||
          !sub_peer->authenticated || sub_peer->room_id != pub_peer->room_id ||
          !sub_peer->has_data_subscription) {
        continue;
      }
      MoqtObjectDatagram down_dg = *dg;
      down_dg.track_alias = sub_peer->data_downstream_alias;
      down_dg.group_id = remapped_gid;
      sub_peer->quic->SendDatagram(down_dg.Encode());
    }
  }
}

void EmbeddedMoqRelayServer::BroadcastNamespaceChange(
    uint64_t origin_session_id,
    const MoqtTrackNamespace& full_ns,
    bool is_done) {
  for (auto& [other_id, other] : sessions_) {
    if (other_id == origin_session_id || !other->quic) {
      continue;
    }
    for (const auto& [sub_ns_sid, prefix] : other->subscribed_ns_prefixes) {
      if (!full_ns.StartsWith(prefix)) {
        continue;
      }
      MoqControlMessage msg;
      msg.type = is_done ? MoqControlMessageType::kNamespaceDone
                         : MoqControlMessageType::kNamespace;
      msg.track_namespace = full_ns.SuffixAfter(prefix);
      other->quic->WriteStream(sub_ns_sid, msg.Encode(), /*fin=*/false);
    }
  }
}

void EmbeddedMoqRelayServer::OpenUpstreamSubscriptionsToPublisher(
    PeerSession* pub_peer) {
  if (pub_peer == nullptr || !pub_peer->quic ||
      pub_peer->upstream_high_sub_sid.has_value()) {
    return;
  }
  auto open_up_sub = [&](const char* track_name, uint8_t prio) {
    const uint64_t sid = pub_peer->quic->OpenBidirectionalStream();
    MoqControlMessage sub;
    sub.type = MoqControlMessageType::kSubscribe;
    sub.request_id = AllocateServerRequestId(pub_peer);
    sub.track_namespace = pub_peer->video_peer_namespace;
    sub.track_name = track_name;
    sub.parameters.forward = 1;
    sub.parameters.subscriber_priority = prio;
    sub.parameters.subscription_filter =
        MoqtSubscriptionFilter{MoqFilterType::kNextGroupStart, {}, 0};
    pub_peer->upstream_sub_rx_bufs[sid] = {};
    pub_peer->quic->WriteStream(sid, sub.Encode(), /*fin=*/false);
    return sid;
  };
  pub_peer->upstream_low_sub_sid = open_up_sub("video/low", 16);
  pub_peer->upstream_high_sub_sid = open_up_sub("video/high", 32);
}

void EmbeddedMoqRelayServer::ForwardNewGroupRequest(
    const MoqtTrackNamespace& target_peer_ns,
    SpatialLayer layer) {
  PeerSession* peer = FindNewestVideoPublisher(target_peer_ns);
  if (peer == nullptr) {
    return;
  }
  const Timestamp now = clock_->CurrentTime();
  if (peer->last_kf_req_time.IsFinite() &&
      (now - peer->last_kf_req_time) < TimeDelta::Millis(80)) {
    return;
  }
  peer->last_kf_req_time = now;
  const auto opt_sid = (layer == SpatialLayer::kLow)
                           ? peer->upstream_low_sub_sid
                           : peer->upstream_high_sub_sid;
  if (!opt_sid.has_value()) {
    return;
  }
  const size_t lidx = (layer == SpatialLayer::kHigh) ? 1 : 0;
  const uint64_t safe_largest =
      std::min(peer->largest_group[lidx], kMaxQuicVarIntValue - 1);
  MoqControlMessage upd;
  upd.type = MoqControlMessageType::kRequestUpdate;
  upd.request_id = AllocateServerRequestId(peer);
  upd.parameters.new_group_request = safe_largest + 1;
  peer->quic->WriteStream(*opt_sid, upd.Encode(), /*fin=*/false);
}

void EmbeddedMoqRelayServer::HandleUpstreamSubResponseBytes(
    PeerSession* peer,
    uint64_t stream_id,
    ArrayView<const uint8_t> data,
    bool fin) {
  auto& buf = peer->upstream_sub_rx_bufs[stream_id];
  if (buf.size() + data.size() > kMaxRelayControlOrHeaderBufBytes) {
    buf.clear();
    CloseAndEraseSession(peer->session_id, kMoqtErrProtocolViolation);
    return;
  }
  buf.insert(buf.end(), data.begin(), data.end());
  while (!buf.empty()) {
    size_t consumed = 0;
    bool violation = false;
    uint64_t decode_err = kMoqtErrProtocolViolation;
    auto msg = MoqControlMessage::Decode(buf, &consumed, &violation, &decode_err);
    if (violation) {
      CloseAndEraseSession(peer->session_id,
                           decode_err != kMoqtErrNoError
                               ? decode_err
                               : kMoqtErrProtocolViolation);
      return;
    }
    if (!msg.has_value()) {
      break;
    }
    buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(consumed));
  }
  if (fin) {
    peer->upstream_sub_rx_bufs.erase(stream_id);
  }
}

void EmbeddedMoqRelayServer::HandleControlBytes(PeerSession* peer,
                                                std::vector<uint8_t>* buf) {
  while (!buf->empty()) {
    size_t consumed = 0;
    bool violation = false;
    uint64_t decode_err = kMoqtErrProtocolViolation;
    auto msg = MoqControlMessage::Decode(*buf, &consumed, &violation, &decode_err);
    if (violation) {
      buf->clear();
      CloseAndEraseSession(peer->session_id,
                           decode_err != kMoqtErrNoError
                               ? decode_err
                               : kMoqtErrProtocolViolation);
      return;
    }
    if (!msg.has_value()) {
      break;
    }
    buf->erase(buf->begin(), buf->begin() + static_cast<ptrdiff_t>(consumed));

    if (msg->type == MoqControlMessageType::kSetup) {
      if (peer->peer_setup_received) {
        CloseAndEraseSession(peer->session_id, kMoqtErrProtocolViolation);
        return;
      }
      if (peer->is_webtransport) {
        // draft-17 第 9.4.1.1 / 9.4.1.2 节：WebTransport 模式下收到 AUTHORITY 或 PATH 必须关闭会话。
        for (const auto& opt : msg->setup_options) {
          if (opt.type == kMoqtSetupOptionAuthority) {
            CloseAndEraseSession(peer->session_id, kMoqtErrInvalidAuthority);
            return;
          }
          if (opt.type == kMoqtSetupOptionPath) {
            CloseAndEraseSession(peer->session_id, kMoqtErrInvalidPath);
            return;
          }
        }
      }

      const std::string required_token = GetRequiredAuthTokenCopy();
      if (!required_token.empty()) {
        std::vector<std::vector<uint8_t>> setup_tokens;
        for (const auto& opt : msg->setup_options) {
          if (opt.type == kMoqtSetupOptionAuthToken) {
            setup_tokens.push_back(opt.bytes_value);
          }
        }
        if (!setup_tokens.empty()) {
          if (!VerifyAuthTokenList(setup_tokens, required_token)) {
            CloseAndEraseSession(peer->session_id, kMoqtErrUnauthorized);
            return;
          }
          peer->authenticated = true;
        }
      } else {
        peer->authenticated = true;
      }

      peer->peer_setup_received = true;
      const uint64_t sid_self = peer->session_id;
      std::vector<std::pair<uint64_t, bool>> pending_req_sids;
      pending_req_sids.reserve(peer->client_request_streams.size());
      for (const auto& [rsid, rst] : peer->client_request_streams) {
        if (!rst.rx_buf.empty() || rst.fin_received) {
          pending_req_sids.emplace_back(rsid, rst.fin_received);
        }
      }
      for (const auto& [rsid, req_fin] : pending_req_sids) {
        const auto pit = sessions_.find(sid_self);
        if (pit == sessions_.end()) {
          return;
        }
        HandleClientRequestBytes(pit->second.get(), rsid,
                                 ArrayView<const uint8_t>(), req_fin);
      }

      const auto pit_after_reqs = sessions_.find(sid_self);
      if (pit_after_reqs == sessions_.end()) {
        return;
      }
      std::vector<std::pair<uint64_t, bool>> pending_uni_sids;
      for (const auto& [usid, fan] : pit_after_reqs->second->inbound_uni_streams) {
        if (fan.kind == UpstreamSubgroupFanout::Kind::kUnknown &&
            !fan.header_buf.empty()) {
          pending_uni_sids.emplace_back(usid, fan.fin_received);
        }
      }
      for (const auto& [usid, uni_fin] : pending_uni_sids) {
        const auto pit = sessions_.find(sid_self);
        if (pit == sessions_.end()) {
          return;
        }
        HandleUnidirectionalBytes(pit->second.get(), usid,
                                  ArrayView<const uint8_t>(), uni_fin);
      }
    } else if (msg->type == MoqControlMessageType::kGoaway) {
      if (!peer->peer_setup_received || !msg->new_session_uri.empty()) {
        // draft-17 第 9.5 节：未完成 SETUP 或客户端发送非空 New Session URI 属于协议违规。
        CloseAndEraseSession(peer->session_id, kMoqtErrProtocolViolation);
        return;
      }
    } else {
      CloseAndEraseSession(peer->session_id, kMoqtErrProtocolViolation);
      return;
    }
  }
}

void EmbeddedMoqRelayServer::RemoveClientRequestStream(PeerSession* peer,
                                                       uint64_t stream_id) {
  if (peer == nullptr) {
    return;
  }
  peer->upstream_sub_rx_bufs.erase(stream_id);
  peer->subscribed_ns_prefixes.erase(stream_id);

  const auto pub_it = peer->published_namespaces.find(stream_id);
  if (pub_it != peer->published_namespaces.end()) {
    const MoqtTrackNamespace ns = pub_it->second;
    peer->published_namespaces.erase(pub_it);
    if (ns.fields.size() >= 4 && ns.fields[3] == "video") {
      peer->is_video_publisher = false;
      if (peer->upstream_low_sub_sid.has_value()) {
        if (peer->quic) {
          peer->quic->ResetStream(*peer->upstream_low_sub_sid, 0);
        }
        peer->upstream_sub_rx_bufs.erase(*peer->upstream_low_sub_sid);
        peer->upstream_low_sub_sid.reset();
      }
      if (peer->upstream_high_sub_sid.has_value()) {
        if (peer->quic) {
          peer->quic->ResetStream(*peer->upstream_high_sub_sid, 0);
        }
        peer->upstream_sub_rx_bufs.erase(*peer->upstream_high_sub_sid);
        peer->upstream_high_sub_sid.reset();
      }
    }
    if (!IsNamespaceStillPublishedByAnyPeer(ns)) {
      BroadcastNamespaceChange(peer->session_id, ns, /*is_done=*/true);
    }
  }

  const auto req_it = peer->client_request_streams.find(stream_id);
  if (req_it != peer->client_request_streams.end()) {
    peer->active_client_req_id_to_stream.erase(req_it->second.initial_request_id);
    if (req_it->second.published_track_alias.has_value()) {
      peer->client_published_aliases.erase(
          *req_it->second.published_track_alias);
    }
    if (req_it->second.role == ClientRequestStreamState::Role::kSubscribeVideo) {
      const auto grp_it = peer->video_subscriptions.find(req_it->second.ns);
      if (grp_it != peer->video_subscriptions.end()) {
        if (grp_it->second.low_sub.has_value() &&
            grp_it->second.low_sub->bidi_stream_id == stream_id) {
          grp_it->second.low_sub.reset();
        }
        if (grp_it->second.high_sub.has_value() &&
            grp_it->second.high_sub->bidi_stream_id == stream_id) {
          grp_it->second.high_sub.reset();
        }
        if (!grp_it->second.low_sub.has_value() &&
            !grp_it->second.high_sub.has_value()) {
          peer->video_subscriptions.erase(grp_it);
        }
      }
    } else if (req_it->second.role ==
               ClientRequestStreamState::Role::kSubscribeData) {
      peer->has_data_subscription = false;
    }
    peer->client_request_streams.erase(req_it);
  }
}

void EmbeddedMoqRelayServer::HandleClientRequestBytes(
    PeerSession* peer,
    uint64_t stream_id,
    ArrayView<const uint8_t> data,
    bool fin) {
  if (peer->client_request_streams.find(stream_id) ==
          peer->client_request_streams.end() &&
      peer->client_request_streams.size() >= kMaxRelayClientRequestStreams) {
    if (peer->quic) {
      peer->quic->ResetStream(stream_id, kMoqtErrProtocolViolation);
    }
    return;
  }
  auto& rst = peer->client_request_streams[stream_id];
  if (rst.rx_buf.size() + data.size() > kMaxRelayControlOrHeaderBufBytes) {
    rst.rx_buf.clear();
    CloseAndEraseSession(peer->session_id, kMoqtErrProtocolViolation);
    return;
  }
  rst.rx_buf.insert(rst.rx_buf.end(), data.begin(), data.end());
  rst.fin_received = rst.fin_received || fin;
  if (!peer->peer_setup_received) {
    // QUIC 不同流之间无序到达：在控制流 SETUP 到达前仅做有界暂存，且不能因客户端半关闭 FIN 提前删除请求！
    return;
  }

  const std::string required_token = GetRequiredAuthTokenCopy();

  while (!rst.rx_buf.empty()) {
    size_t consumed = 0;
    bool violation = false;
    uint64_t decode_err = kMoqtErrProtocolViolation;
    auto msg =
        MoqControlMessage::Decode(rst.rx_buf, &consumed, &violation, &decode_err);
    if (violation) {
      CloseAndEraseSession(peer->session_id,
                           decode_err != kMoqtErrNoError
                               ? decode_err
                               : kMoqtErrProtocolViolation);
      return;
    }
    if (!msg.has_value()) {
      break;
    }
    rst.rx_buf.erase(rst.rx_buf.begin(),
                     rst.rx_buf.begin() + static_cast<ptrdiff_t>(consumed));

    if (!required_token.empty() && !peer->authenticated) {
      if (!msg->parameters.authorization_tokens.empty() &&
          VerifyAuthTokenList(msg->parameters.authorization_tokens,
                              required_token)) {
        peer->authenticated = true;
      } else {
        CloseAndEraseSession(peer->session_id, kMoqtErrUnauthorized);
        return;
      }
    }

    // draft-17 第 9.1 节：客户端发起的请求类消息必须携带偶数 Request ID 且会话内不可重复。
    const bool carries_req_id =
        (msg->type == MoqControlMessageType::kSubscribe ||
         msg->type == MoqControlMessageType::kPublish ||
         msg->type == MoqControlMessageType::kPublishNamespace ||
         msg->type == MoqControlMessageType::kSubscribeNamespace ||
         msg->type == MoqControlMessageType::kRequestUpdate ||
         msg->type == MoqControlMessageType::kTrackStatus ||
         msg->type == MoqControlMessageType::kFetch);
    if (!carries_req_id) {
      CloseAndEraseSession(peer->session_id, kMoqtErrProtocolViolation);
      return;
    }
    if ((msg->request_id & 1u) != 0) {
      CloseAndEraseSession(peer->session_id, kMoqtErrInvalidRequestId);
      return;
    }

    ClientRequestStreamState* target_rst = &rst;
    if (rst.role == ClientRequestStreamState::Role::kUnparsed) {
      if (msg->type == MoqControlMessageType::kRequestUpdate) {
        // 支持在新双向流上通过引用活跃 request_id 发送 REQUEST_UPDATE。
        uint64_t target_req_id = 0;
        if (msg->required_request_id_delta > 0) {
          if (!peer->seen_client_request_ids.insert(msg->request_id).second) {
            CloseAndEraseSession(peer->session_id, kMoqtErrInvalidRequestId);
            return;
          }
          target_req_id =
              msg->request_id - 2 * msg->required_request_id_delta;
          if (peer->seen_client_request_ids.count(target_req_id) == 0) {
            CloseAndEraseSession(peer->session_id,
                                 kMoqtErrInvalidRequiredRequestId);
            return;
          }
        } else if (peer->active_client_req_id_to_stream.count(msg->request_id) >
                   0) {
          target_req_id = msg->request_id;
        } else {
          CloseAndEraseSession(
              peer->session_id,
              peer->seen_client_request_ids.count(msg->request_id) > 0
                  ? kMoqtErrInvalidRequestId
                  : kMoqtErrProtocolViolation);
          return;
        }

        const auto active_it =
            peer->active_client_req_id_to_stream.find(target_req_id);
        if (active_it == peer->active_client_req_id_to_stream.end()) {
          MoqControlMessage err;
          err.type = MoqControlMessageType::kRequestError;
          err.error_or_status_code = kMoqtReqErrDoesNotExist;
          err.reason_phrase = "request closed";
          peer->quic->WriteStream(stream_id, err.Encode(), /*fin=*/true);
          peer->client_request_streams.erase(stream_id);
          return;
        }
        const auto orig_it =
            peer->client_request_streams.find(active_it->second);
        if (orig_it == peer->client_request_streams.end()) {
          MoqControlMessage err;
          err.type = MoqControlMessageType::kRequestError;
          err.error_or_status_code = kMoqtReqErrDoesNotExist;
          err.reason_phrase = "request closed";
          peer->quic->WriteStream(stream_id, err.Encode(), /*fin=*/true);
          peer->client_request_streams.erase(stream_id);
          return;
        }
        rst.role = ClientRequestStreamState::Role::kDetachedRequestUpdate;
        rst.initial_request_id = msg->request_id;
        target_rst = &orig_it->second;
      } else {
        if (!peer->seen_client_request_ids.insert(msg->request_id).second) {
          CloseAndEraseSession(peer->session_id, kMoqtErrInvalidRequestId);
          return;
        }
        if (msg->required_request_id_delta > 0) {
          const uint64_t dep_id =
              msg->request_id - 2 * msg->required_request_id_delta;
          if (peer->seen_client_request_ids.count(dep_id) == 0) {
            CloseAndEraseSession(peer->session_id,
                                 kMoqtErrInvalidRequiredRequestId);
            return;
          }
        }
        rst.initial_request_id = msg->request_id;
        peer->active_client_req_id_to_stream[msg->request_id] = stream_id;
      }
    } else if (msg->type != MoqControlMessageType::kRequestUpdate) {
      CloseAndEraseSession(peer->session_id, kMoqtErrProtocolViolation);
      return;
    } else {
      if (!peer->seen_client_request_ids.insert(msg->request_id).second) {
        CloseAndEraseSession(peer->session_id, kMoqtErrInvalidRequestId);
        return;
      }
      if (msg->required_request_id_delta > 0) {
        const uint64_t dep_id =
            msg->request_id - 2 * msg->required_request_id_delta;
        if (peer->seen_client_request_ids.count(dep_id) == 0) {
          CloseAndEraseSession(peer->session_id,
                               kMoqtErrInvalidRequiredRequestId);
          return;
        }
      }
      if (rst.role == ClientRequestStreamState::Role::kDetachedRequestUpdate) {
        CloseAndEraseSession(peer->session_id, kMoqtErrProtocolViolation);
        return;
      }
    }

    switch (msg->type) {
      case MoqControlMessageType::kSubscribeNamespace: {
        rst.role = ClientRequestStreamState::Role::kSubscribeNamespace;
        rst.ns = msg->track_namespace;
        if (peer->room_id.empty() && msg->track_namespace.fields.size() >= 2 &&
            msg->track_namespace.fields[0] == "rtc") {
          peer->room_id = msg->track_namespace.fields[1];
        }
        peer->subscribed_ns_prefixes[stream_id] = msg->track_namespace;

        MoqControlMessage rok;
        rok.type = MoqControlMessageType::kRequestOk;
        std::vector<uint8_t> out = rok.Encode();

        // 枚举当前已发布的全部匹配命名空间（去重），紧随 REQUEST_OK 发送 NAMESPACE (0x08)。
        std::set<MoqtTrackNamespace> emitted_ns;
        for (const auto& [other_id, other] : sessions_) {
          if (other_id == peer->session_id) {
            continue;
          }
          for (const auto& [pub_sid, full_ns] : other->published_namespaces) {
            (void)pub_sid;
            if (full_ns.StartsWith(msg->track_namespace) &&
                emitted_ns.insert(full_ns).second) {
              MoqControlMessage nm;
              nm.type = MoqControlMessageType::kNamespace;
              nm.track_namespace = full_ns.SuffixAfter(msg->track_namespace);
              const auto enc = nm.Encode();
              out.insert(out.end(), enc.begin(), enc.end());
            }
          }
        }
        peer->quic->WriteStream(stream_id, out, /*fin=*/false);
        break;
      }

      case MoqControlMessageType::kPublishNamespace: {
        rst.role = ClientRequestStreamState::Role::kPublishNamespace;
        rst.ns = msg->track_namespace;
        if (msg->track_namespace.fields.size() >= 3 &&
            msg->track_namespace.fields[0] == "rtc") {
          peer->room_id = msg->track_namespace.fields[1];
          peer->peer_id = msg->track_namespace.fields[2];
        }
        peer->published_namespaces[stream_id] = msg->track_namespace;

        if (msg->track_namespace.fields.size() >= 4 &&
            msg->track_namespace.fields[3] == "video") {
          peer->video_peer_namespace =
              MoqtTrackNamespace::MakePeerNamespace(peer->room_id,
                                                    peer->peer_id);
          peer->is_video_publisher = true;
        }

        // 若同一发布者快速重连发布了已存在的命名空间，立即摘除旧残留会话所有权，
        // 确保关键帧请求路由至最新会话且旧会话超时断开时绝不误广播 NAMESPACE_DONE。
        SupersedeStalePublisherSessions(peer, msg->track_namespace);

        MoqControlMessage rok;
        rok.type = MoqControlMessageType::kRequestOk;
        peer->quic->WriteStream(stream_id, rok.Encode(), /*fin=*/false);

        if (peer->is_video_publisher) {
          OpenUpstreamSubscriptionsToPublisher(peer);
          for (const auto& [sub_id, sub_peer] : sessions_) {
            if (sub_id == peer->session_id) {
              continue;
            }
            const auto vsub_it =
                sub_peer->video_subscriptions.find(peer->video_peer_namespace);
            if (vsub_it != sub_peer->video_subscriptions.end()) {
              ForwardNewGroupRequest(peer->video_peer_namespace,
                                     vsub_it->second.target_layer);
              break;
            }
          }
        }

        RTC_LOG(kInfo) << "MOQT Relay peer=" << peer->peer_id
                       << " PUBLISH_NAMESPACE "
                       << msg->track_namespace.ToSlashString();
        BroadcastNamespaceChange(peer->session_id, msg->track_namespace,
                                 /*is_done=*/false);
        break;
      }

      case MoqControlMessageType::kPublish: {
        if (!peer->client_published_aliases.insert(msg->track_alias).second) {
          CloseAndEraseSession(peer->session_id, kMoqtErrDuplicateTrackAlias);
          return;
        }
        rst.role = ClientRequestStreamState::Role::kPublishTrack;
        rst.ns = msg->track_namespace;
        rst.track_name = msg->track_name;
        rst.published_track_alias = msg->track_alias;
        MoqControlMessage pok;
        pok.type = MoqControlMessageType::kPublishOk;
        peer->quic->WriteStream(stream_id, pok.Encode(), /*fin=*/false);
        break;
      }

      case MoqControlMessageType::kSubscribe: {
        rst.ns = msg->track_namespace;
        rst.track_name = msg->track_name;
        if (peer->room_id.empty() && msg->track_namespace.fields.size() >= 2 &&
            msg->track_namespace.fields[0] == "rtc") {
          peer->room_id = msg->track_namespace.fields[1];
        }

        if (msg->track_name.rfind("data", 0) == 0) {
          rst.role = ClientRequestStreamState::Role::kSubscribeData;
          peer->has_data_subscription = true;
          peer->data_downstream_alias = kMoqDownstreamDataTrackAlias;

          MoqControlMessage ok;
          ok.type = MoqControlMessageType::kSubscribeOk;
          ok.track_alias = peer->data_downstream_alias;
          ok.track_properties.push_back(
              MoqtKeyValuePair::MakeVarInt(kMoqtPropDynamicGroups, 1));
          peer->quic->WriteStream(stream_id, ok.Encode(), /*fin=*/false);
          break;
        }

        rst.role = ClientRequestStreamState::Role::kSubscribeVideo;
        const SpatialLayer layer =
            (msg->track_name == "video/low") ? SpatialLayer::kLow
                                             : SpatialLayer::kHigh;
        rst.video_layer = layer;
        const uint8_t fwd = msg->parameters.forward.value_or(1);
        const uint64_t alias = ++peer->next_track_alias;

        auto& grp = peer->video_subscriptions[msg->track_namespace];
        grp.target_peer_ns = msg->track_namespace;
        LayerSubStreamInfo info{stream_id, alias, layer, fwd};
        if (layer == SpatialLayer::kLow) {
          grp.low_sub = info;
        } else {
          grp.high_sub = info;
        }
        if (fwd == 1) {
          grp.target_layer = layer;
          if (!grp.low_sub.has_value() || !grp.high_sub.has_value()) {
            grp.active_layer = layer;
          } else if (grp.active_layer != layer) {
            grp.waiting_for_group_switch = true;
            const size_t t_idx = (layer == SpatialLayer::kHigh) ? 1 : 0;
            if (PeerSession* pub_p =
                    FindNewestVideoPublisher(msg->track_namespace)) {
              grp.switch_epoch_min_group[t_idx] = pub_p->largest_group[t_idx] + 1;
            }
          }
        }

        MoqControlMessage ok;
        ok.type = MoqControlMessageType::kSubscribeOk;
        ok.track_alias = alias;
        ok.track_properties.push_back(
            MoqtKeyValuePair::MakeVarInt(kMoqtPropDynamicGroups, 1));
        peer->quic->WriteStream(stream_id, ok.Encode(), /*fin=*/false);

        if (fwd == 1 || msg->parameters.new_group_request.has_value()) {
          ForwardNewGroupRequest(msg->track_namespace, layer);
        }
        break;
      }

      case MoqControlMessageType::kRequestUpdate: {
        MoqControlMessage rok;
        rok.type = MoqControlMessageType::kRequestOk;
        const bool close_detached_stream =
            (rst.role == ClientRequestStreamState::Role::kDetachedRequestUpdate &&
             rst.fin_received);
        peer->quic->WriteStream(stream_id, rok.Encode(),
                                /*fin=*/close_detached_stream);

        if (target_rst->role == ClientRequestStreamState::Role::kSubscribeVideo) {
          const auto grp_it = peer->video_subscriptions.find(target_rst->ns);
          if (grp_it != peer->video_subscriptions.end()) {
            auto& grp = grp_it->second;
            const SpatialLayer upd_layer = target_rst->video_layer;
            auto* sub_ptr = (upd_layer == SpatialLayer::kLow)
                                ? (grp.low_sub ? &*grp.low_sub : nullptr)
                                : (grp.high_sub ? &*grp.high_sub : nullptr);
            if (sub_ptr != nullptr && msg->parameters.forward.has_value()) {
              sub_ptr->forward = *msg->parameters.forward;
              if (sub_ptr->forward == 1 && grp.target_layer != upd_layer) {
                grp.target_layer = upd_layer;
                grp.waiting_for_group_switch = true;
                const size_t t_idx = (upd_layer == SpatialLayer::kHigh) ? 1 : 0;
                if (PeerSession* pub_p =
                        FindNewestVideoPublisher(target_rst->ns)) {
                  grp.switch_epoch_min_group[t_idx] =
                      pub_p->largest_group[t_idx] + 1;
                }
                ForwardNewGroupRequest(target_rst->ns, upd_layer);
              }
            }
            if (msg->parameters.new_group_request.has_value() &&
                (sub_ptr == nullptr || sub_ptr->forward == 1)) {
              ForwardNewGroupRequest(target_rst->ns, upd_layer);
            }
          }
        }
        if (close_detached_stream) {
          peer->client_request_streams.erase(stream_id);
          return;
        }
        break;
      }

      case MoqControlMessageType::kTrackStatus: {
        peer->active_client_req_id_to_stream.erase(msg->request_id);
        MoqControlMessage rok;
        rok.type = MoqControlMessageType::kRequestOk;
        peer->quic->WriteStream(stream_id, rok.Encode(), /*fin=*/true);
        peer->client_request_streams.erase(stream_id);
        return;
      }

      case MoqControlMessageType::kFetch:
      default: {
        peer->active_client_req_id_to_stream.erase(msg->request_id);
        MoqControlMessage err;
        err.type = MoqControlMessageType::kRequestError;
        err.error_or_status_code = kMoqtReqErrNotSupported;
        err.reason_phrase = "unsupported request";
        peer->quic->WriteStream(stream_id, err.Encode(), /*fin=*/true);
        peer->client_request_streams.erase(stream_id);
        return;
      }
    }
  }
  // 严禁在客户端双向请求流发送半关闭 FIN 时调用 RemoveClientRequestStream！
  // 订阅与发布命名空间仅在 RESET_STREAM / STOP_SENDING / 会话断开时终止。
}

void EmbeddedMoqRelayServer::HandleUnidirectionalBytes(
    PeerSession* publisher,
    uint64_t stream_id,
    ArrayView<const uint8_t> data,
    bool fin) {
  if (publisher->inbound_uni_streams.find(stream_id) ==
          publisher->inbound_uni_streams.end() &&
      publisher->inbound_uni_streams.size() >= kMaxRelayInboundUniStreams) {
    if (publisher->quic) {
      publisher->quic->StopSending(stream_id, kMoqtErrProtocolViolation);
    }
    return;
  }
  auto& fanout = publisher->inbound_uni_streams[stream_id];
  fanout.fin_received = fanout.fin_received || fin;
  if (fanout.kind == UpstreamSubgroupFanout::Kind::kIgnoredFetch) {
    if (fanout.fin_received) {
      publisher->inbound_uni_streams.erase(stream_id);
    }
    return;
  }
  ArrayView<const uint8_t> payload_to_forward = data;

  if (fanout.kind == UpstreamSubgroupFanout::Kind::kUnknown) {
    if (fanout.header_buf.size() + data.size() >
        kMaxRelayControlOrHeaderBufBytes) {
      fanout.header_buf.clear();
      CloseAndEraseSession(publisher->session_id, kMoqtErrProtocolViolation);
      return;
    }
    fanout.header_buf.insert(fanout.header_buf.end(), data.begin(), data.end());
    size_t peek_off = 0;
    uint64_t stype = 0;
    bool bad_vi = false;
    if (!MoqtVarInt::Read(fanout.header_buf, &peek_off, &stype, &bad_vi)) {
      if (bad_vi) {
        CloseAndEraseSession(publisher->session_id, kMoqtErrProtocolViolation);
        return;
      }
      if (fanout.fin_received) {
        publisher->inbound_uni_streams.erase(stream_id);
      }
      return;
    }

    if (stype == static_cast<uint64_t>(MoqControlMessageType::kSetup)) {
      if (publisher->client_control_stream_id.has_value() &&
          *publisher->client_control_stream_id != stream_id) {
        CloseAndEraseSession(publisher->session_id, kMoqtErrProtocolViolation);
        return;
      }
      publisher->client_control_stream_id = stream_id;
      fanout.kind = UpstreamSubgroupFanout::Kind::kControl;
      if (fanout.fin_received) {
        CloseAndEraseSession(publisher->session_id, kMoqtErrProtocolViolation);
        return;
      }
      HandleControlBytes(publisher, &fanout.header_buf);
      return;
    }

    if (stype == kMoqtStreamTypeFetchHeader) {
      fanout.kind = UpstreamSubgroupFanout::Kind::kIgnoredFetch;
      fanout.header_buf.clear();
      if (publisher->quic) {
        publisher->quic->StopSending(stream_id, kMoqtReqErrNotSupported);
      }
      if (fanout.fin_received) {
        publisher->inbound_uni_streams.erase(stream_id);
      }
      return;
    }

    const bool valid_sg_type =
        ((stype >= 0x10u && stype <= 0x1Fu) ||
         (stype >= 0x30u && stype <= 0x3Fu)) &&
        (((stype & 0x06u) >> 1) != 0x03u);
    if (!valid_sg_type) {
      CloseAndEraseSession(publisher->session_id, kMoqtErrProtocolViolation);
      return;
    }

    if (!publisher->peer_setup_received) {
      // QUIC 首包控制流丢包重传期间，合法子组单向流可能早于 SETUP 到达，做有界暂存待 SETUP 后重放。
      size_t total_pre_setup_bytes = 0;
      for (const auto& [usid, ufan] : publisher->inbound_uni_streams) {
        (void)usid;
        if (ufan.kind == UpstreamSubgroupFanout::Kind::kUnknown) {
          total_pre_setup_bytes += ufan.header_buf.size();
        }
      }
      if (total_pre_setup_bytes > kMaxPreSetupBufferedUniBytes) {
        if (publisher->quic) {
          publisher->quic->StopSending(stream_id, 0x02);
        }
        publisher->inbound_uni_streams.erase(stream_id);
      }
      return;
    }

    if (!publisher->authenticated) {
      CloseAndEraseSession(publisher->session_id, kMoqtErrUnauthorized);
      return;
    }

    size_t hdr_consumed = 0;
    bool violation = false;
    auto hdr =
        MoqSubgroupHeader::Decode(fanout.header_buf, &hdr_consumed, &violation);
    if (violation) {
      CloseAndEraseSession(publisher->session_id, kMoqtErrProtocolViolation);
      return;
    }
    if (!hdr.has_value()) {
      if (fanout.fin_received) {
        publisher->inbound_uni_streams.erase(stream_id);
      }
      return;
    }
    fanout.kind = UpstreamSubgroupFanout::Kind::kSubgroup;
    fanout.header = *hdr;

    if (hdr->track_alias == kMoqUpstreamDataTrackAlias) {
      // 零拷贝高优扇出房间内 MoQ 数据轨道子组流，并按发布者会话重映射 group_id 消除多发布者同房间碰撞。
      const uint64_t remapped_gid =
          RemapPublisherDataGroupId(publisher->publisher_tag, hdr->group_id);
      const uint64_t clamped_grp = std::min(remapped_gid, kMaxSafeMoqGroupId);
      const int64_t data_send_order =
          (int64_t{1} << 50) - static_cast<int64_t>(clamped_grp);
      for (auto& [other_id, sub_peer] : sessions_) {
        if (other_id == publisher->session_id || !sub_peer->quic ||
            !sub_peer->authenticated || sub_peer->room_id != publisher->room_id ||
            !sub_peer->has_data_subscription) {
          continue;
        }
        const uint64_t down_sid = sub_peer->quic->OpenUnidirectionalStream(
            hdr->publisher_priority, data_send_order);
        MoqSubgroupHeader down_hdr = *hdr;
        down_hdr.track_alias = sub_peer->data_downstream_alias;
        down_hdr.group_id = remapped_gid;
        sub_peer->quic->WriteStream(down_sid, down_hdr.Encode(),
                                    /*fin=*/false);
        fanout.downstream_targets.emplace_back(other_id, down_sid);
      }
      payload_to_forward = ArrayView<const uint8_t>(
          fanout.header_buf.data() + hdr_consumed,
          fanout.header_buf.size() - hdr_consumed);
    } else if (!publisher->is_video_publisher) {
      // 已被新重连发布者接管的旧残留会话不再向下游扇出陈旧视频帧。
      fanout.header_buf.clear();
      if (publisher->quic) {
        publisher->quic->StopSending(stream_id, 0);
      }
      if (fanout.fin_received) {
        publisher->inbound_uni_streams.erase(stream_id);
      }
      return;
    } else {
      const Timestamp now = clock_->CurrentTime();
      if (!publisher->first_media_time.IsFinite()) {
        publisher->first_media_time = now;
      }
      const SpatialLayer stream_layer =
          (hdr->track_alias == 1) ? SpatialLayer::kLow : SpatialLayer::kHigh;
      const size_t lidx = (stream_layer == SpatialLayer::kHigh) ? 1 : 0;
      publisher->largest_group[lidx] =
          std::max(publisher->largest_group[lidx],
                   std::min(hdr->group_id, kMaxQuicVarIntValue - 1));

      if (stream_layer == SpatialLayer::kLow) {
        publisher->has_low_layer = true;
        publisher->last_low_time = now;
      } else {
        publisher->has_high_layer = true;
        publisher->last_high_time = now;
      }
      const bool low_alive =
          publisher->has_low_layer &&
          (now - publisher->last_low_time) < TimeDelta::Millis(350);
      const bool high_startup_grace =
          !publisher->has_high_layer &&
          (now - publisher->first_media_time) < TimeDelta::Millis(200);
      const bool high_alive =
          high_startup_grace ||
          (publisher->has_high_layer &&
           (now - publisher->last_high_time) < TimeDelta::Millis(350));

      auto detach_other_layer_fanout = [&](uint64_t target_sub_sess_id,
                                           SpatialLayer keep_layer) {
        const auto target_sub_it = sessions_.find(target_sub_sess_id);
        QuicServerSessionHandle* target_quic =
            (target_sub_it != sessions_.end()) ? target_sub_it->second->quic.get()
                                               : nullptr;
        for (auto& [in_sid, in_fan] : publisher->inbound_uni_streams) {
          if (in_sid == stream_id ||
              in_fan.kind != UpstreamSubgroupFanout::Kind::kSubgroup ||
              in_fan.header.track_alias == kMoqUpstreamDataTrackAlias) {
            continue;
          }
          const SpatialLayer in_layer =
              (in_fan.header.track_alias == 1) ? SpatialLayer::kLow
                                               : SpatialLayer::kHigh;
          if (in_layer == keep_layer) {
            continue;
          }
          for (auto tit = in_fan.downstream_targets.begin();
               tit != in_fan.downstream_targets.end();) {
            if (tit->first == target_sub_sess_id) {
              if (target_quic != nullptr) {
                target_quic->ResetStream(tit->second, 0);
              }
              tit = in_fan.downstream_targets.erase(tit);
            } else {
              ++tit;
            }
          }
        }
      };

      auto reset_stale_media_streams_for_slow_sub = [&](uint64_t slow_sub_id,
                                                        QuicServerSessionHandle*
                                                            slow_quic) {
        for (auto& [in_sid, in_fan] : publisher->inbound_uni_streams) {
          if (in_sid == stream_id ||
              in_fan.kind != UpstreamSubgroupFanout::Kind::kSubgroup ||
              in_fan.header.track_alias == kMoqUpstreamDataTrackAlias) {
            continue;
          }
          for (auto tit = in_fan.downstream_targets.begin();
               tit != in_fan.downstream_targets.end();) {
            if (tit->first == slow_sub_id) {
              if (slow_quic != nullptr) {
                slow_quic->ResetStream(tit->second, 0x02 /* DELIVERY_TIMEOUT */);
              }
              tit = in_fan.downstream_targets.erase(tit);
            } else {
              ++tit;
            }
          }
        }
      };

      for (auto& [other_id, sub_peer] : sessions_) {
        if (other_id == publisher->session_id || !sub_peer->quic ||
            !sub_peer->authenticated) {
          continue;
        }
        const auto grp_it =
            sub_peer->video_subscriptions.find(publisher->video_peer_namespace);
        if (grp_it == sub_peer->video_subscriptions.end()) {
          continue;
        }
        auto& sub = grp_it->second;

        // 慢消费者保护：若下游订阅者未发送缓冲已积压超过 2 MB，使用 DELIVERY_TIMEOUT(0x02) 重置陈旧媒体子组流。
        if (sub_peer->quic->GetCongestionSnapshot()
                .unsent_stream_bytes.bytes() > kSlowConsumerMaxUnsentBytes) {
          reset_stale_media_streams_for_slow_sub(other_id,
                                                 sub_peer->quic.get());
          if (sub_peer->quic->GetCongestionSnapshot()
                  .unsent_stream_bytes.bytes() > kSlowConsumerMaxUnsentBytes) {
            ForwardNewGroupRequest(publisher->video_peer_namespace,
                                   sub.target_layer);
            continue;
          }
        }

        const bool switch_ready_on_target =
            sub.waiting_for_group_switch && stream_layer == sub.target_layer &&
            ((hdr->subgroup_id == 0 &&
              (hdr->group_id >= sub.switch_epoch_min_group[lidx] ||
               hdr->group_id <= 1)) ||
             (hdr->subgroup_id > 0 && sub.switch_epoch_min_group[lidx] > 0 &&
              hdr->group_id >= sub.switch_epoch_min_group[lidx]));
        if (switch_ready_on_target) {
          sub.active_layer = sub.target_layer;
          sub.waiting_for_group_switch = false;
          sub.switch_epoch_min_group[lidx] = hdr->group_id;
          sub.active_group_id = hdr->group_id;
          detach_other_layer_fanout(other_id, sub.active_layer);
          RTC_LOG(kInfo) << "MOQT Relay completed GOP-aligned Simulcast switch"
                         << " for subscriber=" << sub_peer->peer_id << " -> "
                         << (sub.active_layer == SpatialLayer::kLow ? "LOW"
                                                                    : "HIGH");
        } else if (sub.target_layer == SpatialLayer::kHigh && !high_alive &&
                   sub.active_layer == SpatialLayer::kHigh &&
                   stream_layer == SpatialLayer::kLow &&
                   hdr->subgroup_id == 0) {
          sub.active_layer = SpatialLayer::kLow;
          sub.switch_epoch_min_group[0] = hdr->group_id;
          sub.active_group_id = hdr->group_id;
          detach_other_layer_fanout(other_id, SpatialLayer::kLow);
          RTC_LOG(kInfo) << "MOQT Relay auto-downgraded subscriber="
                         << sub_peer->peer_id
                         << " to LOW due to upstream HIGH layer suspension";
        } else if (sub.target_layer == SpatialLayer::kHigh &&
                   sub.active_layer == SpatialLayer::kLow &&
                   !sub.waiting_for_group_switch &&
                   stream_layer == SpatialLayer::kHigh &&
                   hdr->subgroup_id == 0) {
          sub.active_layer = SpatialLayer::kHigh;
          sub.switch_epoch_min_group[1] = hdr->group_id;
          sub.active_group_id = hdr->group_id;
          detach_other_layer_fanout(other_id, SpatialLayer::kHigh);
          RTC_LOG(kInfo) << "MOQT Relay auto-restored subscriber="
                         << sub_peer->peer_id << " back to HIGH layer";
        }

        const bool layer_matches =
            (stream_layer == sub.active_layer) ||
            (sub.active_layer == SpatialLayer::kLow && !low_alive &&
             stream_layer == SpatialLayer::kHigh) ||
            (sub.active_layer == SpatialLayer::kHigh && !high_alive &&
             stream_layer == SpatialLayer::kLow);
        if (!layer_matches) {
          continue;
        }
        // 拦截关键帧切换边界前后乱序到达的旧 GOP 增强时间层子组流（subgroup_id > 0）。
        if (hdr->subgroup_id > 0 &&
            hdr->group_id < sub.switch_epoch_min_group[lidx]) {
          continue;
        }

        uint64_t chosen_alias = 0;
        if (stream_layer == SpatialLayer::kLow && sub.low_sub.has_value()) {
          chosen_alias = sub.low_sub->downstream_track_alias;
        } else if (stream_layer == SpatialLayer::kHigh &&
                   sub.high_sub.has_value()) {
          chosen_alias = sub.high_sub->downstream_track_alias;
        } else if (sub.high_sub.has_value()) {
          chosen_alias = sub.high_sub->downstream_track_alias;
        } else if (sub.low_sub.has_value()) {
          chosen_alias = sub.low_sub->downstream_track_alias;
        } else {
          continue;
        }

        sub.active_group_id = std::max(sub.active_group_id, hdr->group_id);
        const uint64_t clamped_grp = std::min(hdr->group_id, kMaxSafeMoqGroupId);
        const uint64_t clamped_sg =
            std::min(hdr->subgroup_id, kMaxSafeMoqSubgroupId);
        const int64_t send_order =
            static_cast<int64_t>(clamped_grp * 100ULL) + 50 -
            static_cast<int64_t>(clamped_sg);
        const uint64_t down_sid = sub_peer->quic->OpenUnidirectionalStream(
            hdr->publisher_priority, send_order);

        MoqSubgroupHeader down_hdr = *hdr;
        down_hdr.track_alias = chosen_alias;
        sub_peer->quic->WriteStream(down_sid, down_hdr.Encode(), /*fin=*/false);

        fanout.downstream_targets.emplace_back(other_id, down_sid);
      }

      payload_to_forward = ArrayView<const uint8_t>(
          fanout.header_buf.data() + hdr_consumed,
          fanout.header_buf.size() - hdr_consumed);
    }
  } else if (fanout.kind == UpstreamSubgroupFanout::Kind::kControl) {
    if (fanout.fin_received) {
      CloseAndEraseSession(publisher->session_id, kMoqtErrProtocolViolation);
      return;
    }
    if (fanout.header_buf.size() + data.size() >
        kMaxRelayControlOrHeaderBufBytes) {
      fanout.header_buf.clear();
      CloseAndEraseSession(publisher->session_id, kMoqtErrProtocolViolation);
      return;
    }
    fanout.header_buf.insert(fanout.header_buf.end(), data.begin(), data.end());
    HandleControlBytes(publisher, &fanout.header_buf);
    return;
  }

  if (!payload_to_forward.empty() || fanout.fin_received) {
    const bool is_media_subgroup =
        (fanout.kind == UpstreamSubgroupFanout::Kind::kSubgroup &&
         fanout.header.track_alias != kMoqUpstreamDataTrackAlias);
    for (auto tit = fanout.downstream_targets.begin();
         tit != fanout.downstream_targets.end();) {
      const uint64_t sub_sess_id = tit->first;
      const uint64_t down_sid = tit->second;
      const auto sub_it = sessions_.find(sub_sess_id);
      if (sub_it == sessions_.end() || !sub_it->second->quic) {
        tit = fanout.downstream_targets.erase(tit);
        continue;
      }
      if (is_media_subgroup &&
          sub_it->second->quic->GetCongestionSnapshot()
                  .unsent_stream_bytes.bytes() > kSlowConsumerMaxUnsentBytes) {
        sub_it->second->quic->ResetStream(down_sid, 0x02 /* DELIVERY_TIMEOUT */);
        tit = fanout.downstream_targets.erase(tit);
        ForwardNewGroupRequest(
            publisher->video_peer_namespace,
            (fanout.header.track_alias == 1) ? SpatialLayer::kLow
                                             : SpatialLayer::kHigh);
        continue;
      }
      sub_it->second->quic->WriteStream(down_sid, payload_to_forward,
                                        fanout.fin_received);
      ++tit;
    }
  }

  if (!fanout.header_buf.empty() &&
      fanout.kind == UpstreamSubgroupFanout::Kind::kSubgroup) {
    fanout.header_buf.clear();
  }
  if (fanout.fin_received) {
    publisher->inbound_uni_streams.erase(stream_id);
  }
}

}  // namespace rtc
