#include "server/embedded_moq_relay.h"

#include <algorithm>
#include <limits>

#include "rtc_base/logging.h"

namespace rtc {

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
  if (session->negotiated_alpn() == kHttp3Alpn && sid < 1'000'000) {
    // 挂载 HTTP/3 + WebTransport 多路复用器；普通 HTTP/3 请求返回实时中继遥测状态，
    // Extended CONNECT(:protocol=webtransport) 将升级为虚拟 MOQT 会话回调至本实例。
    const uint64_t vbase = next_wt_virtual_id_base_;
    next_wt_virtual_id_base_ += 1024;
    auto h3_handler = [this](const Http3Request& req) -> Http3Response {
      if (custom_h3_handler_) {
        return custom_h3_handler_(req);
      }
      Http3Response resp;
      resp.status = 200;
      resp.headers.push_back({"content-type", "application/json"});
      resp.headers.push_back({"server", "RTCSDK-MoQ-Relay-draft17"});
      const std::string json =
          std::string("{\"protocol\":\"draft-ietf-moq-transport-17\",") +
          "\"http3\":true,\"webtransport\":true,\"path\":\"" + req.path +
          "\",\"active_moq_sessions\":" + std::to_string(sessions_.size()) +
          "}";
      resp.body.assign(json.begin(), json.end());
      return resp;
    };
    auto h3_conn = std::make_shared<Http3ServerConnection>(
        std::move(session), this, std::vector<std::string>{kMoqtDraft17Alpn},
        std::move(h3_handler), vbase);
    h3_conns_[sid] = h3_conn;
    h3_conn->Start();
    return;
  }

  auto ctx = std::make_unique<PeerSession>();
  ctx->session_id = sid;
  ctx->is_webtransport = (sid >= 1'000'000);
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
}

void EmbeddedMoqRelayServer::OnServerSessionDisconnected(uint64_t session_id,
                                                         int error_code) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto h3_it = h3_conns_.find(session_id);
  if (h3_it != h3_conns_.end()) {
    h3_it->second->OnQuicDisconnected(error_code);
    h3_conns_.erase(h3_it);
    return;
  }

  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  std::vector<MoqtTrackNamespace> active_ns;
  for (const auto& [bsid, ns] : it->second->published_namespaces) {
    (void)bsid;
    active_ns.push_back(ns);
  }
  sessions_.erase(it);

  for (const auto& ns : active_ns) {
    BroadcastNamespaceChange(session_id, ns, /*is_done=*/true);
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
    it->second->inbound_uni_streams.try_emplace(stream_id);
  } else if (it->second->upstream_sub_rx_bufs.find(stream_id) ==
             it->second->upstream_sub_rx_bufs.end()) {
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
  auto dg = MoqtObjectDatagram::Decode(data, &violation);
  if (violation) {
    if (pub_peer->quic) {
      pub_peer->quic->Close(kMoqtErrProtocolViolation);
    }
    return;
  }
  if (!dg.has_value()) {
    return;
  }
  if (dg->track_alias == kMoqUpstreamDataTrackAlias) {
    for (auto& [other_id, sub_peer] : sessions_) {
      if (other_id == pub_peer->session_id || !sub_peer->quic ||
          sub_peer->room_id != pub_peer->room_id ||
          !sub_peer->has_data_subscription) {
        continue;
      }
      MoqtObjectDatagram down_dg = *dg;
      down_dg.track_alias = sub_peer->data_downstream_alias;
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
  const Timestamp now = clock_->CurrentTime();
  for (auto& [sid, peer] : sessions_) {
    (void)sid;
    if (!peer->is_video_publisher ||
        peer->video_peer_namespace != target_peer_ns || !peer->quic) {
      continue;
    }
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
    MoqControlMessage upd;
    upd.type = MoqControlMessageType::kRequestUpdate;
    upd.request_id = AllocateServerRequestId(peer.get());
    upd.parameters.new_group_request = peer->largest_group[lidx] + 1;
    peer->quic->WriteStream(*opt_sid, upd.Encode(), /*fin=*/false);
    return;
  }
}

void EmbeddedMoqRelayServer::HandleUpstreamSubResponseBytes(
    PeerSession* peer,
    uint64_t stream_id,
    ArrayView<const uint8_t> data,
    bool fin) {
  auto& buf = peer->upstream_sub_rx_bufs[stream_id];
  buf.insert(buf.end(), data.begin(), data.end());
  while (!buf.empty()) {
    size_t consumed = 0;
    bool violation = false;
    auto msg = MoqControlMessage::Decode(buf, &consumed, &violation);
    if (violation) {
      if (peer->quic) {
        peer->quic->Close(kMoqtErrProtocolViolation);
      }
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
    auto msg = MoqControlMessage::Decode(*buf, &consumed, &violation);
    if (violation) {
      if (peer->quic) {
        peer->quic->Close(kMoqtErrProtocolViolation);
      }
      buf->clear();
      return;
    }
    if (!msg.has_value()) {
      break;
    }
    buf->erase(buf->begin(), buf->begin() + static_cast<ptrdiff_t>(consumed));

    if (msg->type == MoqControlMessageType::kSetup) {
      if (peer->peer_setup_received) {
        peer->quic->Close(kMoqtErrProtocolViolation);
        return;
      }
      if (peer->is_webtransport) {
        // draft-17 第 9.4.1.1 / 9.4.1.2 节：WebTransport 模式下收到 AUTHORITY 或 PATH 必须关闭会话。
        for (const auto& opt : msg->setup_options) {
          if (opt.type == kMoqtSetupOptionAuthority) {
            peer->quic->Close(kMoqtErrInvalidAuthority);
            return;
          }
          if (opt.type == kMoqtSetupOptionPath) {
            peer->quic->Close(kMoqtErrInvalidPath);
            return;
          }
        }
      }
      peer->peer_setup_received = true;
    } else if (msg->type == MoqControlMessageType::kGoaway) {
      if (!msg->new_session_uri.empty()) {
        // draft-17 第 9.5 节：客户端发送非空 New Session URI 属于协议违规。
        peer->quic->Close(kMoqtErrProtocolViolation);
        return;
      }
    } else {
      peer->quic->Close(kMoqtErrProtocolViolation);
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
    BroadcastNamespaceChange(peer->session_id, ns, /*is_done=*/true);
  }

  const auto req_it = peer->client_request_streams.find(stream_id);
  if (req_it != peer->client_request_streams.end()) {
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
  auto& rst = peer->client_request_streams[stream_id];
  rst.rx_buf.insert(rst.rx_buf.end(), data.begin(), data.end());

  while (!rst.rx_buf.empty()) {
    size_t consumed = 0;
    bool violation = false;
    auto msg = MoqControlMessage::Decode(rst.rx_buf, &consumed, &violation);
    if (violation) {
      if (peer->quic) {
        peer->quic->Close(kMoqtErrProtocolViolation);
      }
      rst.rx_buf.clear();
      return;
    }
    if (!msg.has_value()) {
      break;
    }
    rst.rx_buf.erase(rst.rx_buf.begin(),
                     rst.rx_buf.begin() + static_cast<ptrdiff_t>(consumed));

    // draft-17 第 9.1 节：客户端发起的 Request ID 必须为偶数。
    if ((msg->type == MoqControlMessageType::kSubscribe ||
         msg->type == MoqControlMessageType::kPublishNamespace ||
         msg->type == MoqControlMessageType::kSubscribeNamespace ||
         msg->type == MoqControlMessageType::kRequestUpdate ||
         msg->type == MoqControlMessageType::kTrackStatus) &&
        (msg->request_id & 1u) != 0) {
      peer->quic->Close(kMoqtErrInvalidRequestId);
      return;
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

        // 枚举当前已发布的全部匹配命名空间，紧随 REQUEST_OK 发送 NAMESPACE (0x08)。
        for (const auto& [other_id, other] : sessions_) {
          if (other_id == peer->session_id) {
            continue;
          }
          for (const auto& [pub_sid, full_ns] : other->published_namespaces) {
            (void)pub_sid;
            if (full_ns.StartsWith(msg->track_namespace)) {
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

        MoqControlMessage rok;
        rok.type = MoqControlMessageType::kRequestOk;
        peer->quic->WriteStream(stream_id, rok.Encode(), /*fin=*/false);

        if (peer->is_video_publisher) {
          OpenUpstreamSubscriptionsToPublisher(peer);
        }

        RTC_LOG(kInfo) << "MOQT Relay peer=" << peer->peer_id
                       << " PUBLISH_NAMESPACE "
                       << msg->track_namespace.ToSlashString();
        BroadcastNamespaceChange(peer->session_id, msg->track_namespace,
                                 /*is_done=*/false);
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
        peer->quic->WriteStream(stream_id, rok.Encode(), /*fin=*/false);

        if (rst.role == ClientRequestStreamState::Role::kSubscribeVideo) {
          const auto grp_it = peer->video_subscriptions.find(rst.ns);
          if (grp_it != peer->video_subscriptions.end()) {
            auto& grp = grp_it->second;
            auto* sub_ptr = (rst.video_layer == SpatialLayer::kLow)
                                ? (grp.low_sub ? &*grp.low_sub : nullptr)
                                : (grp.high_sub ? &*grp.high_sub : nullptr);
            if (sub_ptr != nullptr && msg->parameters.forward.has_value()) {
              sub_ptr->forward = *msg->parameters.forward;
              if (sub_ptr->forward == 1 && grp.target_layer != rst.video_layer) {
                grp.target_layer = rst.video_layer;
                grp.waiting_for_group_switch = true;
                ForwardNewGroupRequest(rst.ns, rst.video_layer);
              }
            }
            if (msg->parameters.new_group_request.has_value() &&
                (sub_ptr == nullptr || sub_ptr->forward == 1)) {
              ForwardNewGroupRequest(rst.ns, rst.video_layer);
            }
          }
        }
        break;
      }

      case MoqControlMessageType::kTrackStatus: {
        MoqControlMessage rok;
        rok.type = MoqControlMessageType::kRequestOk;
        peer->quic->WriteStream(stream_id, rok.Encode(), /*fin=*/true);
        break;
      }

      default: {
        MoqControlMessage err;
        err.type = MoqControlMessageType::kRequestError;
        err.error_or_status_code = kMoqtReqErrNotSupported;
        err.reason_phrase = "unsupported request";
        peer->quic->WriteStream(stream_id, err.Encode(), /*fin=*/true);
        break;
      }
    }
  }

  if (fin) {
    RemoveClientRequestStream(peer, stream_id);
  }
}

void EmbeddedMoqRelayServer::HandleUnidirectionalBytes(
    PeerSession* publisher,
    uint64_t stream_id,
    ArrayView<const uint8_t> data,
    bool fin) {
  auto& fanout = publisher->inbound_uni_streams[stream_id];
  ArrayView<const uint8_t> payload_to_forward = data;

  if (fanout.kind == UpstreamSubgroupFanout::Kind::kUnknown) {
    fanout.header_buf.insert(fanout.header_buf.end(), data.begin(), data.end());
    size_t peek_off = 0;
    uint64_t stype = 0;
    bool bad_vi = false;
    if (!MoqtVarInt::Read(fanout.header_buf, &peek_off, &stype, &bad_vi)) {
      if (bad_vi && publisher->quic) {
        publisher->quic->Close(kMoqtErrProtocolViolation);
      }
      return;
    }

    if (stype == static_cast<uint64_t>(MoqControlMessageType::kSetup)) {
      fanout.kind = UpstreamSubgroupFanout::Kind::kControl;
      if (fin) {
        publisher->quic->Close(kMoqtErrProtocolViolation);
        return;
      }
      HandleControlBytes(publisher, &fanout.header_buf);
      return;
    }

    size_t hdr_consumed = 0;
    bool violation = false;
    auto hdr =
        MoqSubgroupHeader::Decode(fanout.header_buf, &hdr_consumed, &violation);
    if (violation) {
      if (publisher->quic) {
        publisher->quic->Close(kMoqtErrProtocolViolation);
      }
      return;
    }
    if (!hdr.has_value()) {
      return;
    }
    fanout.kind = UpstreamSubgroupFanout::Kind::kSubgroup;
    fanout.header = *hdr;

    if (hdr->track_alias == kMoqUpstreamDataTrackAlias) {
      // 零拷贝高优扇出房间内 MoQ 数据轨道子组流。
      const int64_t data_send_order =
          (int64_t{1} << 50) - static_cast<int64_t>(hdr->group_id);
      for (auto& [other_id, sub_peer] : sessions_) {
        if (other_id == publisher->session_id || !sub_peer->quic ||
            sub_peer->room_id != publisher->room_id ||
            !sub_peer->has_data_subscription) {
          continue;
        }
        const uint64_t down_sid = sub_peer->quic->OpenUnidirectionalStream(
            hdr->publisher_priority, data_send_order);
        MoqSubgroupHeader down_hdr = *hdr;
        down_hdr.track_alias = sub_peer->data_downstream_alias;
        sub_peer->quic->WriteStream(down_sid, down_hdr.Encode(),
                                    /*fin=*/false);
        fanout.downstream_targets.emplace_back(other_id, down_sid);
      }
      payload_to_forward = ArrayView<const uint8_t>(
          fanout.header_buf.data() + hdr_consumed,
          fanout.header_buf.size() - hdr_consumed);
    } else {
      const Timestamp now = clock_->CurrentTime();
      if (!publisher->first_media_time.IsFinite()) {
        publisher->first_media_time = now;
      }
      const SpatialLayer stream_layer =
          (hdr->track_alias == 1) ? SpatialLayer::kLow : SpatialLayer::kHigh;
      const size_t lidx = (stream_layer == SpatialLayer::kHigh) ? 1 : 0;
      publisher->largest_group[lidx] =
          std::max(publisher->largest_group[lidx], hdr->group_id);

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
          in_fan.downstream_targets.erase(
              std::remove_if(in_fan.downstream_targets.begin(),
                             in_fan.downstream_targets.end(),
                             [target_sub_sess_id](const auto& kv) {
                               return kv.first == target_sub_sess_id;
                             }),
              in_fan.downstream_targets.end());
        }
      };

      for (auto& [other_id, sub_peer] : sessions_) {
        if (other_id == publisher->session_id || !sub_peer->quic) {
          continue;
        }
        const auto grp_it =
            sub_peer->video_subscriptions.find(publisher->video_peer_namespace);
        if (grp_it == sub_peer->video_subscriptions.end()) {
          continue;
        }
        auto& sub = grp_it->second;
        if (sub.waiting_for_group_switch && stream_layer == sub.target_layer &&
            hdr->subgroup_id == 0) {
          sub.active_layer = sub.target_layer;
          sub.waiting_for_group_switch = false;
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

        sub.active_group_id = hdr->group_id;
        const int64_t send_order =
            static_cast<int64_t>(hdr->group_id * 100) + 50 -
            static_cast<int64_t>(hdr->subgroup_id);
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
    if (fin) {
      publisher->quic->Close(kMoqtErrProtocolViolation);
      return;
    }
    fanout.header_buf.insert(fanout.header_buf.end(), data.begin(), data.end());
    HandleControlBytes(publisher, &fanout.header_buf);
    return;
  }

  if (!payload_to_forward.empty() || fin) {
    for (const auto& [sub_sess_id, down_sid] : fanout.downstream_targets) {
      const auto sub_it = sessions_.find(sub_sess_id);
      if (sub_it != sessions_.end() && sub_it->second->quic) {
        sub_it->second->quic->WriteStream(down_sid, payload_to_forward, fin);
      }
    }
  }

  if (!fanout.header_buf.empty() &&
      fanout.kind == UpstreamSubgroupFanout::Kind::kSubgroup) {
    fanout.header_buf.clear();
  }
  if (fin) {
    publisher->inbound_uni_streams.erase(stream_id);
  }
}

}  // namespace rtc
