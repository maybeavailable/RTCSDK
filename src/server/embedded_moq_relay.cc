#include "server/embedded_moq_relay.h"

#include <algorithm>

#include "rtc_base/logging.h"

namespace rtc {

EmbeddedMoqRelayServer::EmbeddedMoqRelayServer(std::string bind_ip)
    : clock_(Clock::GetRealTimeClock()),
      bind_ip_(std::move(bind_ip)),
      net_queue_(std::make_unique<TaskQueueBoost>("moq-relay",
                                                  TaskQueuePriority::kHigh)),
      net_checker_(net_queue_.get()),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {
  quic_server_ = std::make_unique<AsioQuicServer>(clock_, net_queue_.get(),
                                                  this, bind_ip_, "moq-00");
}

EmbeddedMoqRelayServer::~EmbeddedMoqRelayServer() { Stop(); }

bool EmbeddedMoqRelayServer::Start(uint16_t udp_port) {
  if (!quic_server_->Start(udp_port)) {
    RTC_LOG(kError) << "EmbeddedMoqRelayServer failed to bind UDP " << bind_ip_
                    << ":" << udp_port;
    return false;
  }
  stopped_.store(false, std::memory_order_release);
  RTC_LOG(kInfo) << "EmbeddedMoqRelayServer started on moq://" << bind_ip_
                 << ":" << quic_server_->local_port();
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
    sessions_.clear();
  });
  net_queue_->Shutdown();
  RTC_LOG(kInfo) << "EmbeddedMoqRelayServer stopped";
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

void EmbeddedMoqRelayServer::SplitRoomAndPeer(std::string_view ns,
                                              std::string* out_room,
                                              std::string* out_peer) {
  const size_t slash = ns.find('/');
  if (slash == std::string_view::npos) {
    *out_room = "default";
    *out_peer = std::string(ns);
    return;
  }
  *out_room = std::string(ns.substr(0, slash));
  *out_peer = std::string(ns.substr(slash + 1));
}

void EmbeddedMoqRelayServer::OnServerSessionConnected(
    std::shared_ptr<QuicServerSessionHandle> session) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  auto ctx = std::make_unique<PeerSession>();
  ctx->session_id = session->session_id();
  ctx->quic = std::move(session);
  sessions_.emplace(ctx->session_id, std::move(ctx));
}

void EmbeddedMoqRelayServer::OnServerSessionDisconnected(uint64_t session_id,
                                                         int /*error_code*/) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  const std::string room = it->second->room_id;
  const std::string ns = it->second->announced_namespace;
  const bool was_announced = it->second->is_announced;
  sessions_.erase(it);

  if (was_announced && !ns.empty()) {
    MoqControlMessage unann;
    unann.type = MoqControlMessageType::kUnannounce;
    unann.track_namespace = ns;
    for (auto& [sid, peer] : sessions_) {
      (void)sid;
      if (peer->room_id == room) {
        SendControlToPeer(peer.get(), unann);
      }
    }
  }
}

void EmbeddedMoqRelayServer::OnServerStreamOpened(uint64_t session_id,
                                                  uint64_t stream_id,
                                                  bool unidirectional) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  if (!unidirectional) {
    it->second->control_stream_id = stream_id;
    it->second->has_control_stream = true;
  } else {
    it->second->inbound_uni_streams[stream_id] = UpstreamSubgroupFanout{};
  }
}

void EmbeddedMoqRelayServer::OnServerStreamData(uint64_t session_id,
                                                uint64_t stream_id,
                                                ArrayView<const uint8_t> data,
                                                bool fin) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  const bool is_bidi = (stream_id & 0x02u) == 0;
  if (is_bidi) {
    it->second->control_stream_id = stream_id;
    it->second->has_control_stream = true;
    HandleControlBytes(it->second.get(), data);
  } else {
    HandleUnidirectionalBytes(it->second.get(), stream_id, data, fin);
  }
}

void EmbeddedMoqRelayServer::OnServerStreamReset(uint64_t session_id,
                                                 uint64_t stream_id,
                                                 uint64_t app_error_code) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return;
  }
  const auto fan_it = it->second->inbound_uni_streams.find(stream_id);
  if (fan_it == it->second->inbound_uni_streams.end()) {
    return;
  }
  for (const auto& [sub_sess_id, down_sid] :
       fan_it->second.downstream_targets) {
    const auto sub_it = sessions_.find(sub_sess_id);
    if (sub_it != sessions_.end() && sub_it->second->quic) {
      sub_it->second->quic->ResetStream(down_sid, app_error_code);
    }
  }
  it->second->inbound_uni_streams.erase(fan_it);
}

void EmbeddedMoqRelayServer::SendControlToPeer(PeerSession* peer,
                                               const MoqControlMessage& msg) {
  if (peer == nullptr || !peer->quic) {
    return;
  }
  if (!peer->has_control_stream) {
    peer->control_stream_id = peer->quic->OpenBidirectionalStream();
    peer->has_control_stream = true;
  }
  const auto wire = msg.Encode();
  peer->quic->WriteStream(peer->control_stream_id, wire, false);
}

void EmbeddedMoqRelayServer::ForwardKeyframeRequest(
    const std::string& target_namespace,
    const std::string& track_name) {
  const Timestamp now = clock_->CurrentTime();
  for (auto& [sid, peer] : sessions_) {
    (void)sid;
    if (peer->is_announced && peer->announced_namespace == target_namespace) {
      if (peer->last_kf_req_time.IsFinite() &&
          (now - peer->last_kf_req_time) < TimeDelta::Millis(80)) {
        return;
      }
      peer->last_kf_req_time = now;
      MoqControlMessage kf;
      kf.type = MoqControlMessageType::kKeyframeRequest;
      kf.track_namespace = target_namespace;
      kf.track_name = track_name;
      SendControlToPeer(peer.get(), kf);
      return;
    }
  }
}

void EmbeddedMoqRelayServer::HandleControlBytes(PeerSession* peer,
                                                ArrayView<const uint8_t> data) {
  peer->ctrl_rx_buf.insert(peer->ctrl_rx_buf.end(), data.begin(), data.end());
  while (!peer->ctrl_rx_buf.empty()) {
    size_t consumed = 0;
    auto msg = MoqControlMessage::Decode(peer->ctrl_rx_buf, &consumed);
    if (!msg.has_value()) {
      break;
    }
    peer->ctrl_rx_buf.erase(
        peer->ctrl_rx_buf.begin(),
        peer->ctrl_rx_buf.begin() + static_cast<ptrdiff_t>(consumed));

    switch (msg->type) {
      case MoqControlMessageType::kClientSetup: {
        SplitRoomAndPeer(msg->track_namespace, &peer->room_id, &peer->peer_id);
        MoqControlMessage srv_setup;
        srv_setup.type = MoqControlMessageType::kServerSetup;
        srv_setup.track_namespace = msg->track_namespace;
        SendControlToPeer(peer, srv_setup);

        // 向新加入的节点通知同一房间内所有当前活跃的发布流声明。
        for (const auto& [other_id, other] : sessions_) {
          if (other_id == peer->session_id || other->room_id != peer->room_id ||
              !other->is_announced) {
            continue;
          }
          MoqControlMessage ann;
          ann.type = MoqControlMessageType::kAnnounce;
          ann.track_namespace = other->announced_namespace;
          ann.track_name = other->announced_track_name;
          SendControlToPeer(peer, ann);
        }
        break;
      }
      case MoqControlMessageType::kAnnounce: {
        if (peer->room_id.empty()) {
          SplitRoomAndPeer(msg->track_namespace, &peer->room_id,
                           &peer->peer_id);
        }
        peer->announced_namespace = msg->track_namespace;
        peer->announced_track_name = msg->track_name;
        peer->is_announced = true;

        MoqControlMessage ok = *msg;
        ok.type = MoqControlMessageType::kAnnounceOk;
        SendControlToPeer(peer, ok);

        RTC_LOG(kInfo) << "MoQ Relay peer=" << peer->peer_id
                       << " announced namespace=" << peer->announced_namespace
                       << " (" << peer->announced_track_name << ")";

        for (auto& [other_id, other] : sessions_) {
          if (other_id == peer->session_id || other->room_id != peer->room_id) {
            continue;
          }
          SendControlToPeer(other.get(), *msg);
        }
        break;
      }
      case MoqControlMessageType::kUnannounce: {
        peer->is_announced = false;
        for (auto& [other_id, other] : sessions_) {
          if (other_id != peer->session_id && other->room_id == peer->room_id) {
            SendControlToPeer(other.get(), *msg);
          }
        }
        break;
      }
      case MoqControlMessageType::kSubscribe: {
        DownstreamSubscription sub;
        sub.subscribe_id = msg->subscribe_id;
        sub.downstream_track_alias = msg->track_alias;
        sub.target_namespace = msg->track_namespace;
        sub.target_layer = (msg->track_name == "video/low")
                               ? SpatialLayer::kLow
                               : SpatialLayer::kHigh;
        sub.active_layer = sub.target_layer;
        peer->subscriptions.insert_or_assign(sub.subscribe_id, sub);

        MoqControlMessage ok = *msg;
        ok.type = MoqControlMessageType::kSubscribeOk;
        SendControlToPeer(peer, ok);

        RTC_LOG(kInfo) << "MoQ Relay subscriber=" << peer->peer_id
                       << " subscribed to " << sub.target_namespace
                       << " alias=" << sub.downstream_track_alias << " layer="
                       << (sub.target_layer == SpatialLayer::kLow ? "LOW"
                                                                  : "HIGH");
        ForwardKeyframeRequest(sub.target_namespace, msg->track_name);
        break;
      }
      case MoqControlMessageType::kSubscribeUpdate: {
        const auto sub_it = peer->subscriptions.find(msg->subscribe_id);
        if (sub_it == peer->subscriptions.end()) {
          break;
        }
        const SpatialLayer desired = (msg->track_name == "video/low")
                                         ? SpatialLayer::kLow
                                         : SpatialLayer::kHigh;
        if (sub_it->second.target_layer != desired) {
          sub_it->second.target_layer = desired;
          sub_it->second.waiting_for_group_switch = true;
          ForwardKeyframeRequest(sub_it->second.target_namespace,
                                 msg->track_name);
        }
        break;
      }
      case MoqControlMessageType::kUnsubscribe: {
        peer->subscriptions.erase(msg->subscribe_id);
        break;
      }
      case MoqControlMessageType::kKeyframeRequest: {
        ForwardKeyframeRequest(msg->track_namespace, msg->track_name);
        break;
      }
      default:
        break;
    }
  }
}

void EmbeddedMoqRelayServer::HandleUnidirectionalBytes(
    PeerSession* publisher,
    uint64_t stream_id,
    ArrayView<const uint8_t> data,
    bool fin) {
  auto& fanout = publisher->inbound_uni_streams[stream_id];
  ArrayView<const uint8_t> payload_to_forward = data;

  if (!fanout.header_parsed) {
    fanout.header_buf.insert(fanout.header_buf.end(), data.begin(), data.end());
    size_t hdr_consumed = 0;
    auto hdr = MoqSubgroupHeader::Decode(fanout.header_buf, &hdr_consumed);
    if (!hdr.has_value()) {
      return;
    }
    fanout.header = *hdr;
    fanout.header_parsed = true;

    const Timestamp now = clock_->CurrentTime();
    if (!publisher->first_media_time.IsFinite()) {
      publisher->first_media_time = now;
    }
    const SpatialLayer stream_layer =
        (hdr->track_alias == 1) ? SpatialLayer::kLow : SpatialLayer::kHigh;
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
    // 首帧启动 200ms 宽限期内等待高优先级低清包之后紧随到达的高清层流头，避免首帧误降级。
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
        if (in_sid == stream_id || !in_fan.header_parsed) {
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

    // 将房间内匹配的订阅者绑定至下行单向流进行扇出分发。
    for (auto& [other_id, sub_peer] : sessions_) {
      if (other_id == publisher->session_id || !sub_peer->quic) {
        continue;
      }
      for (auto& [sub_id, sub] : sub_peer->subscriptions) {
        (void)sub_id;
        if (sub.target_namespace != publisher->announced_namespace) {
          continue;
        }
        if (sub.waiting_for_group_switch && stream_layer == sub.target_layer &&
            hdr->subgroup_id == 0) {
          sub.active_layer = sub.target_layer;
          sub.waiting_for_group_switch = false;
          detach_other_layer_fanout(other_id, sub.active_layer);
          RTC_LOG(kInfo) << "MoQ Relay completed GOP-aligned Simulcast switch"
                         << " for subscriber=" << sub_peer->peer_id << " -> "
                         << (sub.active_layer == SpatialLayer::kLow ? "LOW"
                                                                    : "HIGH");
        } else if (sub.target_layer == SpatialLayer::kHigh && !high_alive &&
                   sub.active_layer == SpatialLayer::kHigh &&
                   stream_layer == SpatialLayer::kLow &&
                   hdr->subgroup_id == 0) {
          // 当上行发布端因拥塞暂停高清层（High）时，在低清层（Low）新 GOP 边界自动降级转发，保障画面不断流。
          sub.active_layer = SpatialLayer::kLow;
          detach_other_layer_fanout(other_id, SpatialLayer::kLow);
          RTC_LOG(kInfo) << "MoQ Relay auto-downgraded subscriber="
                         << sub_peer->peer_id
                         << " to LOW due to upstream HIGH layer suspension";
        } else if (sub.target_layer == SpatialLayer::kHigh &&
                   sub.active_layer == SpatialLayer::kLow &&
                   !sub.waiting_for_group_switch &&
                   stream_layer == SpatialLayer::kHigh &&
                   hdr->subgroup_id == 0) {
          // 当上行带宽恢复、高清层（High）重新发送关键帧 GOP 时，自动切回订阅者期望的高清层。
          sub.active_layer = SpatialLayer::kHigh;
          detach_other_layer_fanout(other_id, SpatialLayer::kHigh);
          RTC_LOG(kInfo) << "MoQ Relay auto-restored subscriber="
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

        sub.active_group_id = hdr->group_id;
        const int64_t send_order =
            static_cast<int64_t>(hdr->group_id * 100) + 50 -
            static_cast<int64_t>(hdr->subgroup_id);
        const uint64_t down_sid = sub_peer->quic->OpenUnidirectionalStream(
            hdr->publisher_priority, send_order);

        MoqSubgroupHeader down_hdr = *hdr;
        down_hdr.track_alias = sub.downstream_track_alias;
        const auto down_hdr_bytes = down_hdr.Encode();
        sub_peer->quic->WriteStream(down_sid, down_hdr_bytes, false);

        fanout.downstream_targets.emplace_back(other_id, down_sid);
      }
    }

    payload_to_forward = ArrayView<const uint8_t>(
        fanout.header_buf.data() + hdr_consumed,
        fanout.header_buf.size() - hdr_consumed);
  }

  if (!payload_to_forward.empty() || fin) {
    for (const auto& [sub_sess_id, down_sid] : fanout.downstream_targets) {
      const auto sub_it = sessions_.find(sub_sess_id);
      if (sub_it != sessions_.end() && sub_it->second->quic) {
        sub_it->second->quic->WriteStream(down_sid, payload_to_forward, fin);
      }
    }
  }

  if (!fanout.header_buf.empty() && fanout.header_parsed) {
    fanout.header_buf.clear();
  }
  if (fin) {
    publisher->inbound_uni_streams.erase(stream_id);
  }
}

}  // namespace rtc