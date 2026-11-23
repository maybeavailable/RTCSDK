#include "sdk/rtc_video_engine_impl.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "call/webrtc_p2p_backend.h"
#include "moq/moq_transport.h"
#include "rtc_base/logging.h"

namespace rtc {

std::unique_ptr<RtcVideoEngine> RtcVideoEngine::Create(
    const EngineConfig& config,
    IRtcEventObserver* observer,
    std::shared_ptr<IMoqQuicEngine> custom_moq_quic_engine) {
  return std::make_unique<RtcVideoEngineImpl>(
      config, observer, std::move(custom_moq_quic_engine));
}

void RtcVideoEngine::SetMinLogSeverity(LoggingSeverity severity) {
  LogMessage::SetMinLogSeverity(severity);
}

void RtcVideoEngine::SetLogToStderr(bool enable) {
  LogMessage::SetLogToStderr(enable);
}

void RtcVideoEngine::AddLogSink(LogSink* sink, LoggingSeverity min_severity) {
  LogMessage::AddLogSink(sink, min_severity);
}

void RtcVideoEngine::RemoveLogSink(LogSink* sink) {
  LogMessage::RemoveLogSink(sink);
}

RtcVideoEngineImpl::RtcVideoEngineImpl(
    const EngineConfig& config,
    IRtcEventObserver* observer,
    std::shared_ptr<IMoqQuicEngine> custom_moq_quic_engine)
    : clock_(Clock::GetRealTimeClock()),
      config_(config),
      use_simulcast_(
          (config.transport_mode == RTC_TRANSPORT_MODE_MOQ ||
           config.transport_mode == RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT) &&
          config.enable_simulcast),
      observer_(observer),
      queues_(std::make_unique<SdkTaskQueues>()),
      slab_pool_(PacketSlabPool::Create(2048)),
      rate_allocator_(SimulcastAllocatorConfig{
          use_simulcast_, config.min_bitrate_bps, 120'000,
          config.low_layer_max_bps, 400'000, 80'000, config.max_bitrate_bps}),
      cb_checker_(queues_->callback()),
      cb_safety_(PendingTaskSafetyFlag::CreateDetached()) {
  const bool is_moq =
      (config_.transport_mode == RTC_TRANSPORT_MODE_MOQ ||
       config_.transport_mode == RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT);
  RTC_LOG(kInfo) << "RtcVideoEngine created (mode="
                 << (config_.transport_mode ==
                             RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT
                         ? "IETF_MoQ_WebTransport_H3"
                         : (is_moq ? "IETF_MoQ_Draft17" : "WebRTC_P2P"))
                 << ", codec="
                 << (config_.publish_codec == RTC_CODEC_H265 ? "H265" : "H264")
                 << ", simulcast=" << (use_simulcast_ ? "on" : "off") << ")";
  if (is_moq) {
    backend_ = std::make_unique<MoqRelayBackend>(
        clock_, queues_.get(), config_, this,
        std::move(custom_moq_quic_engine));
  } else {
    backend_ =
        std::make_unique<WebRtcP2pBackend>(clock_, queues_.get(), config_, this);
  }
}

RtcVideoEngineImpl::~RtcVideoEngineImpl() {
  LeaveRoom();
  queues_->callback()->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&cb_checker_);
    cb_safety_.flag()->SetNotAlive();
  });
  backend_.reset();
  queues_->ShutdownAll();
  RTC_LOG(kInfo) << "RtcVideoEngine destroyed cleanly";
}

int RtcVideoEngineImpl::JoinRoom(const std::string& room_id,
                                 const std::string& local_peer_id) {
  if (room_id.empty() || local_peer_id.empty()) {
    return RTC_ERR_INVALID_ARG;
  }
  bool expected = false;
  if (!joined_.compare_exchange_strong(expected, true,
                                       std::memory_order_acq_rel)) {
    return RTC_ERR_ALREADY_CONNECTED;
  }
  return backend_->StartSession(room_id, local_peer_id);
}

int RtcVideoEngineImpl::LeaveRoom() {
  bool expected = true;
  if (!joined_.compare_exchange_strong(expected, false,
                                       std::memory_order_acq_rel)) {
    return RTC_OK;
  }
  RTC_LOG(kInfo) << "Leaving session";
  if (backend_) {
    backend_->StopSession();
  }
  return RTC_OK;
}

int RtcVideoEngineImpl::PushVideoFrame(const rtc_encoded_frame_t& frame) {
  if (frame.data == nullptr || frame.size == 0) {
    return RTC_ERR_INVALID_ARG;
  }
  if (!joined_.load(std::memory_order_acquire)) {
    return RTC_ERR_NOT_CONNECTED;
  }

  EncodedVideoFrame internal;
  internal.data.assign(frame.data, frame.data + frame.size);
  internal.capture_time =
      Timestamp::Micros(static_cast<int64_t>(frame.capture_ts_us));
  internal.rtp_timestamp =
      MicrosToRtp90kHz(static_cast<int64_t>(frame.capture_ts_us));
  internal.codec = static_cast<VideoCodec>(config_.publish_codec);
  internal.layer =
      (use_simulcast_ && frame.layer == RTC_STREAM_LAYER_LOW)
          ? SpatialLayer::kLow
          : SpatialLayer::kHigh;
  internal.dep.is_keyframe = frame.is_keyframe;
  internal.dep.spatial_id = static_cast<uint8_t>(internal.layer);
  internal.dep.temporal_id = frame.temporal_id;
  internal.dep.discardable = frame.discardable;

  return backend_->SendEncodedFrame(std::move(internal));
}

int RtcVideoEngineImpl::SubscribeTrack(const std::string& remote_track_id,
                                       rtc_stream_layer_e preferred_layer) {
  if (remote_track_id.empty()) {
    return RTC_ERR_INVALID_ARG;
  }
  return backend_->SubscribeRemoteTrack(
      remote_track_id, preferred_layer == RTC_STREAM_LAYER_LOW
                           ? SpatialLayer::kLow
                           : SpatialLayer::kHigh);
}

int RtcVideoEngineImpl::SwitchSubscribedLayer(
    const std::string& remote_track_id,
    rtc_stream_layer_e preferred_layer) {
  if (remote_track_id.empty()) {
    return RTC_ERR_INVALID_ARG;
  }
  return backend_->SwitchSubscribedLayer(
      remote_track_id, preferred_layer == RTC_STREAM_LAYER_LOW
                           ? SpatialLayer::kLow
                           : SpatialLayer::kHigh);
}

int RtcVideoEngineImpl::UnsubscribeTrack(const std::string& remote_track_id) {
  if (remote_track_id.empty()) {
    return RTC_ERR_INVALID_ARG;
  }
  return backend_->UnsubscribeRemoteTrack(remote_track_id);
}

int RtcVideoEngineImpl::RequestRemoteIdr(const std::string& remote_track_id) {
  return backend_->RequestRemoteKeyFrame(remote_track_id);
}

int RtcVideoEngineImpl::SetQuicCongestionControl(rtc_quic_cc_algo_e algo) {
  return backend_->SetQuicCongestionControl(algo);
}

int RtcVideoEngineImpl::SetCustomQuicCongestionController(
    std::shared_ptr<IQuicCongestionControllerFactory> factory) {
  return backend_->SetCustomQuicCongestionController(std::move(factory));
}

int RtcVideoEngineImpl::CreateLocalOffer(std::string* out_sdp) {
  joined_.store(true, std::memory_order_release);
  return backend_->CreateLocalOffer(out_sdp);
}

int RtcVideoEngineImpl::SetRemoteDescription(std::string_view sdp_type,
                                             std::string_view remote_sdp,
                                             std::string* out_answer_sdp) {
  joined_.store(true, std::memory_order_release);
  return backend_->SetRemoteDescription(sdp_type, remote_sdp, out_answer_sdp);
}

int RtcVideoEngineImpl::AddRemoteIceCandidate(std::string_view candidate_sdp) {
  return backend_->AddRemoteIceCandidate(candidate_sdp);
}

int RtcVideoEngineImpl::CreateDataChannel(const DataChannelConfig& config) {
  return backend_->CreateDataChannel(config);
}

int RtcVideoEngineImpl::SendData(int channel_id,
                                 const uint8_t* data,
                                 size_t size,
                                 bool is_binary) {
  if (size > 0 && data == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return backend_->SendData(channel_id, MakeArrayView(data, size), is_binary);
}

int RtcVideoEngineImpl::CloseDataChannel(int channel_id) {
  return backend_->CloseDataChannel(channel_id);
}

// ======================= 隔离队列事件回调分发 =======================

void RtcVideoEngineImpl::OnBackendConnectionState(rtc_connection_state_e state,
                                                  int reason_code) {
  if (observer_ == nullptr) {
    return;
  }
  queues_->callback()->PostTask(
      SafeTask(cb_safety_.flag(), [this, state, reason_code]() {
        RTC_DCHECK_RUN_ON(&cb_checker_);
        observer_->OnConnectionState(state, reason_code);
      }));
}

void RtcVideoEngineImpl::OnBackendTargetTransferRate(
    const TargetTransferRate& rate) {
  const double loss = std::clamp(rate.loss_rate_ratio, 0.0, 0.45);
  double overhead_ratio = 0.0;
  if (config_.transport_mode == RTC_TRANSPORT_MODE_MOQ ||
      config_.transport_mode == RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT) {
    // LOC 封装头 + QUIC 1-RTT 流帧头（约 2.5%）+ ARQ 流重传开销。
    overhead_ratio = 0.025 + (loss / (1.0 - loss));
  } else {
    // RTP 固定头 + RFC 8285 头部扩展 + RTCP TWCC/RR 反馈开销（约 3.0%）。
    constexpr double kRtpHeaderOverhead = 0.030;
    double fec_ratio = 0.0;
    if (config_.enable_flexfec) {
      if (rate.target_rate < DataRate::KilobitsPerSec(200) ||
          (loss < 0.02 && rate.rtt < TimeDelta::Millis(70))) {
        fec_ratio = 0.005;  // 仅分摊稀疏 IDR 关键帧冗余校验开销。
      } else {
        const double rtt_factor =
            (rate.rtt >= TimeDelta::Millis(80)) ? 1.35 : 1.0;
        fec_ratio = std::clamp(loss * 1.4 * rtt_factor, 0.05, 0.40) + 0.01;
      }
    }
    const double rtx_ratio =
        loss * ((config_.enable_flexfec && fec_ratio >= 0.05) ? 0.55 : 1.05);
    overhead_ratio = kRtpHeaderOverhead + fec_ratio + rtx_ratio;
  }

  const VideoBitrateAllocation alloc =
      rate_allocator_.Allocate(rate.target_rate, overhead_ratio);

  for (int i = 0; i < 2; ++i) {
    const SpatialLayer sl =
        (i == 0) ? SpatialLayer::kLow : SpatialLayer::kHigh;
    backend_->SetLayerActive(sl, alloc.layers[i].active);
  }

  if (observer_ == nullptr) {
    return;
  }
  for (int i = 0; i < 2; ++i) {
    if (!use_simulcast_ && i == 0) {
      continue;
    }
    const auto& cur = alloc.layers[i];
    const auto& prev = last_allocation_.layers[i];
    const bool changed =
        !has_last_allocation_ || (cur.active != prev.active) ||
        (cur.target_fps != prev.target_fps) ||
        (std::abs(static_cast<int64_t>(cur.target_bitrate_bps) -
                  static_cast<int64_t>(prev.target_bitrate_bps)) >= 25'000);
    if (changed) {
      const rtc_stream_layer_e c_layer =
          (i == 0) ? RTC_STREAM_LAYER_LOW : RTC_STREAM_LAYER_HIGH;
      queues_->callback()->PostTask(
          SafeTask(cb_safety_.flag(), [this, c_layer, cur]() {
            RTC_DCHECK_RUN_ON(&cb_checker_);
            observer_->OnEncoderBitrateAllocation(
                c_layer, cur.active, cur.target_bitrate_bps, cur.target_fps);
          }));
    }
  }
  last_allocation_ = alloc;
  has_last_allocation_ = true;
}

void RtcVideoEngineImpl::OnBackendForceKeyFrame(SpatialLayer layer) {
  if (observer_ == nullptr) {
    return;
  }
  const rtc_stream_layer_e c_layer =
      (layer == SpatialLayer::kLow) ? RTC_STREAM_LAYER_LOW
                                    : RTC_STREAM_LAYER_HIGH;
  queues_->callback()->PostTask(SafeTask(cb_safety_.flag(), [this, c_layer]() {
    RTC_DCHECK_RUN_ON(&cb_checker_);
    observer_->OnEncoderForceIdr(c_layer);
  }));
}

void RtcVideoEngineImpl::OnBackendRemoteTrackPublished(
    const std::string& peer_id,
    const std::string& track_id,
    VideoCodec codec) {
  if (observer_ == nullptr) {
    return;
  }
  queues_->callback()->PostTask(
      SafeTask(cb_safety_.flag(), [this, peer_id, track_id, codec]() {
        RTC_DCHECK_RUN_ON(&cb_checker_);
        observer_->OnRemoteTrackPublished(
            peer_id, track_id, static_cast<rtc_video_codec_e>(codec));
      }));
}

void RtcVideoEngineImpl::OnBackendRemoteTrackUnpublished(
    const std::string& peer_id,
    const std::string& track_id) {
  if (observer_ == nullptr) {
    return;
  }
  queues_->callback()->PostTask(
      SafeTask(cb_safety_.flag(), [this, peer_id, track_id]() {
        RTC_DCHECK_RUN_ON(&cb_checker_);
        observer_->OnRemoteTrackUnpublished(peer_id, track_id);
      }));
}

void RtcVideoEngineImpl::OnBackendDecodableFrame(const std::string& peer_id,
                                                 const std::string& track_id,
                                                 EncodedVideoFrame frame) {
  if (observer_ == nullptr) {
    return;
  }
  queues_->callback()->PostTask(SafeTask(
      cb_safety_.flag(), [this, peer_id, track_id, f = std::move(frame)]() {
        RTC_DCHECK_RUN_ON(&cb_checker_);
        rtc_encoded_frame_t c_frame{};
        c_frame.data = f.data.data();
        c_frame.size = f.data.size();
        c_frame.capture_ts_us = static_cast<uint64_t>(
            f.capture_time.IsFinite() ? f.capture_time.us() : 0);
        c_frame.is_keyframe = f.dep.is_keyframe;
        c_frame.layer = (f.layer == SpatialLayer::kLow) ? RTC_STREAM_LAYER_LOW
                                                        : RTC_STREAM_LAYER_HIGH;
        c_frame.temporal_id = f.dep.temporal_id;
        c_frame.discardable = f.dep.discardable;
        observer_->OnRemoteEncodedFrame(peer_id, track_id, c_frame);
      }));
}

void RtcVideoEngineImpl::OnBackendStatsSnapshot(
    const rtc_network_stats_t& stats) {
  if (observer_ == nullptr) {
    return;
  }
  queues_->callback()->PostTask(SafeTask(cb_safety_.flag(), [this, stats]() {
    RTC_DCHECK_RUN_ON(&cb_checker_);
    observer_->OnNetworkStats(stats);
  }));
}

void RtcVideoEngineImpl::OnBackendLocalIceCandidate(
    const std::string& sdp_mid,
    int sdp_mline_index,
    const std::string& candidate) {
  if (observer_ == nullptr) {
    return;
  }
  queues_->callback()->PostTask(
      SafeTask(cb_safety_.flag(), [this, sdp_mid, sdp_mline_index, candidate]() {
        RTC_DCHECK_RUN_ON(&cb_checker_);
        observer_->OnLocalIceCandidate(sdp_mid, sdp_mline_index, candidate);
      }));
}

void RtcVideoEngineImpl::OnBackendDataChannelState(
    const std::string& peer_id,
    int channel_id,
    const std::string& label,
    rtc_data_channel_state_e state) {
  if (observer_ == nullptr) {
    return;
  }
  queues_->callback()->PostTask(
      SafeTask(cb_safety_.flag(),
               [this, peer_id, channel_id, label, state]() {
                 RTC_DCHECK_RUN_ON(&cb_checker_);
                 observer_->OnDataChannelState(peer_id, channel_id, label,
                                               state);
               }));
}

void RtcVideoEngineImpl::OnBackendDataChannelMessage(
    const std::string& peer_id,
    int channel_id,
    bool is_binary,
    std::vector<uint8_t> payload) {
  if (observer_ == nullptr) {
    return;
  }
  queues_->callback()->PostTask(SafeTask(
      cb_safety_.flag(),
      [this, peer_id, channel_id, is_binary, buf = std::move(payload)]() {
        RTC_DCHECK_RUN_ON(&cb_checker_);
        static constexpr uint8_t kEmptyByte = 0;
        const uint8_t* ptr = buf.empty() ? &kEmptyByte : buf.data();
        observer_->OnDataChannelMessage(peer_id, channel_id, is_binary, ptr,
                                        buf.size());
      }));
}

}  // namespace rtc

// ======================= 纯 C99 ABI 接口实现 =======================

struct rtc_client_t {
  class CCallbackBridge final : public rtc::IRtcEventObserver {
   public:
    CCallbackBridge(const rtc_callbacks_t* cbs, void* ud) : user_data_(ud) {
      if (cbs != nullptr) {
        callbacks_ = *cbs;
      }
    }

    void OnEncoderBitrateAllocation(rtc_stream_layer_e layer,
                                    bool active,
                                    uint32_t bps,
                                    uint32_t fps) override {
      if (callbacks_.on_encoder_bitrate_allocation != nullptr) {
        callbacks_.on_encoder_bitrate_allocation(user_data_, layer, active, bps,
                                                 fps);
      }
    }
    void OnEncoderForceIdr(rtc_stream_layer_e layer) override {
      if (callbacks_.on_encoder_force_idr != nullptr) {
        callbacks_.on_encoder_force_idr(user_data_, layer);
      }
    }
    void OnRemoteTrackPublished(const std::string& peer_id,
                                const std::string& track_id,
                                rtc_video_codec_e codec) override {
      if (callbacks_.on_remote_track_published != nullptr) {
        callbacks_.on_remote_track_published(user_data_, peer_id.c_str(),
                                             track_id.c_str(), codec);
      }
    }
    void OnRemoteTrackUnpublished(const std::string& peer_id,
                                  const std::string& track_id) override {
      if (callbacks_.on_remote_track_unpublished != nullptr) {
        callbacks_.on_remote_track_unpublished(user_data_, peer_id.c_str(),
                                               track_id.c_str());
      }
    }
    void OnRemoteEncodedFrame(const std::string& peer_id,
                              const std::string& track_id,
                              const rtc_encoded_frame_t& frame) override {
      if (callbacks_.on_remote_encoded_frame != nullptr) {
        callbacks_.on_remote_encoded_frame(user_data_, peer_id.c_str(),
                                           track_id.c_str(), &frame);
      }
    }
    void OnConnectionState(rtc_connection_state_e state,
                           int reason_code) override {
      if (callbacks_.on_connection_state != nullptr) {
        callbacks_.on_connection_state(user_data_, state, reason_code);
      }
    }
    void OnNetworkStats(const rtc_network_stats_t& stats) override {
      if (callbacks_.on_network_stats != nullptr) {
        callbacks_.on_network_stats(user_data_, &stats);
      }
    }
    void OnLocalIceCandidate(const std::string& sdp_mid,
                             int sdp_mline_index,
                             const std::string& candidate) override {
      if (callbacks_.on_local_ice_candidate != nullptr) {
        callbacks_.on_local_ice_candidate(user_data_, sdp_mid.c_str(),
                                          sdp_mline_index, candidate.c_str());
      }
    }
    void OnDataChannelState(const std::string& peer_id,
                            int channel_id,
                            const std::string& label,
                            rtc_data_channel_state_e state) override {
      if (callbacks_.on_data_channel_state != nullptr) {
        callbacks_.on_data_channel_state(user_data_, peer_id.c_str(),
                                         channel_id, label.c_str(), state);
      }
    }
    void OnDataChannelMessage(const std::string& peer_id,
                              int channel_id,
                              bool is_binary,
                              const uint8_t* data,
                              size_t size) override {
      if (callbacks_.on_data_channel_message != nullptr) {
        callbacks_.on_data_channel_message(user_data_, peer_id.c_str(),
                                           channel_id, is_binary, data, size);
      }
    }

   private:
    rtc_callbacks_t callbacks_{};
    void* user_data_ = nullptr;
  };

  std::unique_ptr<CCallbackBridge> bridge;
  std::unique_ptr<rtc::RtcVideoEngine> engine;
};

extern "C" {

void rtc_set_log_level(rtc_log_severity_e min_severity) {
  rtc::LogMessage::SetMinLogSeverity(
      static_cast<rtc::LoggingSeverity>(min_severity));
}

void rtc_enable_stderr_logging(bool enable) {
  rtc::LogMessage::SetLogToStderr(enable);
}

void rtc_set_log_callback(rtc_log_callback_fn callback, void* user_data) {
  rtc::LogMessage::SetCLogCallback(callback, user_data);
}

rtc_client_t* rtc_client_create(const rtc_config_t* cfg,
                                const rtc_callbacks_t* cbs,
                                void* user_data) {
  if (cfg == nullptr) {
    return nullptr;
  }
  rtc::EngineConfig cpp_cfg;
  cpp_cfg.transport_mode = cfg->transport_mode;
  if (cfg->signaling_or_moq_url != nullptr) {
    cpp_cfg.signaling_or_moq_url = cfg->signaling_or_moq_url;
  }
  if (cfg->auth_token != nullptr) {
    cpp_cfg.auth_token = cfg->auth_token;
  }

  const size_t n_ice = std::min<size_t>(cfg->ice_server_count, 4);
  for (size_t i = 0; i < n_ice; ++i) {
    if (cfg->ice_servers[i].uri != nullptr) {
      rtc::IceServerConfig ice;
      ice.uri = cfg->ice_servers[i].uri;
      if (cfg->ice_servers[i].username != nullptr) {
        ice.username = cfg->ice_servers[i].username;
      }
      if (cfg->ice_servers[i].password != nullptr) {
        ice.password = cfg->ice_servers[i].password;
      }
      cpp_cfg.ice_servers.push_back(std::move(ice));
    }
  }

  cpp_cfg.publish_codec =
      (cfg->publish_codec == RTC_CODEC_H265) ? RTC_CODEC_H265 : RTC_CODEC_H264;
  cpp_cfg.enable_simulcast = cfg->enable_simulcast;
  cpp_cfg.enable_flexfec = cfg->enable_flexfec;
  cpp_cfg.zero_playout_delay = cfg->zero_playout_delay;
  cpp_cfg.enable_datachannel = !cfg->disable_datachannel;
  if (cfg->min_bitrate_bps > 0) {
    cpp_cfg.min_bitrate_bps = cfg->min_bitrate_bps;
  }
  if (cfg->start_bitrate_bps > 0) {
    cpp_cfg.start_bitrate_bps = cfg->start_bitrate_bps;
  }
  if (cfg->max_bitrate_bps > 0) {
    cpp_cfg.max_bitrate_bps = cfg->max_bitrate_bps;
  }
  if (cfg->low_layer_max_bps > 0) {
    cpp_cfg.low_layer_max_bps = cfg->low_layer_max_bps;
  }
  if (cfg->moq_delivery_timeout_ms > 0) {
    cpp_cfg.moq_delivery_timeout_ms = cfg->moq_delivery_timeout_ms;
  }
  cpp_cfg.quic_cc_algo = cfg->quic_cc_algo;

  auto* handle = new rtc_client_t();
  handle->bridge =
      std::make_unique<rtc_client_t::CCallbackBridge>(cbs, user_data);
  handle->engine = rtc::RtcVideoEngine::Create(cpp_cfg, handle->bridge.get());
  return handle;
}

int rtc_client_join_room(rtc_client_t* client,
                         const char* room_id,
                         const char* local_peer_id) {
  if (client == nullptr || room_id == nullptr || local_peer_id == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->JoinRoom(room_id, local_peer_id);
}

int rtc_client_leave_room(rtc_client_t* client) {
  if (client == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->LeaveRoom();
}

void rtc_client_destroy(rtc_client_t* client) { delete client; }

int rtc_client_push_video_frame(rtc_client_t* client,
                                const rtc_encoded_frame_t* frame) {
  if (client == nullptr || frame == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->PushVideoFrame(*frame);
}

int rtc_client_subscribe_track(rtc_client_t* client,
                               const char* remote_track_id,
                               rtc_stream_layer_e preferred_layer) {
  if (client == nullptr || remote_track_id == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->SubscribeTrack(remote_track_id, preferred_layer);
}

int rtc_client_switch_subscribed_layer(rtc_client_t* client,
                                       const char* remote_track_id,
                                       rtc_stream_layer_e preferred_layer) {
  if (client == nullptr || remote_track_id == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->SwitchSubscribedLayer(remote_track_id,
                                               preferred_layer);
}

int rtc_client_unsubscribe_track(rtc_client_t* client,
                                 const char* remote_track_id) {
  if (client == nullptr || remote_track_id == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->UnsubscribeTrack(remote_track_id);
}

int rtc_client_request_remote_idr(rtc_client_t* client,
                                  const char* remote_track_id) {
  if (client == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->RequestRemoteIdr(
      remote_track_id != nullptr ? remote_track_id : "");
}

int rtc_client_set_quic_cc_algo(rtc_client_t* client, rtc_quic_cc_algo_e algo) {
  if (client == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->SetQuicCongestionControl(algo);
}

const char* rtc_quic_cc_algo_name(rtc_quic_cc_algo_e algo) {
  switch (algo) {
    case RTC_QUIC_CC_BBR:
      return "BBRv1";
    case RTC_QUIC_CC_BBR2:
      return "BBRv2";
    case RTC_QUIC_CC_CUBIC:
      return "CUBIC";
    case RTC_QUIC_CC_COPA:
      return "Copa";
    case RTC_QUIC_CC_NEWRENO:
      return "NewReno";
    default:
      return "Unknown";
  }
}

int rtc_client_create_offer(rtc_client_t* client,
                            char* out_sdp_buf,
                            size_t out_sdp_capacity) {
  if (client == nullptr || out_sdp_buf == nullptr || out_sdp_capacity == 0) {
    return RTC_ERR_INVALID_ARG;
  }
  std::string sdp;
  const int rc = client->engine->CreateLocalOffer(&sdp);
  if (rc != RTC_OK) {
    return rc;
  }
  if (sdp.size() + 1 > out_sdp_capacity) {
    return RTC_ERR_NO_MEMORY;
  }
  std::memcpy(out_sdp_buf, sdp.data(), sdp.size() + 1);
  return RTC_OK;
}

int rtc_client_set_remote_description(rtc_client_t* client,
                                      const char* sdp_type,
                                      const char* remote_sdp,
                                      char* out_answer_buf,
                                      size_t out_answer_capacity) {
  if (client == nullptr || sdp_type == nullptr || remote_sdp == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  std::string answer_sdp;
  const int rc = client->engine->SetRemoteDescription(
      sdp_type, remote_sdp, out_answer_buf != nullptr ? &answer_sdp : nullptr);
  if (rc != RTC_OK) {
    return rc;
  }
  if (out_answer_buf != nullptr && std::strcmp(sdp_type, "offer") == 0) {
    if (answer_sdp.size() + 1 > out_answer_capacity) {
      return RTC_ERR_NO_MEMORY;
    }
    std::memcpy(out_answer_buf, answer_sdp.data(), answer_sdp.size() + 1);
  }
  return RTC_OK;
}

int rtc_client_add_remote_ice_candidate(rtc_client_t* client,
                                        const char* candidate_sdp) {
  if (client == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->AddRemoteIceCandidate(
      candidate_sdp != nullptr ? candidate_sdp : "");
}

void rtc_data_channel_init_default(rtc_data_channel_init_t* init,
                                   const char* label) {
  if (init == nullptr) {
    return;
  }
  std::memset(init, 0, sizeof(*init));
  init->label = (label != nullptr) ? label : "data";
  init->protocol = "";
  init->ordered = true;
  init->max_retransmits = -1;
  init->max_packet_lifetime_ms = -1;
  init->negotiated = false;
  init->id = -1;
}

int rtc_client_create_data_channel(rtc_client_t* client,
                                   const rtc_data_channel_init_t* init) {
  if (client == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  rtc::DataChannelConfig cfg;
  if (init != nullptr) {
    if (init->label != nullptr) {
      cfg.label = init->label;
    }
    if (init->protocol != nullptr) {
      cfg.protocol = init->protocol;
    }
    cfg.ordered = init->ordered;
    cfg.max_retransmits = init->max_retransmits;
    cfg.max_packet_lifetime_ms = init->max_packet_lifetime_ms;
    cfg.negotiated = init->negotiated;
    cfg.id = init->id;
  }
  return client->engine->CreateDataChannel(cfg);
}

int rtc_client_send_data(rtc_client_t* client,
                         int channel_id,
                         const uint8_t* data,
                         size_t size,
                         bool is_binary) {
  if (client == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->SendData(channel_id, data, size, is_binary);
}

int rtc_client_close_data_channel(rtc_client_t* client, int channel_id) {
  if (client == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  return client->engine->CloseDataChannel(channel_id);
}

}  // extern "C"