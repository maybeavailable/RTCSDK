#include "sdk/rtc_video_engine_impl.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <new>

#include "call/webrtc_p2p_backend.h"
#include "moq/moq_transport.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {

SimulcastAllocatorConfig MakeSafeAllocatorConfig(const EngineConfig& config,
                                                 bool use_simulcast) {
  const uint32_t min_total = std::max<uint32_t>(30'000, config.min_bitrate_bps);
  const uint32_t max_total = std::max<uint32_t>(min_total, config.max_bitrate_bps);
  const uint32_t low_max =
      std::clamp<uint32_t>(config.low_layer_max_bps, 60'000, max_total);
  const uint32_t low_min = std::min<uint32_t>(120'000, low_max);
  return SimulcastAllocatorConfig{
      use_simulcast, min_total, low_min, low_max, 400'000, 80'000, max_total};
}

}  // namespace

std::unique_ptr<RtcVideoEngine> RtcVideoEngine::Create(
    const EngineConfig& config,
    IRtcEventObserver* observer,
    std::shared_ptr<IMoqQuicEngine> custom_moq_quic_engine) {
  if (config.publish_codec != RTC_CODEC_H264 &&
      config.publish_codec != RTC_CODEC_H265) {
    RTC_LOG(kError) << "RtcVideoEngine::Create failed: unsupported codec="
                    << static_cast<int>(config.publish_codec);
    return nullptr;
  }
  if (config.transport_mode != RTC_TRANSPORT_MODE_WEBRTC_P2P &&
      config.transport_mode != RTC_TRANSPORT_MODE_MOQ &&
      config.transport_mode != RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT) {
    RTC_LOG(kError) << "RtcVideoEngine::Create failed: invalid transport_mode="
                    << static_cast<int>(config.transport_mode);
    return nullptr;
  }
  try {
    return std::make_unique<RtcVideoEngineImpl>(
        config, observer, std::move(custom_moq_quic_engine));
  } catch (const std::bad_alloc&) {
    RTC_LOG(kError) << "RtcVideoEngine::Create failed: out of memory";
    return nullptr;
  }
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
      rate_allocator_(MakeSafeAllocatorConfig(config, use_simulcast_)),
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
  std::lock_guard<std::mutex> lock(lifecycle_mu_);
  if (joined_.load(std::memory_order_acquire) ||
      direct_sdp_active_.load(std::memory_order_acquire)) {
    return RTC_ERR_ALREADY_CONNECTED;
  }
  joined_.store(true, std::memory_order_release);
  const int rc = backend_->StartSession(room_id, local_peer_id);
  if (rc != RTC_OK) {
    joined_.store(false, std::memory_order_release);
  }
  return rc;
}

int RtcVideoEngineImpl::LeaveRoom() {
  std::lock_guard<std::mutex> lock(lifecycle_mu_);
  const bool was_joined = joined_.exchange(false, std::memory_order_acq_rel);
  const bool was_direct =
      direct_sdp_active_.exchange(false, std::memory_order_acq_rel);
  if (!was_joined && !was_direct) {
    return RTC_OK;
  }
  RTC_LOG(kInfo) << "Leaving session";
  if (backend_) {
    backend_->StopSession();
  }
  {
    std::lock_guard<std::mutex> bwe_lock(bwe_alloc_mu_);
    has_last_allocation_ = false;
    last_allocation_ = VideoBitrateAllocation{};
  }
  return RTC_OK;
}

int RtcVideoEngineImpl::PushVideoFrame(const rtc_encoded_frame_t& frame) {
  if (frame.data == nullptr || frame.size == 0) {
    return RTC_ERR_INVALID_ARG;
  }
  if (config_.publish_codec != RTC_CODEC_H264 &&
      config_.publish_codec != RTC_CODEC_H265) {
    return RTC_ERR_CODEC_UNSUPPORTED;
  }
  if (!joined_.load(std::memory_order_acquire) &&
      !direct_sdp_active_.load(std::memory_order_acquire)) {
    return RTC_ERR_NOT_CONNECTED;
  }
  // WebRTC P2P 单 SSRC 模式下若业务同时开启了双码流（enable_simulcast=true），
  // 忽略低清子码流帧，避免双分辨率 SPS/PPS 与参考帧交织污染同一 SSRC。
  if (!use_simulcast_ && config_.enable_simulcast &&
      frame.layer == RTC_STREAM_LAYER_LOW) {
    return RTC_OK;
  }

  constexpr uint64_t kMaxSafeCaptureUs =
      static_cast<uint64_t>(std::numeric_limits<int64_t>::max() - 1);
  const uint64_t clamped_ts_us = std::min(frame.capture_ts_us, kMaxSafeCaptureUs);

  EncodedVideoFrame internal;
  internal.data.assign(frame.data, frame.data + frame.size);
  internal.capture_time =
      Timestamp::Micros(static_cast<int64_t>(clamped_ts_us));
  internal.rtp_timestamp = MicrosToRtp90kHzU64(frame.capture_ts_us);
  internal.codec = static_cast<VideoCodec>(config_.publish_codec);
  internal.layer =
      (use_simulcast_ && frame.layer == RTC_STREAM_LAYER_LOW)
          ? SpatialLayer::kLow
          : SpatialLayer::kHigh;
  internal.dep.is_keyframe = frame.is_keyframe;
  internal.dep.spatial_id = static_cast<uint8_t>(internal.layer);
  internal.dep.temporal_id = frame.is_keyframe ? 0 : frame.temporal_id;
  internal.dep.discardable = frame.is_keyframe ? false : frame.discardable;

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
  if (out_sdp == nullptr) {
    return RTC_ERR_INVALID_ARG;
  }
  std::lock_guard<std::mutex> lock(lifecycle_mu_);
  if (joined_.load(std::memory_order_acquire) &&
      !config_.signaling_or_moq_url.empty()) {
    return RTC_ERR_ALREADY_CONNECTED;
  }
  const int rc = backend_->CreateLocalOffer(out_sdp);
  if (rc == RTC_OK) {
    direct_sdp_active_.store(true, std::memory_order_release);
  }
  return rc;
}

int RtcVideoEngineImpl::SetRemoteDescription(std::string_view sdp_type,
                                             std::string_view remote_sdp,
                                             std::string* out_answer_sdp) {
  if (sdp_type.empty() || remote_sdp.empty()) {
    return RTC_ERR_INVALID_ARG;
  }
  std::lock_guard<std::mutex> lock(lifecycle_mu_);
  if (joined_.load(std::memory_order_acquire) &&
      !config_.signaling_or_moq_url.empty()) {
    return RTC_ERR_ALREADY_CONNECTED;
  }
  const int rc =
      backend_->SetRemoteDescription(sdp_type, remote_sdp, out_answer_sdp);
  if (rc == RTC_OK) {
    direct_sdp_active_.store(true, std::memory_order_release);
  }
  return rc;
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
  const double raw_loss =
      std::isnan(rate.loss_rate_ratio) ? 0.0 : rate.loss_rate_ratio;
  const double loss = std::clamp(raw_loss, 0.0, 0.45);
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

  VideoBitrateAllocation alloc;
  bool notify_layers[2] = {false, false};
  {
    std::lock_guard<std::mutex> bwe_lock(bwe_alloc_mu_);
    alloc = rate_allocator_.Allocate(rate.target_rate, overhead_ratio);
    for (int i = 0; i < 2; ++i) {
      if (!use_simulcast_ && i == 0) {
        continue;
      }
      const auto& cur = alloc.layers[i];
      const auto& prev = last_allocation_.layers[i];
      notify_layers[i] =
          !has_last_allocation_ || (cur.active != prev.active) ||
          (cur.target_fps != prev.target_fps) ||
          (std::abs(static_cast<int64_t>(cur.target_bitrate_bps) -
                    static_cast<int64_t>(prev.target_bitrate_bps)) >= 25'000);
    }
    last_allocation_ = alloc;
    has_last_allocation_ = true;
    for (int i = 0; i < 2; ++i) {
      const SpatialLayer sl =
          (i == 0) ? SpatialLayer::kLow : SpatialLayer::kHigh;
      backend_->SetLayerActive(sl, alloc.layers[i].active);
    }
  }

  if (observer_ == nullptr) {
    return;
  }
  for (int i = 0; i < 2; ++i) {
    if (notify_layers[i]) {
      const auto cur = alloc.layers[i];
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