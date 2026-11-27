// C++17 IETF MoQ 多路拉流 SDK 完整使用示例（`cpp17_moq_multipull_full_demo.cc`）
//
// 基于 `Boost.Asio` QUIC v1 与 `EmbeddedMoqRelayServer`，100% 覆盖测试
// `rtc_video_engine.hpp` 中的 C++17 IETF MoQ API 接口：
//   - 2 路 Simulcast 摄像头推流端（`cam_front_h265` 与 `cam_rear_h264`，包含
//     `LOW` + `HIGH` 空间层及 SVC `temporal_id` / `discardable` 元数据）
//   - 1 个多路拉流控制台（`nvr_console`），在模拟 UDP 丢包环境下通过单条 QUIC v1
//     连接并发订阅两路摄像头（`SubscribeTrack`）
//   - 动态 GOP 对齐的 Simulcast 空间层切换（`SwitchSubscribedLayer`）
//   - 上行 IDR 关键帧请求（`RequestRemoteIdr`）、周期性网络遥测回调
//     （`OnNetworkStats`）、取消轨道订阅（`UnsubscribeTrack`）以及远端轨道
//     离线事件回调（`OnRemoteTrackUnpublished`）

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "rtc_base/logging.h"
#include "rtc_video_engine.hpp"
#include "server/embedded_moq_relay.h"

namespace {

class CameraPublisherObserver final : public rtc::IRtcEventObserver {
 public:
  explicit CameraPublisherObserver(std::string name) : name_(std::move(name)) {}

  CameraPublisherObserver(const CameraPublisherObserver&) = delete;
  CameraPublisherObserver& operator=(const CameraPublisherObserver&) = delete;

  void OnEncoderBitrateAllocation(rtc_stream_layer_e layer,
                                  bool layer_active,
                                  uint32_t target_bitrate_bps,
                                  uint32_t target_fps) override {
    std::lock_guard<std::mutex> lock(mutex_);
    ++bwe_cbs_;
    RTC_LOG(kInfo) << "[" << name_ << "] VENC layer="
                   << (layer == RTC_STREAM_LAYER_HIGH ? "HIGH" : "LOW")
                   << " active=" << layer_active
                   << " target_kbps=" << (target_bitrate_bps / 1000)
                   << " fps=" << target_fps;
  }

  void OnEncoderForceIdr(rtc_stream_layer_e layer) override {
    std::lock_guard<std::mutex> lock(mutex_);
    force_idr_[layer] = true;
  }

  void OnRemoteTrackPublished(const std::string& /*peer_id*/,
                              const std::string& /*track_id*/,
                              rtc_video_codec_e /*codec*/) override {}

  void OnRemoteTrackUnpublished(const std::string& /*peer_id*/,
                                const std::string& /*track_id*/) override {}

  void OnRemoteEncodedFrame(const std::string& /*peer_id*/,
                            const std::string& /*track_id*/,
                            const rtc_encoded_frame_t& /*frame*/) override {}

  void OnConnectionState(rtc_connection_state_e state,
                         int /*reason_code*/) override {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state == RTC_CONN_STATE_CONNECTED) {
      connected_ = true;
      cv_.notify_all();
    }
  }

  void OnNetworkStats(const rtc_network_stats_t& /*stats*/) override {
    std::lock_guard<std::mutex> lock(mutex_);
    ++stats_cbs_;
  }

  bool WaitConnected(int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                        [this]() { return connected_; });
  }

  bool ConsumeForceIdr(rtc_stream_layer_e layer) {
    std::lock_guard<std::mutex> lock(mutex_);
    const bool v = force_idr_[layer];
    force_idr_[layer] = false;
    return v;
  }

 private:
  const std::string name_;
  std::mutex mutex_;
  std::condition_variable cv_;
  bool connected_ = false;
  bool force_idr_[2]{false, false};
  uint32_t bwe_cbs_ = 0;
  uint32_t stats_cbs_ = 0;
};

class MultiPullConsoleObserver final : public rtc::IRtcEventObserver {
 public:
  struct PullTrackStats {
    uint32_t frames = 0;
    size_t bytes = 0;
    rtc_stream_layer_e last_layer = RTC_STREAM_LAYER_HIGH;
  };

  void OnEncoderBitrateAllocation(rtc_stream_layer_e /*layer*/,
                                  bool /*layer_active*/,
                                  uint32_t /*target_bitrate_bps*/,
                                  uint32_t /*target_fps*/) override {}

  void OnEncoderForceIdr(rtc_stream_layer_e /*layer*/) override {}

  void OnRemoteTrackPublished(const std::string& peer_id,
                              const std::string& track_id,
                              rtc_video_codec_e codec) override {
    std::lock_guard<std::mutex> lock(mutex_);
    published_tracks_[track_id] = codec;
    RTC_LOG(kInfo) << "[NVR-Console] Remote camera online: peer=" << peer_id
                   << " track=" << track_id
                   << " codec=" << (codec == RTC_CODEC_H265 ? "H265" : "H264");
    cv_.notify_all();
  }

  void OnRemoteTrackUnpublished(const std::string& /*peer_id*/,
                                const std::string& track_id) override {
    std::lock_guard<std::mutex> lock(mutex_);
    ++unpublished_count_;
    RTC_LOG(kInfo) << "[NVR-Console] Remote camera offline: track=" << track_id;
    cv_.notify_all();
  }

  void OnRemoteEncodedFrame(const std::string& /*peer_id*/,
                            const std::string& track_id,
                            const rtc_encoded_frame_t& frame) override {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& st = stats_by_track_[track_id];
    ++st.frames;
    st.bytes += frame.size;
    st.last_layer = frame.layer;
    cv_.notify_all();
  }

  void OnConnectionState(rtc_connection_state_e state,
                         int /*reason_code*/) override {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state == RTC_CONN_STATE_CONNECTED) {
      connected_ = true;
      cv_.notify_all();
    }
  }

  void OnNetworkStats(const rtc_network_stats_t& /*stats*/) override {
    std::lock_guard<std::mutex> lock(mutex_);
    ++stats_cbs_;
    cv_.notify_all();
  }

  void OnDataChannelMessage(const std::string& peer_id,
                            int /*channel_id*/,
                            bool /*is_binary*/,
                            const uint8_t* data,
                            size_t size) override {
    std::lock_guard<std::mutex> lock(mutex_);
    ++dc_messages_rx_;
    RTC_LOG(kInfo) << "[NVR-Console] MoQ DataChannel RX from " << peer_id
                   << ": "
                   << std::string(reinterpret_cast<const char*>(data), size);
    cv_.notify_all();
  }

  bool WaitConnected(int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                        [this]() { return connected_; });
  }

  bool WaitTracksDiscovered(const std::string& track_a,
                            const std::string& track_b,
                            int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                        [this, &track_a, &track_b]() {
                          return published_tracks_.count(track_a) > 0 &&
                                 published_tracks_.count(track_b) > 0;
                        });
  }

  bool WaitBothTracksDecoded(const std::string& track_a,
                             const std::string& track_b,
                             uint32_t min_frames_each,
                             int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(
        lock, std::chrono::milliseconds(timeout_ms),
        [this, &track_a, &track_b, min_frames_each]() {
          return stats_by_track_[track_a].frames >= min_frames_each &&
                 stats_by_track_[track_b].frames >= min_frames_each;
        });
  }

  bool WaitTrackUnpublished(int timeout_ms = 3000) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                        [this]() { return unpublished_count_ > 0; });
  }

  PullTrackStats GetStats(const std::string& track_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = stats_by_track_.find(track_id);
    return (it != stats_by_track_.end()) ? it->second : PullTrackStats{};
  }

  uint32_t stats_cbs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_cbs_;
  }
  uint32_t dc_messages_rx() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dc_messages_rx_;
  }

 private:
  mutable std::mutex mutex_;
  std::condition_variable cv_;
  bool connected_ = false;
  uint32_t unpublished_count_ = 0;
  uint32_t stats_cbs_ = 0;
  uint32_t dc_messages_rx_ = 0;
  std::map<std::string, rtc_video_codec_e> published_tracks_;
  std::map<std::string, PullTrackStats> stats_by_track_;
};

std::vector<uint8_t> BuildAnnexBFrame(rtc_video_codec_e codec,
                                      bool is_idr,
                                      size_t body_bytes) {
  std::vector<uint8_t> out;
  if (codec == RTC_CODEC_H265) {
    if (is_idr) {
      const uint8_t hdr[] = {
          0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01,
          0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x60,
          0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xC1, 0x73,
          0x00, 0x00, 0x00, 0x01, 0x26, 0x01};
      out.insert(out.end(), hdr, hdr + sizeof(hdr));
    } else {
      const uint8_t hdr[] = {0x00, 0x00, 0x00, 0x01, 0x02, 0x01};
      out.insert(out.end(), hdr, hdr + sizeof(hdr));
    }
  } else {
    if (is_idr) {
      const uint8_t hdr[] = {
          0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xE0, 0x1F,
          0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80,
          0x00, 0x00, 0x00, 0x01, 0x65, 0x88};
      out.insert(out.end(), hdr, hdr + sizeof(hdr));
    } else {
      const uint8_t hdr[] = {0x00, 0x00, 0x00, 0x01, 0x41, 0x9A};
      out.insert(out.end(), hdr, hdr + sizeof(hdr));
    }
  }
  out.resize(out.size() + body_bytes, 0x7E);
  return out;
}

// 用户自定义 QUIC 拥塞控制器插件，演示支持热插拔的
// `IQuicCongestionController` 与 `IQuicCongestionControllerFactory` 扩展接口。
class CustomLowLatencyDroneCc final : public rtc::IQuicCongestionController {
 public:
  explicit CustomLowLatencyDroneCc(size_t mss)
      : mss_(mss), cwnd_bytes_(12 * mss) {}

  std::string_view Name() const override { return "CustomDroneCC"; }

  void OnPacketSent(int64_t /*now_us*/,
                    uint64_t /*pn*/,
                    size_t /*bytes*/,
                    bool /*in_flight*/,
                    size_t /*prior_in_flight*/) override {}

  void OnCongestionEvent(
      int64_t /*now_us*/,
      size_t /*prior_in_flight_bytes*/,
      size_t /*bytes_in_flight*/,
      const rtc::QuicRttSample& rtt,
      const std::vector<rtc::QuicAckedPacket>& acked_packets,
      const std::vector<rtc::QuicLostPacket>& lost_packets) override {
    if (rtt.smoothed_rtt_us > 0) {
      smoothed_rtt_us_ = rtt.smoothed_rtt_us;
    }
    if (!lost_packets.empty()) {
      cwnd_bytes_ = std::max(4 * mss_, (cwnd_bytes_ * 4) / 5);
    } else {
      for (const auto& p : acked_packets) {
        cwnd_bytes_ = std::min<size_t>(2 * 1024 * 1024, cwnd_bytes_ + p.bytes / 2);
      }
    }
  }

  void OnPersistentCongestion(int64_t /*now_us*/) override {
    cwnd_bytes_ = 4 * mss_;
  }

  size_t GetCongestionWindowBytes() const override { return cwnd_bytes_; }

  int64_t GetPacingRateBps(int64_t smoothed_rtt_us) const override {
    const int64_t rtt = std::max<int64_t>(
        2000, smoothed_rtt_us > 0 ? smoothed_rtt_us : smoothed_rtt_us_);
    return static_cast<int64_t>(
        (static_cast<double>(cwnd_bytes_) * 8'000'000.0 * 1.15) /
        static_cast<double>(rtt));
  }

  int64_t GetBandwidthEstimateBps() const override {
    const int64_t rtt = std::max<int64_t>(2000, smoothed_rtt_us_);
    return (static_cast<int64_t>(cwnd_bytes_) * 8'000'000) / rtt;
  }

  size_t GetSlowStartThresholdBytes() const override { return cwnd_bytes_; }

  rtc::QuicCcMigrationState ExportMigrationState() const override {
    rtc::QuicCcMigrationState st;
    st.cwnd_bytes = cwnd_bytes_;
    st.ssthresh_bytes = cwnd_bytes_;
    st.bandwidth_estimate_bps = GetBandwidthEstimateBps();
    st.smoothed_rtt_us = smoothed_rtt_us_;
    return st;
  }

  void ImportMigrationState(const rtc::QuicCcMigrationState& state,
                            int64_t /*now_us*/) override {
    cwnd_bytes_ = std::max(4 * mss_, state.cwnd_bytes);
    if (state.smoothed_rtt_us > 0) {
      smoothed_rtt_us_ = state.smoothed_rtt_us;
    }
  }

 private:
  size_t mss_;
  size_t cwnd_bytes_;
  int64_t smoothed_rtt_us_ = 25'000;
};

class CustomLowLatencyDroneCcFactory final
    : public rtc::IQuicCongestionControllerFactory {
 public:
  std::unique_ptr<rtc::IQuicCongestionController> Create(
      size_t max_datagram_size) override {
    return std::make_unique<CustomLowLatencyDroneCc>(max_datagram_size);
  }
};

}  // namespace

int main(int argc, char** argv) {
  rtc::RtcVideoEngine::SetMinLogSeverity(rtc::LoggingSeverity::kInfo);
  rtc::RingBufferLogSink diag_ring(128);
  rtc::RtcVideoEngine::AddLogSink(&diag_ring, rtc::LoggingSeverity::kInfo);
  struct LogSinkGuard {
    rtc::LogSink* sink;
    ~LogSinkGuard() { rtc::RtcVideoEngine::RemoveLogSink(sink); }
  } sink_guard{&diag_ring};

  std::string relay_url;
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::string_view(argv[i]) == "--relay") {
      relay_url = argv[i + 1];
    }
  }

  std::unique_ptr<rtc::EmbeddedMoqRelayServer> local_relay;
  if (relay_url.empty()) {
    local_relay = std::make_unique<rtc::EmbeddedMoqRelayServer>("127.0.0.1");
    if (!local_relay->Start(0)) {
      RTC_LOG(kError) << "Failed to start local EmbeddedMoqRelayServer";
      return 1;
    }
    local_relay->SetSimulatedDropRates(0.02, 0.05);
    relay_url = "moq://127.0.0.1:" + std::to_string(local_relay->udp_port());
  }

  rtc::EngineConfig pull_cfg;
  pull_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
  pull_cfg.signaling_or_moq_url = relay_url;
  pull_cfg.zero_playout_delay = true;

  MultiPullConsoleObserver console_obs;
  auto console_engine = rtc::RtcVideoEngine::Create(pull_cfg, &console_obs);
  if (console_engine->JoinRoom("fleet_room", "nvr_console") != RTC_OK ||
      !console_obs.WaitConnected()) {
    return 2;
  }

  rtc::EngineConfig cam1_cfg = pull_cfg;
  cam1_cfg.publish_codec = RTC_CODEC_H265;
  cam1_cfg.enable_simulcast = true;
  cam1_cfg.moq_delivery_timeout_ms = 400;
  cam1_cfg.quic_cc_algo = RTC_QUIC_CC_BBR2;

  rtc::EngineConfig cam2_cfg = cam1_cfg;
  cam2_cfg.publish_codec = RTC_CODEC_H264;
  cam2_cfg.quic_cc_algo = RTC_QUIC_CC_CUBIC;

  CameraPublisherObserver cam1_obs("CamFront-H265");
  CameraPublisherObserver cam2_obs("CamRear-H264");
  auto cam1_engine = rtc::RtcVideoEngine::Create(cam1_cfg, &cam1_obs);
  auto cam2_engine = rtc::RtcVideoEngine::Create(cam2_cfg, &cam2_obs);

  cam1_engine->JoinRoom("fleet_room", "cam_front_h265");
  cam2_engine->JoinRoom("fleet_room", "cam_rear_h264");
  if (!cam1_obs.WaitConnected() || !cam2_obs.WaitConnected()) {
    return 3;
  }

  if (!console_obs.WaitTracksDiscovered("cam_front_h265", "cam_rear_h264")) {
    return 4;
  }
  console_engine->SubscribeTrack("cam_front_h265", RTC_STREAM_LAYER_HIGH);
  console_engine->SubscribeTrack("cam_rear_h264", RTC_STREAM_LAYER_LOW);
  std::this_thread::sleep_for(std::chrono::milliseconds(40));

  uint64_t ts_us = 1'000'000;
  rtc::DataChannelConfig moq_dc_cfg;
  moq_dc_cfg.label = "ai_bbox_meta";
  moq_dc_cfg.ordered = true;
  const int cam1_dc = cam1_engine->CreateDataChannel(moq_dc_cfg);
  cam1_engine->SendTextData(cam1_dc, "{\"obj\":\"person\",\"conf\":0.98}");

  for (int f = 0; f < 28; ++f) {
    const bool gop_boundary = (f % 8) == 0;
    const uint8_t tid = (f % 2 == 0) ? 0 : 1;

    auto push_dual_layer = [&](rtc::RtcVideoEngine* eng,
                               CameraPublisherObserver* obs,
                               rtc_video_codec_e codec) {
      const bool low_idr =
          gop_boundary || obs->ConsumeForceIdr(RTC_STREAM_LAYER_LOW);
      const bool high_idr =
          gop_boundary || obs->ConsumeForceIdr(RTC_STREAM_LAYER_HIGH);

      const auto low_bytes =
          BuildAnnexBFrame(codec, low_idr, low_idr ? 1400 : 480);
      const auto high_bytes =
          BuildAnnexBFrame(codec, high_idr, high_idr ? 4800 : 1600);

      rtc_encoded_frame_t low_f{};
      low_f.data = low_bytes.data();
      low_f.size = low_bytes.size();
      low_f.capture_ts_us = ts_us;
      low_f.is_keyframe = low_idr;
      low_f.layer = RTC_STREAM_LAYER_LOW;
      low_f.temporal_id = low_idr ? 0 : tid;
      low_f.discardable = (!low_idr && tid > 0);
      eng->PushVideoFrame(low_f);

      rtc_encoded_frame_t high_f = low_f;
      high_f.data = high_bytes.data();
      high_f.size = high_bytes.size();
      high_f.is_keyframe = high_idr;
      high_f.layer = RTC_STREAM_LAYER_HIGH;
      eng->PushVideoFrame(high_f);
    };

    push_dual_layer(cam1_engine.get(), &cam1_obs, RTC_CODEC_H265);
    push_dual_layer(cam2_engine.get(), &cam2_obs, RTC_CODEC_H264);

    if (f == 6) {
      // 在实时流传输期间对推流端及中继服务器运行时热切换内置 QUIC 拥塞控制算法。
      cam1_engine->SetQuicCongestionControl(RTC_QUIC_CC_COPA);
      cam2_engine->SetQuicCongestionControl(RTC_QUIC_CC_NEWRENO);
      if (local_relay) {
        local_relay->SetQuicCongestionControl(RTC_QUIC_CC_BBR2);
      }
    }
    if (f == 9) {
      RTC_LOG(kInfo) << "[NVR-Console] Swapping main/PIP layout & requesting "
                     << "IDR: cam_front_h265 -> LOW, cam_rear_h264 -> HIGH";
      console_engine->SwitchSubscribedLayer("cam_front_h265",
                                            RTC_STREAM_LAYER_LOW);
      console_engine->SwitchSubscribedLayer("cam_rear_h264",
                                            RTC_STREAM_LAYER_HIGH);
      console_engine->RequestRemoteIdr("cam_front_h265");
    }
    if (f == 16) {
      // 在推流中途热插拔外部自定义的 `IQuicCongestionController` 拥塞控制模块！
      cam1_engine->SetCustomQuicCongestionController(
          std::make_shared<CustomLowLatencyDroneCcFactory>());
      cam2_engine->SetQuicCongestionControl(RTC_QUIC_CC_BBR);
    }

    ts_us += 33'333;
    std::this_thread::sleep_for(std::chrono::milliseconds(22));
  }

  const bool decoded_ok =
      console_obs.WaitBothTracksDecoded("cam_front_h265", "cam_rear_h264", 18);

  // 取消订阅后置摄像头并让前置摄像头离开房间，以验证 UNANNOUNCE 取消发布通知
  console_engine->UnsubscribeTrack("cam_rear_h264");
  cam1_engine->LeaveRoom();
  const bool unpub_ok = console_obs.WaitTrackUnpublished();

  const auto front_stats = console_obs.GetStats("cam_front_h265");
  const auto rear_stats = console_obs.GetStats("cam_rear_h264");
  const auto snapshot = diag_ring.Snapshot();

  RTC_LOG(kInfo) << "=== C++17 MoQ Multi-Pull Full Demo Summary: front="
                 << front_stats.frames << " (layer="
                 << (front_stats.last_layer == RTC_STREAM_LAYER_LOW ? "LOW"
                                                                    : "HIGH")
                 << "), rear=" << rear_stats.frames << " (layer="
                 << (rear_stats.last_layer == RTC_STREAM_LAYER_LOW ? "LOW"
                                                                   : "HIGH")
                 << "), stats_cbs=" << console_obs.stats_cbs()
                 << ", ring_snapshot=" << snapshot.size() << " ===";

  console_engine->UnsubscribeTrack("cam_front_h265");
  console_engine->LeaveRoom();
  cam2_engine->LeaveRoom();
  if (local_relay) {
    local_relay->Stop();
  }
  rtc::RtcVideoEngine::RemoveLogSink(&diag_ring);

  const bool passed = decoded_ok && unpub_ok &&
                      front_stats.last_layer == RTC_STREAM_LAYER_LOW &&
                      rear_stats.last_layer == RTC_STREAM_LAYER_HIGH &&
                      console_obs.dc_messages_rx() > 0 &&
                      console_obs.stats_cbs() > 0 && !snapshot.empty();
  return passed ? 0 : 5;
}
