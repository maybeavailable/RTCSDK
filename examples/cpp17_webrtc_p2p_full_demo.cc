// C++17 WebRTC P2P SDK 完整使用示例（`cpp17_webrtc_p2p_full_demo.cc`）
//
// 100% 覆盖测试 `rtc_video_engine.hpp` 中的 C++17 WebRTC P2P API 接口：
//   - 自定义 `rtc::LogSink`、`RingBufferLogSink`、`SetMinLogSeverity`、
//     `SetLogToStderr` 以及防御性错误码校验
//   - 场景 A：无信令服务器直连 W3C SDP 与 Trickle-ICE 双向 P2P 传输
//     （H.264 编码，涵盖 `CreateLocalOffer`、`SetRemoteDescription`、
//     `AddRemoteIceCandidate`、`OnLocalIceCandidate` 与 `RequestRemoteIdr`）
//   - 场景 B：基于 WebSocket（`P2pWsSignalingServer`）自动信令的 1 对 1 P2P 传输
//     （H.265 编码，涵盖 `IceServerConfig`、`JoinRoom`、`LeaveRoom`、
//     `OnRemoteTrackPublished`、`OnRemoteTrackUnpublished` 与 `OnNetworkStats`）

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "rtc_base/logging.h"
#include "rtc_video_engine.hpp"
#include "server/p2p_ws_signaling_server.h"

namespace {

class CustomMemoryLogSink final : public rtc::LogSink {
 public:
  void OnLogMessage(const rtc::LogEntryView& entry,
                    std::string_view /*formatted_line*/) override {
    if (!entry.queue_name.empty()) {
      entries_count_.fetch_add(1, std::memory_order_relaxed);
    }
  }

  uint32_t entries_count() const {
    return entries_count_.load(std::memory_order_relaxed);
  }

 private:
  std::atomic<uint32_t> entries_count_{0};
};

class FullP2pObserver final : public rtc::IRtcEventObserver {
 public:
  explicit FullP2pObserver(std::string name) : name_(std::move(name)) {}

  FullP2pObserver(const FullP2pObserver&) = delete;
  FullP2pObserver& operator=(const FullP2pObserver&) = delete;

  void BindTrickleTarget(rtc::RtcVideoEngine* target) {
    std::lock_guard<std::mutex> lock(mu_);
    trickle_target_ = target;
  }

  void OnEncoderBitrateAllocation(rtc_stream_layer_e /*layer*/,
                                  bool layer_active,
                                  uint32_t target_bitrate_bps,
                                  uint32_t target_fps) override {
    std::lock_guard<std::mutex> lock(mu_);
    ++bitrate_cbs_;
    last_target_bps_ = layer_active ? target_bitrate_bps : 0;
    last_target_fps_ = target_fps;
    cv_.notify_all();
  }

  void OnEncoderForceIdr(rtc_stream_layer_e /*layer*/) override {
    std::lock_guard<std::mutex> lock(mu_);
    force_idr_requested_ = true;
    ++force_idr_count_;
    cv_.notify_all();
  }

  void OnRemoteTrackPublished(const std::string& peer_id,
                              const std::string& track_id,
                              rtc_video_codec_e codec) override {
    std::lock_guard<std::mutex> lock(mu_);
    ++published_events_;
    remote_track_id_ = track_id;
    RTC_LOG(kInfo) << "[" << name_ << "] Remote track published: peer="
                   << peer_id << " track=" << track_id
                   << " codec=" << (codec == RTC_CODEC_H265 ? "H265" : "H264");
    cv_.notify_all();
  }

  void OnRemoteTrackUnpublished(const std::string& peer_id,
                                const std::string& track_id) override {
    std::lock_guard<std::mutex> lock(mu_);
    ++unpublished_events_;
    RTC_LOG(kInfo) << "[" << name_ << "] Remote track unpublished: peer="
                   << peer_id << " track=" << track_id;
    cv_.notify_all();
  }

  void OnRemoteEncodedFrame(const std::string& /*peer_id*/,
                            const std::string& /*track_id*/,
                            const rtc_encoded_frame_t& frame) override {
    std::lock_guard<std::mutex> lock(mu_);
    ++frames_pulled_;
    bytes_pulled_ += frame.size;
    cv_.notify_all();
  }

  void OnConnectionState(rtc_connection_state_e state,
                         int /*reason_code*/) override {
    std::lock_guard<std::mutex> lock(mu_);
    if (state == RTC_CONN_STATE_CONNECTED) {
      connected_ = true;
      cv_.notify_all();
    }
  }

  void OnNetworkStats(const rtc_network_stats_t& stats) override {
    std::lock_guard<std::mutex> lock(mu_);
    ++stats_cbs_;
    last_rtt_ms_ = stats.rtt_ms;
    cv_.notify_all();
  }

  void OnLocalIceCandidate(const std::string& /*sdp_mid*/,
                           int /*sdp_mline_index*/,
                           const std::string& candidate) override {
    rtc::RtcVideoEngine* target = nullptr;
    {
      std::lock_guard<std::mutex> lock(mu_);
      ++local_cand_cbs_;
      target = trickle_target_;
    }
    if (target != nullptr) {
      target->AddRemoteIceCandidate(candidate);
    }
  }

  void OnDataChannelState(const std::string& /*peer_id*/,
                          int channel_id,
                          const std::string& label,
                          rtc_data_channel_state_e state) override {
    std::lock_guard<std::mutex> lock(mu_);
    if (state == RTC_DATA_CHANNEL_OPEN) {
      last_dc_id_ = channel_id;
      ++dc_open_cbs_;
      RTC_LOG(kInfo) << "[" << name_ << "] DataChannel OPEN label=" << label
                     << " id=" << channel_id;
    }
    cv_.notify_all();
  }

  void OnDataChannelMessage(const std::string& /*peer_id*/,
                            int /*channel_id*/,
                            bool /*is_binary*/,
                            const uint8_t* data,
                            size_t size) override {
    std::lock_guard<std::mutex> lock(mu_);
    ++dc_messages_rx_;
    last_dc_text_.assign(reinterpret_cast<const char*>(data), size);
    cv_.notify_all();
  }

  bool WaitConnected(int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lock(mu_);
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                        [this]() { return connected_; });
  }

  bool WaitFramesPulled(uint32_t min_frames, int timeout_ms = 4000) {
    std::unique_lock<std::mutex> lock(mu_);
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                        [this, min_frames]() {
                          return frames_pulled_ >= min_frames;
                        });
  }

  bool WaitTrackUnpublished(int timeout_ms = 3000) {
    std::unique_lock<std::mutex> lock(mu_);
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                        [this]() { return unpublished_events_ > 0; });
  }

  bool ConsumeForceIdr() {
    std::lock_guard<std::mutex> lock(mu_);
    const bool v = force_idr_requested_;
    force_idr_requested_ = false;
    return v;
  }

  uint32_t frames_pulled() const {
    std::lock_guard<std::mutex> lock(mu_);
    return frames_pulled_;
  }
  uint32_t bitrate_cbs() const {
    std::lock_guard<std::mutex> lock(mu_);
    return bitrate_cbs_;
  }
  uint32_t stats_cbs() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_cbs_;
  }
  uint32_t published_events() const {
    std::lock_guard<std::mutex> lock(mu_);
    return published_events_;
  }
  uint32_t unpublished_events() const {
    std::lock_guard<std::mutex> lock(mu_);
    return unpublished_events_;
  }
  uint32_t dc_messages_rx() const {
    std::lock_guard<std::mutex> lock(mu_);
    return dc_messages_rx_;
  }

 private:
  const std::string name_;
  mutable std::mutex mu_;
  std::condition_variable cv_;
  rtc::RtcVideoEngine* trickle_target_ = nullptr;

  bool connected_ = false;
  bool force_idr_requested_ = false;
  uint32_t force_idr_count_ = 0;
  uint32_t bitrate_cbs_ = 0;
  uint32_t last_target_bps_ = 0;
  uint32_t last_target_fps_ = 0;
  uint32_t published_events_ = 0;
  uint32_t unpublished_events_ = 0;
  std::string remote_track_id_;
  uint32_t frames_pulled_ = 0;
  size_t bytes_pulled_ = 0;
  uint32_t stats_cbs_ = 0;
  int64_t last_rtt_ms_ = 0;
  uint32_t local_cand_cbs_ = 0;
  int last_dc_id_ = -1;
  uint32_t dc_open_cbs_ = 0;
  uint32_t dc_messages_rx_ = 0;
  std::string last_dc_text_;
};

std::vector<uint8_t> BuildAnnexBBitstream(rtc_video_codec_e codec,
                                          bool is_idr,
                                          size_t payload_bytes) {
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
  out.resize(out.size() + payload_bytes, 0x5C);
  return out;
}

bool RunDefensiveCpp17Checks() {
  rtc::EngineConfig cfg;
  auto eng = rtc::RtcVideoEngine::Create(cfg, nullptr);

  rtc_encoded_frame_t empty_frame{};
  const uint8_t sample[6] = {0, 0, 0, 1, 0x65, 0x88};
  rtc_encoded_frame_t valid_frame{};
  valid_frame.data = sample;
  valid_frame.size = sizeof(sample);

  return eng->JoinRoom("", "peer") == RTC_ERR_INVALID_ARG &&
         eng->PushVideoFrame(empty_frame) == RTC_ERR_INVALID_ARG &&
         eng->PushVideoFrame(valid_frame) == RTC_ERR_NOT_CONNECTED &&
         eng->CreateLocalOffer(nullptr) == RTC_ERR_INVALID_ARG &&
         eng->SetRemoteDescription("invalid", "v=0", nullptr) ==
             RTC_ERR_INVALID_ARG;
}

bool RunDirectSdpBidirectionalCpp17P2p() {
  RTC_LOG(kInfo)
      << "--- [C++17 Part 1] Serverless Direct SDP Bidirectional P2P ---";
  rtc::EngineConfig cfg;
  cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  cfg.publish_codec = RTC_CODEC_H264;
  cfg.enable_flexfec = true;
  cfg.zero_playout_delay = true;

  FullP2pObserver cam_obs("Cpp17-CamA");
  FullP2pObserver app_obs("Cpp17-AppB");
  auto cam_eng = rtc::RtcVideoEngine::Create(cfg, &cam_obs);
  auto app_eng = rtc::RtcVideoEngine::Create(cfg, &app_obs);

  cam_obs.BindTrickleTarget(app_eng.get());
  app_obs.BindTrickleTarget(cam_eng.get());
  struct TrickleUnbindGuard {
    FullP2pObserver* cam;
    FullP2pObserver* app;
    ~TrickleUnbindGuard() {
      cam->BindTrickleTarget(nullptr);
      app->BindTrickleTarget(nullptr);
    }
  } unbind_guard{&cam_obs, &app_obs};

  cam_eng->JoinRoom("cpp17_direct", "cam_a");
  app_eng->JoinRoom("cpp17_direct", "app_b");

  rtc::DataChannelConfig dc_cfg;
  dc_cfg.label = "ptz_cmd";
  const int app_dc = app_eng->CreateDataChannel(dc_cfg);
  app_eng->SendTextData(app_dc, "PTZ:TILT_UP:10");

  std::string offer_sdp;
  std::string answer_sdp;
  if (app_eng->CreateLocalOffer(&offer_sdp) != RTC_OK ||
      cam_eng->SetRemoteDescription("offer", offer_sdp, &answer_sdp) !=
          RTC_OK ||
      app_eng->SetRemoteDescription("answer", answer_sdp, nullptr) != RTC_OK) {
    return false;
  }
  cam_eng->AddRemoteIceCandidate("");

  if (!cam_obs.WaitConnected() || !app_obs.WaitConnected()) {
    return false;
  }

  uint64_t ts_us = 1'000'000;
  for (int i = 0; i < 20; ++i) {
    const bool is_idr = (i % 7 == 0) || cam_obs.ConsumeForceIdr();
    const auto h264_bytes =
        BuildAnnexBBitstream(RTC_CODEC_H264, is_idr, is_idr ? 3800 : 1200);

    rtc_encoded_frame_t frame{};
    frame.data = h264_bytes.data();
    frame.size = h264_bytes.size();
    frame.capture_ts_us = ts_us;
    frame.is_keyframe = is_idr;
    frame.layer = RTC_STREAM_LAYER_HIGH;

    cam_eng->PushVideoFrame(frame);
    app_eng->PushVideoFrame(frame);

    if (i == 6) {
      app_eng->RequestRemoteIdr("cam_a_video0");
    }
    ts_us += 33'333;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  const bool frames_ok =
      cam_obs.WaitFramesPulled(12) && app_obs.WaitFramesPulled(12);
  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  RTC_LOG(kInfo) << "[C++17 Part 1 Result] cam_pulled="
                 << cam_obs.frames_pulled()
                 << " app_pulled=" << app_obs.frames_pulled()
                 << " cam_dc_rx=" << cam_obs.dc_messages_rx()
                 << " stats_cbs=" << cam_obs.stats_cbs()
                 << " bwe_cbs=" << cam_obs.bitrate_cbs();

  cam_obs.BindTrickleTarget(nullptr);
  app_obs.BindTrickleTarget(nullptr);
  cam_eng->LeaveRoom();
  app_eng->LeaveRoom();

  return frames_ok && cam_obs.dc_messages_rx() > 0 &&
         cam_obs.stats_cbs() > 0 && cam_obs.bitrate_cbs() > 0;
}

bool RunWsSignalingH265Cpp17P2p() {
  RTC_LOG(kInfo)
      << "--- [C++17 Part 2] WebSocket Auto-Signaling H.265 P2P ---";
  rtc::P2pWsSignalingServer ws_server("127.0.0.1");
  if (!ws_server.Start(0)) {
    return false;
  }

  rtc::EngineConfig cfg;
  cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  cfg.signaling_or_moq_url =
      "ws://127.0.0.1:" + std::to_string(ws_server.port());
  cfg.auth_token = "cpp17_secret";
  cfg.ice_servers.push_back(
      rtc::IceServerConfig{"stun:127.0.0.1:3478", "", ""});
  cfg.publish_codec = RTC_CODEC_H265;
  cfg.enable_flexfec = true;
  cfg.zero_playout_delay = true;

  FullP2pObserver pub_obs("Cpp17-WS-PubH265");
  FullP2pObserver sub_obs("Cpp17-WS-SubH265");
  auto pub_eng = rtc::RtcVideoEngine::Create(cfg, &pub_obs);
  auto sub_eng = rtc::RtcVideoEngine::Create(cfg, &sub_obs);

  pub_eng->JoinRoom("cpp17_ws_room", "robot_arm_cam");
  if (pub_eng->JoinRoom("cpp17_ws_room", "robot_arm_cam") !=
      RTC_ERR_ALREADY_CONNECTED) {
    return false;
  }
  sub_eng->JoinRoom("cpp17_ws_room", "teleop_cockpit");

  if (!pub_obs.WaitConnected() || !sub_obs.WaitConnected()) {
    ws_server.Stop();
    return false;
  }

  uint64_t ts_us = 2'000'000;
  for (int i = 0; i < 18; ++i) {
    const bool is_idr = (i % 6 == 0);
    const auto h265_bytes =
        BuildAnnexBBitstream(RTC_CODEC_H265, is_idr, is_idr ? 4400 : 1400);

    rtc_encoded_frame_t frame{};
    frame.data = h265_bytes.data();
    frame.size = h265_bytes.size();
    frame.capture_ts_us = ts_us;
    frame.is_keyframe = is_idr;
    frame.layer = RTC_STREAM_LAYER_HIGH;
    pub_eng->PushVideoFrame(frame);

    ts_us += 33'333;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  const bool pulled_ok = sub_obs.WaitFramesPulled(12);
  // 推流端离开房间 -> 订阅端验证触发 OnRemoteTrackUnpublished 回调
  pub_eng->LeaveRoom();
  const bool unpub_ok = sub_obs.WaitTrackUnpublished();

  RTC_LOG(kInfo) << "[C++17 Part 2 Result] h265_pulled="
                 << sub_obs.frames_pulled()
                 << " pub_events=" << sub_obs.published_events()
                 << " unpub_events=" << sub_obs.unpublished_events();

  sub_eng->LeaveRoom();
  ws_server.Stop();

  return pulled_ok && sub_obs.published_events() > 0 && unpub_ok;
}

}  // namespace

int main() {
  rtc::RtcVideoEngine::SetLogToStderr(true);
  rtc::RtcVideoEngine::SetMinLogSeverity(rtc::LoggingSeverity::kInfo);

  CustomMemoryLogSink custom_sink;
  rtc::RingBufferLogSink ring_sink(128);
  rtc::RtcVideoEngine::AddLogSink(&custom_sink, rtc::LoggingSeverity::kInfo);
  rtc::RtcVideoEngine::AddLogSink(&ring_sink, rtc::LoggingSeverity::kInfo);

  int exit_code = 0;
  if (!RunDefensiveCpp17Checks()) {
    RTC_LOG(kError) << "C++17 defensive API checks failed";
    exit_code = 1;
  } else if (!RunDirectSdpBidirectionalCpp17P2p()) {
    RTC_LOG(kError) << "C++17 Part 1 (Direct SDP P2P) failed";
    exit_code = 2;
  } else if (!RunWsSignalingH265Cpp17P2p()) {
    RTC_LOG(kError) << "C++17 Part 2 (WebSocket H.265 P2P) failed";
    exit_code = 3;
  }

  RTC_LOG(kInfo) << "=== C++17 WebRTC P2P Full Demo Summary: exit=" << exit_code
                 << " custom_sink_logs=" << custom_sink.entries_count()
                 << " ring_buffer_logs=" << ring_sink.Size() << " ===";

  rtc::RtcVideoEngine::RemoveLogSink(&ring_sink);
  rtc::RtcVideoEngine::RemoveLogSink(&custom_sink);
  return (exit_code == 0 && custom_sink.entries_count() > 0) ? 0 : exit_code;
}
