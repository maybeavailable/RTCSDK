#ifndef INCLUDE_RTC_VIDEO_ENGINE_HPP_
#define INCLUDE_RTC_VIDEO_ENGINE_HPP_

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "rtc_quic_congestion_control.hpp"
#include "rtc_video_sdk.h"

namespace rtc {

enum class LoggingSeverity : int {
  kVerbose = RTC_LOG_VERBOSE,
  kInfo = RTC_LOG_INFO,
  kWarning = RTC_LOG_WARNING,
  kError = RTC_LOG_ERROR,
  kNone = RTC_LOG_NONE,
};

struct LogEntryView {
  LoggingSeverity severity = LoggingSeverity::kInfo;
  int64_t timestamp_us = 0;
  std::string_view queue_name;
  std::string_view file_name;
  int line = 0;
  std::string_view message;
};

class LogSink {
 public:
  virtual ~LogSink() = default;
  virtual void OnLogMessage(const LogEntryView& entry,
                            std::string_view formatted_line) = 0;
};

struct IceServerConfig {
  std::string uri;
  std::string username;
  std::string password;
};

// 双模通用数据通道配置（兼容 RFC 8831/8832 WebRTC DataChannel 与 IETF MoQ 数据轨道）。
struct DataChannelConfig {
  std::string label = "data";
  std::string protocol;
  bool ordered = true;
  int32_t max_retransmits = -1;
  int32_t max_packet_lifetime_ms = -1;
  bool negotiated = false;
  int32_t id = -1;
};

struct EngineConfig {
  rtc_transport_mode_e transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  std::string signaling_or_moq_url;
  std::string auth_token;
  std::vector<IceServerConfig> ice_servers;

  rtc_video_codec_e publish_codec = RTC_CODEC_H264;
  bool enable_simulcast = false;
  bool enable_flexfec = true;
  bool zero_playout_delay = false;
  bool enable_datachannel = true;

  uint32_t min_bitrate_bps = 150'000;
  uint32_t start_bitrate_bps = 1'500'000;
  uint32_t max_bitrate_bps = 6'000'000;
  uint32_t low_layer_max_bps = 450'000;
  uint32_t moq_delivery_timeout_ms = 250;

  // 可插拔 QUIC 拥塞控制配置（用于 MoQ 传输模式）。
  // 若 `custom_quic_cc_factory` 非空，则优先于 `quic_cc_algo` 生效。
  rtc_quic_cc_algo_e quic_cc_algo = RTC_QUIC_CC_BBR;
  std::shared_ptr<IQuicCongestionControllerFactory> custom_quic_cc_factory;
};

class IRtcEventObserver {
 public:
  virtual ~IRtcEventObserver() = default;

  virtual void OnEncoderBitrateAllocation(rtc_stream_layer_e layer,
                                          bool layer_active,
                                          uint32_t target_bitrate_bps,
                                          uint32_t target_fps) = 0;

  virtual void OnEncoderForceIdr(rtc_stream_layer_e layer) = 0;

  virtual void OnRemoteTrackPublished(const std::string& peer_id,
                                      const std::string& track_id,
                                      rtc_video_codec_e codec) = 0;

  virtual void OnRemoteTrackUnpublished(const std::string& peer_id,
                                        const std::string& track_id) = 0;

  virtual void OnRemoteEncodedFrame(const std::string& peer_id,
                                    const std::string& track_id,
                                    const rtc_encoded_frame_t& frame) = 0;

  virtual void OnConnectionState(rtc_connection_state_e state,
                                 int reason_code) = 0;

  virtual void OnNetworkStats(const rtc_network_stats_t& /*stats*/) {}

  virtual void OnLocalIceCandidate(const std::string& /*sdp_mid*/,
                                   int /*sdp_mline_index*/,
                                   const std::string& /*candidate*/) {}

  virtual void OnDataChannelState(const std::string& /*peer_id*/,
                                  int /*channel_id*/,
                                  const std::string& /*label*/,
                                  rtc_data_channel_state_e /*state*/) {}

  virtual void OnDataChannelMessage(const std::string& /*peer_id*/,
                                    int /*channel_id*/,
                                    bool /*is_binary*/,
                                    const uint8_t* /*data*/,
                                    size_t /*size*/) {}
};

class IMoqQuicEngine;

class RtcVideoEngine {
 public:
  static std::unique_ptr<RtcVideoEngine> Create(
      const EngineConfig& config,
      IRtcEventObserver* observer,
      std::shared_ptr<IMoqQuicEngine> custom_moq_quic_engine = nullptr);

  static void SetMinLogSeverity(LoggingSeverity severity);
  static void SetLogToStderr(bool enable);
  static void AddLogSink(LogSink* sink,
                         LoggingSeverity min_severity = LoggingSeverity::kInfo);
  static void RemoveLogSink(LogSink* sink);

  RtcVideoEngine() = default;
  virtual ~RtcVideoEngine() = default;

  RtcVideoEngine(const RtcVideoEngine&) = delete;
  RtcVideoEngine& operator=(const RtcVideoEngine&) = delete;

  virtual int JoinRoom(const std::string& room_id,
                       const std::string& local_peer_id) = 0;
  virtual int LeaveRoom() = 0;

  virtual int PushVideoFrame(const rtc_encoded_frame_t& frame) = 0;

  // MoQ 多路流拉取控制接口（在 WebRTC P2P 模式下，单对端视频流会在
  // SDP/ICE/DTLS 协商完成后自动传输）。
  virtual int SubscribeTrack(const std::string& remote_track_id,
                             rtc_stream_layer_e preferred_layer) = 0;
  virtual int SwitchSubscribedLayer(const std::string& remote_track_id,
                                    rtc_stream_layer_e preferred_layer) = 0;
  virtual int UnsubscribeTrack(const std::string& remote_track_id) = 0;
  virtual int RequestRemoteIdr(const std::string& remote_track_id) = 0;

  // 在 MoQ 会话运行时热切换 QUIC 拥塞控制模块。
  virtual int SetQuicCongestionControl(rtc_quic_cc_algo_e algo) = 0;
  virtual int SetCustomQuicCongestionController(
      std::shared_ptr<IQuicCongestionControllerFactory> factory) = 0;

  // 兼容 W3C 浏览器的直连 WebRTC P2P SDP 与 Trickle-ICE 控制接口。
  virtual int CreateLocalOffer(std::string* out_sdp) = 0;
  virtual int SetRemoteDescription(std::string_view sdp_type,
                                   std::string_view remote_sdp,
                                   std::string* out_answer_sdp = nullptr) = 0;
  virtual int AddRemoteIceCandidate(std::string_view candidate_sdp) = 0;

  // 双模通用数据通道接口（WebRTC P2P 模式使用 SCTP over DTLS / DCEP，
  // IETF MoQ 模式使用 QUIC v1 MoQ 数据轨道）。成功创建返回 >= 0 的 channel_id。
  virtual int CreateDataChannel(const DataChannelConfig& config) = 0;
  virtual int SendData(int channel_id,
                       const uint8_t* data,
                       size_t size,
                       bool is_binary = true) = 0;
  int SendTextData(int channel_id, std::string_view text) {
    return SendData(channel_id, reinterpret_cast<const uint8_t*>(text.data()),
                    text.size(), /*is_binary=*/false);
  }
  virtual int CloseDataChannel(int channel_id) = 0;
};

}  // namespace rtc

#endif  // INCLUDE_RTC_VIDEO_ENGINE_HPP_