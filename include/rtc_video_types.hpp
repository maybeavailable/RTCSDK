#ifndef INCLUDE_RTC_VIDEO_TYPES_HPP_
#define INCLUDE_RTC_VIDEO_TYPES_HPP_

// 纯现代 C++17 实时视频与数据通道 SDK 公共基础类型定义。

#include <cstddef>
#include <cstdint>
#include <string_view>

#if defined(_WIN32)
#define RTC_SDK_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#define RTC_SDK_API __attribute__((visibility("default")))
#else
#define RTC_SDK_API
#endif

// SDK 统一返回错误码。
enum rtc_error_e : int {
  RTC_OK = 0,
  RTC_ERR_INVALID_ARG = -1,
  RTC_ERR_NOT_INITIALIZED = -2,
  RTC_ERR_ALREADY_CONNECTED = -3,
  RTC_ERR_NOT_CONNECTED = -4,
  RTC_ERR_NO_MEMORY = -5,
  RTC_ERR_CODEC_UNSUPPORTED = -6,
  RTC_ERR_PROTOCOL = -7,
  RTC_ERR_INTERNAL = -100,
};

// 底层实时媒体与数据通道传输模式。
enum rtc_transport_mode_e : int {
  // 1 对 1 纯 WebRTC P2P 模式（完整 ICE + DTLS-SRTP + SCTP，兼容 W3C 浏览器）。
  RTC_TRANSPORT_MODE_WEBRTC_P2P = 0,
  // 1 对多 / 多路拉流 IETF Media over QUIC（draft-ietf-moq-transport-17）中继模式
  // （moqt:// 默认走原生 QUIC ALPN "moqt-17"；https:// 或 wt:// 自动切换至 HTTP/3 + WebTransport）。
  RTC_TRANSPORT_MODE_MOQ = 1,
  // 显式通过 HTTP/3 + WebTransport（RFC 9114 + QPACK + draft-ietf-webtrans-http3，ALPN "h3"）
  // 承载 IETF MoQ（draft-17，WT-Protocol: "moqt-17"）的中继模式。
  RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT = 2,
};

// 视频编码格式（纯视频零音频架构）。
enum rtc_video_codec_e : int {
  RTC_CODEC_H264 = 1,
  RTC_CODEC_H265 = 2,
};

// 视频空间层标识（用于 MoQ Simulcast 高低双流与码率分配）。
enum rtc_stream_layer_e : int {
  RTC_STREAM_LAYER_LOW = 0,   // 硬件 VENC 子码流（MoQ Simulcast 低清层）
  RTC_STREAM_LAYER_HIGH = 1,  // 硬件 VENC 主码流（高清层）
};

// 会话连接状态机枚举。
enum rtc_connection_state_e : int {
  RTC_CONN_STATE_IDLE = 0,
  RTC_CONN_STATE_CONNECTING = 1,
  RTC_CONN_STATE_CONNECTED = 2,
  RTC_CONN_STATE_RECONNECTING = 3,
  RTC_CONN_STATE_DISCONNECTED = 4,
  RTC_CONN_STATE_FAILED = 5,
};

// 面向 IETF MoQ 传输的可热插拔 QUIC 拥塞控制算法。
enum rtc_quic_cc_algo_e : int {
  RTC_QUIC_CC_BBR = 0,      // Google BBRv1（默认低延迟媒体拥塞控制算法）
  RTC_QUIC_CC_BBR2 = 1,     // IETF BBRv2（感知丢包与 inflight_hi 容量余量）
  RTC_QUIC_CC_CUBIC = 2,    // 基于 RFC 9438 CUBIC + RFC 9406 HyStart++ 的拥塞控制算法
  RTC_QUIC_CC_COPA = 3,     // MIT / Meta mvfst Copa 面向目标延迟的拥塞控制算法
  RTC_QUIC_CC_NEWRENO = 4,  // 基于 RFC 9002 第 7 节的 NewReno AIMD 拥塞控制算法
};

// 通用数据通道生命周期状态（兼容 W3C RTCDataChannelState 与 IETF MoQ 数据轨道）。
enum rtc_data_channel_state_e : int {
  RTC_DATA_CHANNEL_CONNECTING = 0,
  RTC_DATA_CHANNEL_OPEN = 1,
  RTC_DATA_CHANNEL_CLOSING = 2,
  RTC_DATA_CHANNEL_CLOSED = 3,
};

// 编码后 Annex-B 视频帧零拷贝视图与帧级依赖元数据。
struct rtc_encoded_frame_t {
  const uint8_t* data = nullptr;                     // Annex-B NALU 码流数据指针（00 00 00 01 ...）
  size_t size = 0;                                   // 码流字节长度
  uint64_t capture_ts_us = 0;                        // 单调递增采集时间戳（微秒）
  bool is_keyframe = false;                          // 是否为 IDR / CRA 关键帧
  rtc_stream_layer_e layer = RTC_STREAM_LAYER_HIGH;  // 空间层（低清层或高清层）
  uint8_t temporal_id = 0;                           // 时域层 ID（0 表示基础层，1..3 表示 SVC 增强层）
  bool discardable = false;                          // 是否为非参考帧（MoQ 拥塞时可安全丢弃）
};

// 周期性实时网络与媒体传输统计快照。
struct rtc_network_stats_t {
  int64_t rtt_ms = 0;
  uint32_t target_bitrate_bps = 0;
  uint32_t pacing_bitrate_bps = 0;
  float uplink_packet_loss = 0.0f;
  float downlink_packet_loss = 0.0f;
  uint64_t packets_sent = 0;
  uint64_t packets_retransmitted = 0;
  uint64_t fec_packets_sent = 0;
  uint64_t frames_decoded = 0;
  uint64_t keyframe_requests_sent = 0;
};

namespace rtc {

using ErrorCode = rtc_error_e;
using TransportMode = rtc_transport_mode_e;
using VideoCodecType = rtc_video_codec_e;
using StreamLayer = rtc_stream_layer_e;
using ConnectionState = rtc_connection_state_e;
using QuicCcAlgorithm = rtc_quic_cc_algo_e;
using DataChannelState = rtc_data_channel_state_e;
using EncodedFrameView = rtc_encoded_frame_t;
using NetworkStats = rtc_network_stats_t;

// 返回内置 QUIC 拥塞控制算法的可读名称（零分配编译期常量视图）。
constexpr std::string_view QuicCcAlgoName(rtc_quic_cc_algo_e algo) noexcept {
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
  }
  return "Unknown";
}

}  // namespace rtc

#endif  // INCLUDE_RTC_VIDEO_TYPES_HPP_
