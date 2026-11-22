#ifndef INCLUDE_RTC_VIDEO_SDK_H_
#define INCLUDE_RTC_VIDEO_SDK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define RTC_SDK_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#define RTC_SDK_API __attribute__((visibility("default")))
#else
#define RTC_SDK_API
#endif

typedef struct rtc_client_t rtc_client_t;

typedef enum {
  RTC_OK = 0,
  RTC_ERR_INVALID_ARG = -1,
  RTC_ERR_NOT_INITIALIZED = -2,
  RTC_ERR_ALREADY_CONNECTED = -3,
  RTC_ERR_NOT_CONNECTED = -4,
  RTC_ERR_NO_MEMORY = -5,
  RTC_ERR_CODEC_UNSUPPORTED = -6,
  RTC_ERR_PROTOCOL = -7,
  RTC_ERR_INTERNAL = -100,
} rtc_error_e;

typedef enum {
  RTC_LOG_VERBOSE = 0,
  RTC_LOG_INFO = 1,
  RTC_LOG_WARNING = 2,
  RTC_LOG_ERROR = 3,
  RTC_LOG_NONE = 4,
} rtc_log_severity_e;

typedef void (*rtc_log_callback_fn)(void* user_data,
                                    rtc_log_severity_e severity,
                                    const char* queue_name,
                                    const char* file_name,
                                    int line,
                                    const char* message);

typedef enum {
  // 1 对 1 纯 WebRTC P2P 模式（完整 ICE + DTLS-SRTP，兼容 W3C 浏览器）。
  RTC_TRANSPORT_MODE_WEBRTC_P2P = 0,
  // 1 对多 / 多路拉流 IETF Media over QUIC (MoQ) 中继模式。
  RTC_TRANSPORT_MODE_MOQ = 1,
} rtc_transport_mode_e;

typedef enum {
  RTC_CODEC_H264 = 1,
  RTC_CODEC_H265 = 2,
} rtc_video_codec_e;

typedef enum {
  RTC_STREAM_LAYER_LOW = 0,   // 硬件 VENC 子码流（MoQ Simulcast 低清层）
  RTC_STREAM_LAYER_HIGH = 1,  // 硬件 VENC 主码流（高清层）
} rtc_stream_layer_e;

typedef enum {
  RTC_CONN_STATE_IDLE = 0,
  RTC_CONN_STATE_CONNECTING = 1,
  RTC_CONN_STATE_CONNECTED = 2,
  RTC_CONN_STATE_RECONNECTING = 3,
  RTC_CONN_STATE_DISCONNECTED = 4,
  RTC_CONN_STATE_FAILED = 5,
} rtc_connection_state_e;

// 面向 IETF MoQ 传输的可热插拔 QUIC 拥塞控制算法。
typedef enum {
  RTC_QUIC_CC_BBR = 0,      // Google BBRv1（默认低延迟媒体拥塞控制算法）
  RTC_QUIC_CC_BBR2 = 1,     // IETF BBRv2（感知丢包与 inflight_hi 容量余量）
  RTC_QUIC_CC_CUBIC = 2,    // 基于 RFC 9438 CUBIC + RFC 9406 HyStart++ 的拥塞控制算法
  RTC_QUIC_CC_COPA = 3,     // MIT / Meta mvfst Copa 面向目标延迟的拥塞控制算法
  RTC_QUIC_CC_NEWRENO = 4,  // 基于 RFC 9002 第 7 节的 NewReno AIMD 拥塞控制算法
} rtc_quic_cc_algo_e;

typedef struct {
  const uint8_t* data;      // Annex-B NALU 码流数据指针（00 00 00 01 ...）
  size_t size;              // 码流字节长度
  uint64_t capture_ts_us;   // 单调递增采集时间戳（微秒）
  bool is_keyframe;         // 是否为 IDR / CRA 关键帧
  rtc_stream_layer_e layer; // 空间层（MoQ Simulcast 低清层或高清层）
  uint8_t temporal_id;      // 时域层 ID（0 表示基础层，1..3 表示 SVC 增强层）
  bool discardable;         // 是否为非参考帧（MoQ 可安全丢弃）
} rtc_encoded_frame_t;

typedef struct {
  int64_t rtt_ms;
  uint32_t target_bitrate_bps;
  uint32_t pacing_bitrate_bps;
  float uplink_packet_loss;
  float downlink_packet_loss;
  uint64_t packets_sent;
  uint64_t packets_retransmitted;
  uint64_t fec_packets_sent;
  uint64_t frames_decoded;
  uint64_t keyframe_requests_sent;
} rtc_network_stats_t;

typedef struct {
  void (*on_encoder_bitrate_allocation)(void* user_data,
                                        rtc_stream_layer_e layer,
                                        bool layer_active,
                                        uint32_t target_bitrate_bps,
                                        uint32_t target_fps);

  void (*on_encoder_force_idr)(void* user_data, rtc_stream_layer_e layer);

  void (*on_remote_track_published)(void* user_data,
                                    const char* peer_id,
                                    const char* track_id,
                                    rtc_video_codec_e codec);
  void (*on_remote_track_unpublished)(void* user_data,
                                      const char* peer_id,
                                      const char* track_id);

  void (*on_remote_encoded_frame)(void* user_data,
                                  const char* peer_id,
                                  const char* track_id,
                                  const rtc_encoded_frame_t* frame);

  void (*on_connection_state)(void* user_data,
                              rtc_connection_state_e state,
                              int reason_code);

  void (*on_network_stats)(void* user_data, const rtc_network_stats_t* stats);

  // 可选的 Trickle-ICE 回调，用于自定义 HTTP/MQTT 浏览器 P2P 信令交互。
  void (*on_local_ice_candidate)(void* user_data,
                                 const char* sdp_mid,
                                 int sdp_mline_index,
                                 const char* candidate_sdp);
} rtc_callbacks_t;

typedef struct {
  const char* uri;       // 服务器地址，例如 "stun:192.168.1.10:3478" 或 "turn:10.0.0.2:3478"
  const char* username;  // 可选的 TURN 长期凭证用户名
  const char* password;  // 可选的 TURN 长期凭证密码
} rtc_ice_server_t;

typedef struct {
  rtc_transport_mode_e transport_mode;
  const char* signaling_or_moq_url;
  const char* auth_token;

  rtc_ice_server_t ice_servers[4];
  size_t ice_server_count;

  rtc_video_codec_e publish_codec;
  bool enable_simulcast;  // 用于 RTC_TRANSPORT_MODE_MOQ 模式下的多层 Simulcast 推流
  bool enable_flexfec;
  bool zero_playout_delay;

  uint32_t min_bitrate_bps;
  uint32_t start_bitrate_bps;
  uint32_t max_bitrate_bps;
  uint32_t low_layer_max_bps;
  uint32_t moq_delivery_timeout_ms;
  rtc_quic_cc_algo_e quic_cc_algo;  // 初始 QUIC 拥塞控制算法模块（0 = BBRv1）
} rtc_config_t;

// 全局统一日志 C 接口
RTC_SDK_API void rtc_set_log_level(rtc_log_severity_e min_severity);
RTC_SDK_API void rtc_enable_stderr_logging(bool enable);
RTC_SDK_API void rtc_set_log_callback(rtc_log_callback_fn callback,
                                      void* user_data);

// 客户端生命周期与媒体传输 C 接口
RTC_SDK_API rtc_client_t* rtc_client_create(const rtc_config_t* cfg,
                                            const rtc_callbacks_t* cbs,
                                            void* user_data);

RTC_SDK_API int rtc_client_join_room(rtc_client_t* client,
                                     const char* room_id,
                                     const char* local_peer_id);

RTC_SDK_API int rtc_client_leave_room(rtc_client_t* client);

RTC_SDK_API void rtc_client_destroy(rtc_client_t* client);

RTC_SDK_API int rtc_client_push_video_frame(rtc_client_t* client,
                                            const rtc_encoded_frame_t* frame);

// 多轨道订阅接口（用于 RTC_TRANSPORT_MODE_MOQ 模式；在自动传输点对点媒体的
// RTC_TRANSPORT_MODE_WEBRTC_P2P 模式下为空操作或单对端控制）。
RTC_SDK_API int rtc_client_subscribe_track(rtc_client_t* client,
                                           const char* remote_track_id,
                                           rtc_stream_layer_e preferred_layer);

RTC_SDK_API int rtc_client_switch_subscribed_layer(
    rtc_client_t* client,
    const char* remote_track_id,
    rtc_stream_layer_e preferred_layer);

RTC_SDK_API int rtc_client_unsubscribe_track(rtc_client_t* client,
                                             const char* remote_track_id);

RTC_SDK_API int rtc_client_request_remote_idr(rtc_client_t* client,
                                              const char* remote_track_id);

// 在活跃或空闲的 MoQ 会话上热切换 QUIC 拥塞控制模块，
// 并无缝迁移预估带宽、RTT 与拥塞窗口（cwnd）状态。
RTC_SDK_API int rtc_client_set_quic_cc_algo(rtc_client_t* client,
                                            rtc_quic_cc_algo_e algo);

RTC_SDK_API const char* rtc_quic_cc_algo_name(rtc_quic_cc_algo_e algo);

// 兼容浏览器的直连 WebRTC P2P SDP / Trickle-ICE 交换接口
// （支持通过 HTTP/MQTT/CGI 直接与 Chrome/Firefox/Safari 配对互通，无需依赖 WS）。
RTC_SDK_API int rtc_client_create_offer(rtc_client_t* client,
                                        char* out_sdp_buf,
                                        size_t out_sdp_capacity);

RTC_SDK_API int rtc_client_set_remote_description(rtc_client_t* client,
                                                  const char* sdp_type,
                                                  const char* remote_sdp,
                                                  char* out_answer_buf,
                                                  size_t out_answer_capacity);

RTC_SDK_API int rtc_client_add_remote_ice_candidate(rtc_client_t* client,
                                                    const char* candidate_sdp);

#ifdef __cplusplus
}
#endif

#endif  // INCLUDE_RTC_VIDEO_SDK_H_