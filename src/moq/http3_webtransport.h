#ifndef SRC_MOQ_HTTP3_WEBTRANSPORT_H_
#define SRC_MOQ_HTTP3_WEBTRANSPORT_H_

// 原生 HTTP/3（RFC 9114）、QPACK 头部压缩（RFC 9204 + RFC 7541 Huffman）、
// 扩展 CONNECT（RFC 9220）、HTTP 数据报与 Capsule 协议（RFC 9297）以及
// WebTransport over HTTP/3（draft-ietf-webtrans-http3-14）完整协议栈实现。

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "api/array_view.h"
#include "api/session_backend_interface.h"
#include "moq/asio_quic_transport.h"

namespace rtc {

// HTTP/3 单向流类型标识（RFC 9114 第 6.2 节与 draft-ietf-webtrans-http3-14 第 9.4 节）。
inline constexpr uint64_t kH3StreamTypeControl = 0x00;
inline constexpr uint64_t kH3StreamTypePush = 0x01;
inline constexpr uint64_t kH3StreamTypeQpackEncoder = 0x02;
inline constexpr uint64_t kH3StreamTypeQpackDecoder = 0x03;
inline constexpr uint64_t kH3StreamTypeWebTransportUni = 0x54;

// WebTransport 双向流首字节信号标识（draft-ietf-webtrans-http3-14 第 9.3 节）。
inline constexpr uint64_t kWtStreamSignalBidi = 0x41;

// HTTP/3 帧类型标识（RFC 9114 第 7.2 节）。
inline constexpr uint64_t kH3FrameData = 0x00;
inline constexpr uint64_t kH3FrameHeaders = 0x01;
inline constexpr uint64_t kH3FrameCancelPush = 0x03;
inline constexpr uint64_t kH3FrameSettings = 0x04;
inline constexpr uint64_t kH3FramePushPromise = 0x05;
inline constexpr uint64_t kH3FrameGoaway = 0x07;
inline constexpr uint64_t kH3FrameMaxPushId = 0x0D;

// HTTP/3 SETTINGS 参数标识（RFC 9114 / RFC 9220 / RFC 9297 / WebTransport draft-14）。
inline constexpr uint64_t kH3SettingsQpackMaxTableCapacity = 0x01;
inline constexpr uint64_t kH3SettingsMaxFieldSectionSize = 0x06;
inline constexpr uint64_t kH3SettingsQpackBlockedStreams = 0x07;
inline constexpr uint64_t kH3SettingsEnableConnectProtocol = 0x08;
inline constexpr uint64_t kH3SettingsH3Datagram = 0x33;
inline constexpr uint64_t kH3SettingsH3DatagramDraft00 = 0xFFD277ULL;
inline constexpr uint64_t kH3SettingsEnableWebTransportLegacy = 0x2B603742ULL;
inline constexpr uint64_t kH3SettingsWtMaxSessionsDraft07 = 0xC671706AULL;
inline constexpr uint64_t kH3SettingsWtMaxSessions = 0x14E9CD29ULL;
inline constexpr uint64_t kH3SettingsWtInitialMaxData = 0x2B61ULL;
inline constexpr uint64_t kH3SettingsWtInitialMaxStreamsUni = 0x2B64ULL;
inline constexpr uint64_t kH3SettingsWtInitialMaxStreamsBidi = 0x2B65ULL;

// HTTP/3 与 WebTransport 错误码常量（RFC 9114 第 8.1 节与 WebTransport draft-14 第 9.5 节）。
inline constexpr uint64_t kH3NoError = 0x0100;
inline constexpr uint64_t kH3GeneralProtocolError = 0x0101;
inline constexpr uint64_t kH3StreamCreationError = 0x0103;
inline constexpr uint64_t kH3ClosedCriticalStream = 0x0104;
inline constexpr uint64_t kH3FrameUnexpected = 0x0105;
inline constexpr uint64_t kH3FrameError = 0x0106;
inline constexpr uint64_t kH3ExcessiveLoad = 0x0107;
inline constexpr uint64_t kH3IdError = 0x0108;
inline constexpr uint64_t kH3SettingsError = 0x0109;
inline constexpr uint64_t kH3MissingSettings = 0x010A;
inline constexpr uint64_t kH3RequestRejected = 0x010B;
inline constexpr uint64_t kH3RequestCancelled = 0x010C;
inline constexpr uint64_t kH3MessageError = 0x010E;
inline constexpr uint64_t kWtFlowControlError = 0x045D4487ULL;
inline constexpr uint64_t kWtSessionGone = 0x170D7B68ULL;
inline constexpr uint64_t kWtBufferedStreamRejected = 0x3994BD84ULL;

// 64 位虚拟 WebTransport 会话 ID 标记位（第 62 位），确保与原生 QUIC 会话 ID 永久零碰撞。
inline constexpr uint64_t kWtVirtualSessionBit = uint64_t{1} << 62;
inline constexpr bool IsWtVirtualSessionId(uint64_t session_id) noexcept {
  return (session_id & kWtVirtualSessionBit) != 0;
}
uint64_t AllocateWtVirtualSessionId() noexcept;

// WebTransport Capsule 类型常量（draft-ietf-webtrans-http3-14 第 9.6 节）。
inline constexpr uint64_t kWtCapsuleCloseSession = 0x2843ULL;
inline constexpr uint64_t kWtCapsuleDrainSession = 0x78AEULL;
inline constexpr uint64_t kWtCapsuleMaxData = 0x190B4D3DULL;
inline constexpr uint64_t kWtCapsuleMaxStreamsBidi = 0x190B4D3FULL;
inline constexpr uint64_t kWtCapsuleMaxStreamsUni = 0x190B4D40ULL;
inline constexpr uint64_t kWtCapsuleDataBlocked = 0x190B4D41ULL;
inline constexpr uint64_t kWtCapsuleStreamsBlockedBidi = 0x190B4D43ULL;
inline constexpr uint64_t kWtCapsuleStreamsBlockedUni = 0x190B4D44ULL;

// 单个 HTTP 头部字段键值对。
struct HttpHeaderField {
  std::string name;
  std::string value;
};

// HTTP/3 请求与响应高层消息结构。
struct Http3Request {
  std::string method = "GET";
  std::string scheme = "https";
  std::string authority;
  std::string path = "/";
  std::string protocol;
  std::vector<HttpHeaderField> headers;
  std::vector<uint8_t> body;
};

struct Http3Response {
  int status = 200;
  std::vector<HttpHeaderField> headers;
  std::vector<uint8_t> body;
};

// RFC 9204 QPACK 静态表与 RFC 7541 Huffman 编解码器。
class QpackCodec {
 public:
  static std::vector<uint8_t> HuffmanEncode(std::string_view plain);
  static bool HuffmanDecode(ArrayView<const uint8_t> encoded,
                            std::string* out_plain);

  static std::vector<uint8_t> EncodeFieldSection(
      const std::vector<HttpHeaderField>& headers,
      bool use_huffman = true);
  static bool DecodeFieldSection(ArrayView<const uint8_t> data,
                                 std::vector<HttpHeaderField>* out_headers,
                                 size_t max_field_section_size = 65536);
};

// HTTP/3 帧与 SETTINGS 编解码工具。
struct Http3Frame {
  uint64_t type = 0;
  std::vector<uint8_t> payload;

  static void Append(uint64_t type,
                     ArrayView<const uint8_t> payload,
                     std::vector<uint8_t>* out);
  static std::optional<Http3Frame> Decode(ArrayView<const uint8_t> data,
                                          size_t* consumed);
};

struct Http3Settings {
  uint64_t qpack_max_table_capacity = 0;
  uint64_t max_field_section_size = 65536;
  uint64_t qpack_blocked_streams = 0;
  bool enable_connect_protocol = true;
  bool h3_datagram = true;
  uint64_t wt_max_sessions = 16;
  uint64_t wt_initial_max_data = 16 * 1024 * 1024;
  uint64_t wt_initial_max_streams_uni = 16384;
  uint64_t wt_initial_max_streams_bidi = 1024;

  std::vector<uint8_t> EncodeFrame() const;
  static std::optional<Http3Settings> DecodePayload(
      ArrayView<const uint8_t> payload);
};

// RFC 9297 Capsule 编解码与 WebTransport 会话控制胶囊工具。
struct WebTransportCapsule {
  uint64_t type = 0;
  std::vector<uint8_t> value;

  static std::vector<uint8_t> Encode(uint64_t type,
                                     ArrayView<const uint8_t> value);
  static std::optional<WebTransportCapsule> Decode(
      ArrayView<const uint8_t> data,
      size_t* consumed);

  static std::vector<uint8_t> EncodeCloseSession(uint32_t app_error_code,
                                                 std::string_view error_msg);
  static bool DecodeCloseSession(ArrayView<const uint8_t> value,
                                 uint32_t* out_error_code,
                                 std::string* out_error_msg);
  static std::vector<uint8_t> EncodeDrainSession();
  static std::vector<uint8_t> EncodeMaxData(uint64_t max_data);
  static bool DecodeMaxData(ArrayView<const uint8_t> value,
                            uint64_t* out_max_data);
  static std::vector<uint8_t> EncodeMaxStreams(uint64_t max_streams,
                                               bool unidirectional);
  static bool DecodeMaxStreams(ArrayView<const uint8_t> value,
                               uint64_t* out_max_streams);
};

// WebTransport 应用错误码与协议协商头部工具函数（draft-ietf-webtrans-http3-14 第 3.3 / 4.4 节）。
uint64_t WebTransportCodeToHttp3Code(uint32_t app_code);
std::optional<uint32_t> Http3CodeToWebTransportCode(uint64_t http3_code);

std::string FormatWtAvailableProtocols(const std::vector<std::string>& protos);
std::vector<std::string> ParseWtAvailableProtocols(std::string_view field_val);
std::string FormatWtProtocol(std::string_view proto);
std::optional<std::string> ParseWtProtocol(std::string_view field_val);

// RFC 9297 HTTP Datagram Quarter-Stream-ID 封装与解封工具。
std::vector<uint8_t> EncodeHttp3Datagram(uint64_t connect_stream_id,
                                         ArrayView<const uint8_t> payload);
bool DecodeHttp3Datagram(ArrayView<const uint8_t> wire,
                         uint64_t* out_connect_stream_id,
                         ArrayView<const uint8_t>* out_payload);

// 透明实现 IMoqQuicEngine 接口的 WebTransport over HTTP/3 客户端传输引擎：
// 在底层 QUIC v1（ALPN "h3"）之上自动完成 SETTINGS 交换、Extended CONNECT 升级、
// WT-Available-Protocols 子协议协商、0x41/0x54 流头部映射与 Quarter-Stream-ID 数据报复用，
// 同时支持在连接上并发发起常规 HTTP/3 请求（GET/POST）。
class WebTransportClientEngine final
    : public IMoqQuicEngine,
      public IMoqQuicEngineObserver,
      public std::enable_shared_from_this<WebTransportClientEngine> {
 public:
  using Http3ResponseCallback = std::function<void(const Http3Response&)>;

  explicit WebTransportClientEngine(
      std::shared_ptr<IMoqQuicEngine> inner_quic);
  WebTransportClientEngine(
      std::shared_ptr<IMoqQuicEngine> inner_quic,
      std::string authority,
      std::string path = "/moq",
      std::vector<std::string> available_protocols = {"moqt-17"});
  ~WebTransportClientEngine() override;

  void SetEndpointConfig(std::string authority,
                         std::string path,
                         std::vector<std::string> available_protocols);

  std::string negotiated_wt_protocol() const;

  // 在同一条 HTTP/3 连接上发送常规 HTTP/3 请求（例如 GET /health 或 POST /api）。
  int SendHttp3Request(const Http3Request& req, Http3ResponseCallback on_resp);

  // IMoqQuicEngine 接口实现：
  void SetObserver(IMoqQuicEngineObserver* observer) override;
  int Connect(const std::string& host,
              uint16_t port,
              const std::string& alpn) override;
  void Close(uint64_t app_error_code) override;
  uint64_t OpenBidirectionalStream() override;
  uint64_t OpenUnidirectionalStream(uint8_t publisher_priority,
                                    int64_t send_order) override;
  int WriteStream(uint64_t stream_id,
                  ArrayView<const uint8_t> data,
                  bool fin) override;
  void ResetStream(uint64_t stream_id, uint64_t app_error_code) override;
  void StopSending(uint64_t stream_id, uint64_t app_error_code) override;
  int SendDatagram(ArrayView<const uint8_t> data) override;
  size_t max_datagram_size() const override;
  std::string negotiated_alpn() const override;
  bool is_webtransport() const override { return true; }
  QuicCongestionSnapshot GetCongestionSnapshot() const override;
  int SetCongestionController(
      std::unique_ptr<IQuicCongestionController> controller) override;

  // 底层 QUIC 回调处理（IMoqQuicEngineObserver）：
  void OnQuicConnected() override;
  void OnQuicDisconnected(int error_code) override;
  void OnStreamOpened(uint64_t stream_id, bool unidirectional) override;
  void OnStreamData(uint64_t stream_id,
                    ArrayView<const uint8_t> data,
                    bool fin) override;
  void OnStreamReset(uint64_t stream_id, uint64_t app_error_code) override;
  void OnStreamStopSending(uint64_t stream_id,
                           uint64_t app_error_code) override;
  void OnDatagramReceived(ArrayView<const uint8_t> data) override;

 private:
  struct PendingOutboundChunk {
    std::vector<uint8_t> data;
    bool fin = false;
  };

  struct InboundH3RequestState {
    Http3ResponseCallback callback;
    std::vector<uint8_t> rx_buf;
    Http3Response resp;
    bool headers_parsed = false;
  };

  struct InboundUniStreamState {
    bool type_parsed = false;
    uint64_t stream_type = 0;
    bool wt_session_parsed = false;
    uint64_t wt_session_id = 0;
    bool opened_notified = false;
    bool fin_received = false;
    bool rejected = false;
    std::chrono::steady_clock::time_point created_at =
        std::chrono::steady_clock::now();
    std::vector<uint8_t> buf;
  };

  struct InboundBidiStreamState {
    bool prefix_parsed = false;
    uint64_t wt_session_id = 0;
    bool opened_notified = false;
    bool fin_received = false;
    bool rejected = false;
    std::chrono::steady_clock::time_point created_at =
        std::chrono::steady_clock::now();
    std::vector<uint8_t> buf;
  };

  void TrySendExtendedConnectLocked();
  void HandleControlStreamFramesLocked(std::vector<uint8_t>* buf,
                                       uint64_t* out_h3_error);
  void HandleConnectStreamBytesLocked(ArrayView<const uint8_t> data, bool fin);
  std::vector<uint8_t> MaybeBuildFlowControlDataFrameLocked();
  size_t ComputeTotalEarlyBufferedBytesLocked() const;
  void SweepExpiredOrMismatchedEarlyStreamsLocked(
      std::vector<std::function<void()>>* actions);
  void InvokeObserver(const std::function<void(IMoqQuicEngineObserver*)>& fn);

  std::shared_ptr<IMoqQuicEngine> inner_quic_;
  mutable std::mutex mu_;
  std::condition_variable observer_cv_;
  uint32_t active_observer_calls_ = 0;
  IMoqQuicEngineObserver* observer_ = nullptr;
  std::string authority_;
  bool explicit_authority_ = false;
  std::string path_;
  std::vector<std::string> available_protocols_;
  std::string negotiated_wt_protocol_;

  bool quic_connected_ = false;
  bool peer_settings_received_ = false;
  bool connect_sent_ = false;
  bool wt_established_ = false;
  bool wt_draining_ = false;
  bool wt_pending_flushed_ = false;
  bool closed_ = false;
  bool disconnect_notified_ = false;
  int connect_close_error_ = 0;
  Http3Settings peer_settings_;

  bool local_ctrl_stream_opened_ = false;
  uint64_t local_ctrl_stream_id_ = 0;
  std::optional<uint64_t> peer_ctrl_stream_id_;
  uint64_t connect_stream_id_ = 0;
  std::vector<uint8_t> connect_rx_buf_;
  std::vector<uint8_t> capsule_rx_buf_;

  // WebTransport draft-14 会话级接收流控窗口追踪与自动补充状态。
  uint64_t wt_rx_bytes_consumed_ = 0;
  uint64_t wt_local_max_data_ = 16 * 1024 * 1024;
  uint64_t wt_closed_peer_uni_streams_ = 0;
  uint64_t wt_local_max_streams_uni_ = 16384;
  uint64_t wt_closed_peer_bidi_streams_ = 0;
  uint64_t wt_local_max_streams_bidi_ = 1024;
  uint64_t wt_peer_max_data_ = 16 * 1024 * 1024;
  uint64_t wt_peer_max_streams_uni_ = 16384;
  uint64_t wt_peer_max_streams_bidi_ = 1024;

  struct LocalWtStreamState {
    bool is_uni = false;
    bool local_fin = false;
    bool remote_fin = false;
  };

  // 在 Extended CONNECT 完成前创建的流与待发送块暂存区。
  std::map<uint64_t, LocalWtStreamState> wt_local_streams_;
  std::set<uint64_t> wt_prefix_written_;
  std::map<uint64_t, std::vector<PendingOutboundChunk>> pending_wt_writes_;
  std::vector<std::vector<uint8_t>> pending_wt_datagrams_;
  std::vector<std::pair<Http3Request, Http3ResponseCallback>>
      pending_h3_requests_;

  std::map<uint64_t, InboundH3RequestState> h3_responses_;
  std::map<uint64_t, InboundUniStreamState> inbound_uni_;
  std::map<uint64_t, InboundBidiStreamState> inbound_bidi_;
  std::vector<std::vector<uint8_t>> early_rx_datagrams_;
};

// 服务端 HTTP/3 + WebTransport 多路复用连接处理器：
// 可挂载在任意 ALPN="h3" 的 QuicServerSessionHandle 之上，同时处理常规 HTTP/3 请求
// （通过 Http3RequestHandler 回调）并将 WebTransport Extended CONNECT 会话透明桥接为
// 标准 QuicServerSessionHandle 投递至上层 IQuicServerVisitor（例如 EmbeddedMoqRelayServer）。
class Http3ServerConnection final
    : public std::enable_shared_from_this<Http3ServerConnection> {
 public:
  using Http3RequestHandler =
      std::function<Http3Response(const Http3Request& request)>;

  Http3ServerConnection(std::shared_ptr<QuicServerSessionHandle> raw_quic,
                        IQuicServerVisitor* wt_visitor,
                        std::vector<std::string> supported_wt_protocols,
                        Http3RequestHandler http_handler,
                        uint64_t virtual_session_id_base = 0);
  ~Http3ServerConnection();

  void Start();
  void OnQuicDisconnected(int error_code);
  void OnQuicStreamOpened(uint64_t stream_id, bool unidirectional);
  void OnQuicStreamData(uint64_t stream_id,
                        ArrayView<const uint8_t> data,
                        bool fin);
  void OnQuicStreamReset(uint64_t stream_id, uint64_t app_error_code);
  void OnQuicStreamStopSending(uint64_t stream_id, uint64_t app_error_code);
  void OnQuicDatagramReceived(ArrayView<const uint8_t> data);

 private:
  class WtSessionHandle;

  struct ClientBidiStream {
    enum class Kind : uint8_t {
      kUndecided,
      kHttp3Request,
      kWebTransportConnect,
      kWebTransportBidiData,
    };
    Kind kind = Kind::kUndecided;
    uint64_t wt_connect_stream_id = 0;
    bool opened_notified = false;
    bool headers_received = false;
    bool fin_received = false;
    bool rejected = false;
    std::chrono::steady_clock::time_point created_at =
        std::chrono::steady_clock::now();
    Http3Request h3_req;
    std::vector<uint8_t> rx_buf;
    std::vector<uint8_t> capsule_buf;
  };

  struct ClientUniStream {
    bool type_parsed = false;
    uint64_t stream_type = 0;
    bool wt_session_parsed = false;
    uint64_t wt_connect_stream_id = 0;
    bool opened_notified = false;
    bool fin_received = false;
    bool rejected = false;
    std::chrono::steady_clock::time_point created_at =
        std::chrono::steady_clock::now();
    std::vector<uint8_t> rx_buf;
  };

  void ProcessControlFrames(std::vector<uint8_t>* buf);
  void ProcessHttpOrConnectFrames(uint64_t stream_id,
                                  ClientBidiStream* st,
                                  bool fin);
  void FlushEarlyBufferedSessionTraffic(uint64_t connect_sid,
                                        WtSessionHandle* wt_sess);
  void TerminateWtSession(uint64_t connect_sid, int error_code);
  void CleanupServerStreamsForConnectSid(uint64_t connect_sid);
  void CloseConnectionWithError(uint64_t h3_error_code);
  void RecordClosedWtConnectSid(uint64_t connect_sid);
  void RejectEarlyStreamsForConnectSid(uint64_t connect_sid, uint64_t h3_err);
  size_t ComputeTotalUnclaimedEarlyBytes() const;
  void SweepStaleUnclaimedStreams();

  std::shared_ptr<QuicServerSessionHandle> raw_quic_;
  IQuicServerVisitor* const wt_visitor_;
  std::vector<std::string> supported_wt_protocols_;
  Http3RequestHandler http_handler_;
  uint64_t next_virtual_session_id_ = 0;

  bool conn_closed_ = false;
  bool peer_settings_received_ = false;
  Http3Settings peer_settings_;
  bool local_ctrl_stream_opened_ = false;
  uint64_t local_ctrl_stream_id_ = 0;
  std::optional<uint64_t> peer_ctrl_stream_id_;

  // connect_stream_id -> 虚拟 WebTransport 服务端会话句柄
  std::map<uint64_t, std::shared_ptr<WtSessionHandle>> wt_sessions_;
  std::set<uint64_t> closed_wt_connect_sids_;
  // raw QUIC stream_id -> 归属的 connect_stream_id（用于服务端主动打开的流，跨线程互斥保护）
  mutable std::mutex server_streams_mu_;
  std::map<uint64_t, uint64_t> server_stream_to_connect_sid_;
  std::map<uint64_t, ClientBidiStream> client_bidi_streams_;
  std::map<uint64_t, ClientUniStream> client_uni_streams_;
  std::map<uint64_t, std::vector<std::vector<uint8_t>>> early_datagrams_;
};

// 独立运行的 Boost.Asio HTTP/3 + WebTransport 服务端（监听 ALPN "h3"）。
class AsioHttp3WebTransportServer final : public IQuicServerVisitor {
 public:
  AsioHttp3WebTransportServer(
      Clock* clock,
      TaskQueueBoost* network_queue,
      IQuicServerVisitor* wt_visitor,
      std::string bind_ip = "0.0.0.0",
      std::vector<std::string> supported_wt_protocols = {"moqt-17"},
      Http3ServerConnection::Http3RequestHandler http_handler = {});
  ~AsioHttp3WebTransportServer() override;

  bool Start(uint16_t udp_port = 0);
  void Stop();
  uint16_t local_port() const { return quic_server_.local_port(); }
  std::array<uint8_t, 32> certificate_sha256() const {
    return quic_server_.certificate_sha256();
  }
  std::string certificate_sha256_hex() const {
    return quic_server_.certificate_sha256_hex();
  }

  void OnServerSessionConnected(
      std::shared_ptr<QuicServerSessionHandle> session) override;
  void OnServerSessionDisconnected(uint64_t session_id,
                                   int error_code) override;
  void OnServerStreamOpened(uint64_t session_id,
                            uint64_t stream_id,
                            bool unidirectional) override;
  void OnServerStreamData(uint64_t session_id,
                          uint64_t stream_id,
                          ArrayView<const uint8_t> data,
                          bool fin) override;
  void OnServerStreamReset(uint64_t session_id,
                           uint64_t stream_id,
                           uint64_t app_error_code) override;
  void OnServerStreamStopSending(uint64_t session_id,
                                 uint64_t stream_id,
                                 uint64_t app_error_code) override;
  void OnServerDatagramReceived(uint64_t session_id,
                                ArrayView<const uint8_t> data) override;

 private:
  IQuicServerVisitor* const wt_visitor_;
  std::vector<std::string> supported_wt_protocols_;
  Http3ServerConnection::Http3RequestHandler http_handler_;
  AsioQuicServer quic_server_;
  uint64_t next_virtual_id_base_ = 1'000'000;
  std::map<uint64_t, std::shared_ptr<Http3ServerConnection>> h3_conns_;
};

}  // namespace rtc

#endif  // SRC_MOQ_HTTP3_WEBTRANSPORT_H_
