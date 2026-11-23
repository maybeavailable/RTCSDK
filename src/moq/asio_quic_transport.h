#ifndef SRC_MOQ_ASIO_QUIC_TRANSPORT_H_
#define SRC_MOQ_ASIO_QUIC_TRANSPORT_H_

// 基于 Boost.Asio UDP 套接字与 OpenSSL 3.0 EVP 原语实现的 RFC 9000（QUIC v1 传输）、
// RFC 9001（使用 TLS 保护 QUIC）与 RFC 9002（QUIC 丢包检测与拥塞控制），
// 并在 TaskQueueBoost 上进行线程隔离。

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/ip/udp.hpp>

#include "api/array_view.h"
#include "api/session_backend_interface.h"
#include "api/units.h"
#include "moq/quic_congestion_control.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"
#include "rtc_base/time_utils.h"

namespace rtc {

inline constexpr uint32_t kQuicVersion1 = 0x00000001u;
inline constexpr size_t kQuicCidLength = 8;
inline constexpr size_t kQuicMaxCidLength = 20;
inline constexpr size_t kQuicMaxDatagramSize = 1200;
inline constexpr size_t kQuicMinClientInitialSize = 1200;
inline constexpr size_t kQuicAeadTagLength = 16;

// 遵循 RFC 9000 第 17.2 节的 0..20 字节可变长度连接 ID（默认生成 8 字节本地连接 ID）。
struct QuicCid {
  std::array<uint8_t, kQuicMaxCidLength> bytes{};
  uint8_t length = static_cast<uint8_t>(kQuicCidLength);

  QuicCid() = default;
  QuicCid(const uint8_t* src, size_t n) { Assign(src, n); }

  void Assign(const uint8_t* src, size_t n) {
    length = static_cast<uint8_t>(std::min(n, kQuicMaxCidLength));
    bytes.fill(0);
    if (length > 0 && src != nullptr) {
      std::memcpy(bytes.data(), src, length);
    }
  }

  uint8_t* data() { return bytes.data(); }
  const uint8_t* data() const { return bytes.data(); }
  size_t size() const { return length; }
  bool empty() const { return length == 0; }
  const uint8_t* begin() const { return bytes.data(); }
  const uint8_t* end() const { return bytes.data() + length; }

  operator ArrayView<const uint8_t>() const {
    return ArrayView<const uint8_t>(bytes.data(), length);
  }

  bool operator==(const QuicCid& other) const {
    return length == other.length &&
           std::memcmp(bytes.data(), other.bytes.data(), length) == 0;
  }
  bool operator!=(const QuicCid& other) const { return !(*this == other); }
  bool operator<(const QuicCid& other) const {
    if (length != other.length) {
      return length < other.length;
    }
    return std::memcmp(bytes.data(), other.bytes.data(), length) < 0;
  }
};

enum class QuicEncryptionLevel : uint8_t {
  kInitial = 0,
  kHandshake = 1,
  kOneRtt = 2,
};

struct QuicTrafficKeys {
  std::array<uint8_t, 32> secret{};
  std::array<uint8_t, 16> aead_key{};
  std::array<uint8_t, 12> aead_iv{};
  std::array<uint8_t, 16> hp_key{};
  bool valid = false;
};

struct QuicTransportParameters {
  uint64_t max_idle_timeout_ms = 30'000;
  uint64_t initial_max_data = 16 * 1024 * 1024;
  uint64_t initial_max_stream_data_bidi_local = 2 * 1024 * 1024;
  uint64_t initial_max_stream_data_bidi_remote = 2 * 1024 * 1024;
  uint64_t initial_max_stream_data_uni = 4 * 1024 * 1024;
  uint64_t initial_max_streams_bidi = 256;
  uint64_t initial_max_streams_uni = 16384;
  uint64_t active_connection_id_limit = 4;
  uint64_t max_datagram_frame_size = kQuicMaxDatagramSize;
  bool reset_stream_at_supported = true;
  QuicCid initial_source_cid{};
  QuicCid original_destination_cid{};
  bool has_original_destination_cid = false;

  std::vector<uint8_t> Encode() const;
  static std::optional<QuicTransportParameters> Decode(
      ArrayView<const uint8_t> data);
};

// 遵循 RFC 9001 与 RFC 9000 附录 A 的加密及数据包保护原语。
class QuicCryptoUtils {
 public:
  static QuicCid GenerateRandomCid();

  static bool HkdfExtract(ArrayView<const uint8_t> salt,
                          ArrayView<const uint8_t> ikm,
                          std::array<uint8_t, 32>* out_prk);

  static bool HkdfExpandLabel(ArrayView<const uint8_t> secret,
                              std::string_view label,
                              ArrayView<const uint8_t> context,
                              uint8_t* out,
                              size_t out_len);

  static bool DeriveTrafficKeysFromSecret(
      const std::array<uint8_t, 32>& secret,
      QuicTrafficKeys* out_keys);

  // 根据 RFC 9001 第 5.2 节派生客户端与服务端 Initial 密钥。
  static bool DeriveInitialKeys(ArrayView<const uint8_t> client_dst_cid,
                                QuicTrafficKeys* out_client_keys,
                                QuicTrafficKeys* out_server_keys,
                                std::array<uint8_t, 32>* out_initial_secret);

  static bool GenerateX25519KeyPair(std::array<uint8_t, 32>* out_private_key,
                                    std::array<uint8_t, 32>* out_public_key);

  static bool ComputeX25519SharedSecret(
      const std::array<uint8_t, 32>& private_key,
      const std::array<uint8_t, 32>& peer_public_key,
      std::array<uint8_t, 32>* out_shared_secret);

  static std::array<uint8_t, 32> Sha256(ArrayView<const uint8_t> data);

  static bool HmacSha256(ArrayView<const uint8_t> key,
                         ArrayView<const uint8_t> data,
                         std::array<uint8_t, 32>* out_mac);

  // 遵循 RFC 9000 附录 A.3 的包号重构算法。
  static uint64_t DecodePacketNumber(int64_t largest_pn,
                                     uint64_t truncated_pn,
                                     size_t pn_nbits);

  // 使用 AES-128-GCM 加密负载，并对未掩码包头（其末尾 4 字节须存放大端序截断包号）
  // 应用 AES-128-ECB 包头保护。根据 RFC 9001 第 5.4.2 节，不足 4 字节的明文将填充
  // PADDING (0x00) 帧。
  static std::vector<uint8_t> ProtectPacket(
      const QuicTrafficKeys& keys,
      uint64_t full_packet_number,
      ArrayView<const uint8_t> unmasked_header_without_length,
      bool is_long_header,
      ArrayView<const uint8_t> plaintext,
      size_t min_datagram_bytes = 0);

  struct UnprotectedPacket {
    QuicEncryptionLevel level = QuicEncryptionLevel::kOneRtt;
    uint8_t unmasked_first_byte = 0;
    QuicCid dcid{};
    QuicCid scid{};
    uint64_t packet_number = 0;
    std::vector<uint8_t> plaintext;
    size_t consumed_datagram_bytes = 0;
  };

  // 解析包头不变量、移除包头保护、重构包号并校验 AES-128-GCM 认证标签。
  // 若数据包无效或遭篡改则返回 std::nullopt，且不修改调用方状态。
  static std::optional<UnprotectedPacket> InspectHeaderIds(
      ArrayView<const uint8_t> datagram,
      bool* out_is_long_header,
      QuicEncryptionLevel* out_level,
      QuicCid* out_dcid,
      QuicCid* out_scid,
      size_t* out_total_packet_len);

  static std::optional<UnprotectedPacket> UnprotectPacket(
      ArrayView<const uint8_t> datagram,
      const QuicTrafficKeys& keys,
      int64_t largest_authenticated_pn);
};

// 选择性确认（SACK）区间跟踪器及遵循 RFC 9000 第 19.3 节的 ACK 编解码器。
class QuicAckRangeSet {
 public:
  struct Range {
    uint64_t smallest = 0;
    uint64_t largest = 0;
  };

  void RecordReceived(uint64_t pn, bool ack_eliciting);
  bool Contains(uint64_t pn) const;
  bool empty() const { return ranges_.empty(); }
  int64_t largest_received() const {
    return ranges_.empty() ? -1 : static_cast<int64_t>(ranges_.back().largest);
  }
  bool needs_ack() const { return ack_needed_; }
  void ClearAckNeeded() { ack_needed_ = false; }

  void EncodeAckFrame(uint64_t ack_delay_us, std::vector<uint8_t>* out) const;
  static bool DecodeAckFrame(ArrayView<const uint8_t> data,
                             size_t* offset,
                             uint64_t* out_ack_delay_us,
                             std::vector<Range>* out_ranges);

 private:
  std::vector<Range> ranges_;
  bool ack_needed_ = false;
};

// 单流按偏移量有序的字节重组器，支持乱序 STREAM 帧重组、FIN 标志跟踪以及收到 RESET_STREAM 时立即释放缓冲区。
class QuicStreamReceiveBuffer {
 public:
  void InsertChunk(uint64_t offset, ArrayView<const uint8_t> data, bool fin);
  bool ExtractContiguous(std::vector<uint8_t>* out_data, bool* out_fin);
  void Reset();

  bool is_reset() const { return reset_; }
  bool is_complete() const { return fin_delivered_ || reset_; }

 private:
  uint64_t next_deliver_offset_ = 0;
  std::optional<uint64_t> final_offset_;
  bool fin_delivered_ = false;
  bool reset_ = false;
  std::map<uint64_t, std::vector<uint8_t>> chunks_;
};

// 实现 IMoqQuicEngine 接口的客户端 Boost.Asio QUIC v1 传输引擎。
class AsioQuicClientEngine final
    : public IMoqQuicEngine,
      public std::enable_shared_from_this<AsioQuicClientEngine> {
 public:
  AsioQuicClientEngine(
      Clock* clock,
      TaskQueueBoost* network_queue,
      std::unique_ptr<IQuicCongestionController> initial_cc = nullptr);
  ~AsioQuicClientEngine() override;

  AsioQuicClientEngine(const AsioQuicClientEngine&) = delete;
  AsioQuicClientEngine& operator=(const AsioQuicClientEngine&) = delete;

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

  QuicCongestionSnapshot GetCongestionSnapshot() const override;

  int SetCongestionController(
      std::unique_ptr<IQuicCongestionController> controller) override;

  void SetSimulatedDropRates(double tx_drop_prob, double rx_drop_prob);

 private:
  class Impl;
  std::shared_ptr<Impl> impl_;
};

// 面向 MoQ 中继（Relay）及 HTTP/3 WebTransport 的服务端单连接句柄与访问者回调接口。
class QuicServerSessionHandle {
 public:
  virtual ~QuicServerSessionHandle() = default;

  virtual uint64_t session_id() const = 0;
  virtual std::string negotiated_alpn() const { return {}; }
  virtual uint64_t OpenBidirectionalStream() = 0;
  virtual uint64_t OpenUnidirectionalStream(uint8_t publisher_priority,
                                            int64_t send_order) = 0;
  virtual int WriteStream(uint64_t stream_id,
                          ArrayView<const uint8_t> data,
                          bool fin) = 0;
  virtual void ResetStream(uint64_t stream_id, uint64_t app_error_code) = 0;
  virtual void StopSending(uint64_t /*stream_id*/,
                           uint64_t /*app_error_code*/) {}
  virtual int SendDatagram(ArrayView<const uint8_t> /*data*/) {
    return RTC_ERR_PROTOCOL;
  }
  virtual size_t max_datagram_size() const { return 0; }
  virtual void Close(uint64_t app_error_code) = 0;
  virtual QuicCongestionSnapshot GetCongestionSnapshot() const = 0;
};

class IQuicServerVisitor {
 public:
  virtual ~IQuicServerVisitor() = default;

  virtual void OnServerSessionConnected(
      std::shared_ptr<QuicServerSessionHandle> session) = 0;
  virtual void OnServerSessionDisconnected(uint64_t session_id,
                                           int error_code) = 0;
  virtual void OnServerStreamOpened(uint64_t session_id,
                                    uint64_t stream_id,
                                    bool unidirectional) = 0;
  virtual void OnServerStreamData(uint64_t session_id,
                                  uint64_t stream_id,
                                  ArrayView<const uint8_t> data,
                                  bool fin) = 0;
  virtual void OnServerStreamReset(uint64_t session_id,
                                   uint64_t stream_id,
                                   uint64_t app_error_code) = 0;
  virtual void OnServerStreamStopSending(uint64_t /*session_id*/,
                                         uint64_t /*stream_id*/,
                                         uint64_t /*app_error_code*/) {}
  virtual void OnServerDatagramReceived(uint64_t /*session_id*/,
                                        ArrayView<const uint8_t> /*data*/) {}
};

// 按连接 ID（Connection ID）多路复用的多会话 Boost.Asio UDP QUIC v1 服务端。
class AsioQuicServer {
 public:
  AsioQuicServer(Clock* clock,
                 TaskQueueBoost* network_queue,
                 IQuicServerVisitor* visitor,
                 std::string bind_ip = "0.0.0.0",
                 std::string expected_alpn = "moqt-17");
  AsioQuicServer(Clock* clock,
                 TaskQueueBoost* network_queue,
                 IQuicServerVisitor* visitor,
                 std::string bind_ip,
                 std::vector<std::string> supported_alpns);
  ~AsioQuicServer();

  AsioQuicServer(const AsioQuicServer&) = delete;
  AsioQuicServer& operator=(const AsioQuicServer&) = delete;

  bool Start(uint16_t udp_port = 0);
  void Stop();

  uint16_t local_port() const { return local_port_; }
  std::array<uint8_t, 32> certificate_sha256() const;
  std::string certificate_sha256_hex() const;
  void SetSimulatedDropRates(double rx_drop_prob, double tx_drop_prob);
  void SetCongestionControllerFactory(
      std::shared_ptr<IQuicCongestionControllerFactory> factory);

 private:
  class ServerImpl;
  std::shared_ptr<ServerImpl> impl_;
  uint16_t local_port_ = 0;
};

}  // namespace rtc

#endif  // SRC_MOQ_ASIO_QUIC_TRANSPORT_H_