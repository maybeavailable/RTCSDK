#ifndef SRC_PC_SCTP_DATA_CHANNEL_H_
#define SRC_PC_SCTP_DATA_CHANNEL_H_

// 标准 WebRTC SCTP over DTLS 数据通道协议栈实现，完整遵循：
//   - RFC 4960 / RFC 3309：SCTP 核心协议、CRC-32c 校验、四次握手、分片重组、SACK 与拥塞控制
//   - RFC 3758：SCTP 部分可靠性扩展（PR-SCTP / FORWARD-TSN，支持限次重传与生存期超时跳过）
//   - RFC 6525：SCTP 流重置扩展（RE-CONFIG 双向通道优雅关闭）
//   - RFC 8261 / RFC 8831 / RFC 8832：SCTP over DTLS 封装、DCEP 带内通道协商与二进制/UTF-8 帧传输

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "api/array_view.h"
#include "api/units.h"
#include "pc/dtls_srtp_transport.h"
#include "rtc_video_engine.hpp"

namespace rtc {

// 计算遵循 RFC 4960 附录 B 与 RFC 3309 的 Castagnoli CRC-32c 校验和。
uint32_t ComputeSctpCrc32c(ArrayView<const uint8_t> data);

// 计算将偏移量 [8..11] 视为零字节时的整包 SCTP CRC-32c 校验和。
uint32_t ComputeSctpPacketCrc32c(ArrayView<const uint8_t> packet);

class SctpDataChannelObserver {
 public:
  virtual ~SctpDataChannelObserver() = default;

  // 请求通过底层 DTLS 应用数据通道发送编码后的 SCTP 分组。
  virtual bool SendSctpPacketOverDtls(ArrayView<const uint8_t> packet) = 0;

  // 数据通道状态变更通知（OPEN / CLOSED 等）。
  virtual void OnSctpDataChannelState(int channel_id,
                                      const std::string& label,
                                      rtc_data_channel_state_e state) = 0;

  // 收到完整重组后的 WebRTC DataChannel 应用消息。
  virtual void OnSctpDataChannelMessage(int channel_id,
                                        bool is_binary,
                                        std::vector<uint8_t> payload) = 0;
};

class SctpDataChannelManager {
 public:
  SctpDataChannelManager(Clock* clock, SctpDataChannelObserver* observer);
  ~SctpDataChannelManager() = default;

  SctpDataChannelManager(const SctpDataChannelManager&) = delete;
  SctpDataChannelManager& operator=(const SctpDataChannelManager&) = delete;

  // 配置本端与远端 SCTP 端口及 DTLS 角色，并在 DTLS 就绪后启动四次握手。
  void ConfigureAndStart(DtlsRole dtls_role,
                         uint16_t local_port,
                         uint16_t remote_port);

  // 关闭关联并清理所有挂起队列。
  void Shutdown();

  bool IsAssociationEstablished() const {
    return assoc_state_ == AssocState::kEstablished;
  }

  // 创建本地数据通道（支持连接前预创建，返回 >=0 的稳定 channel_id）。
  int CreateDataChannel(const DataChannelConfig& config);

  // 在指定数据通道上发送消息（若通道尚在握手中则进入发送预备队列）。
  int SendData(int channel_id,
               ArrayView<const uint8_t> payload,
               bool is_binary);

  // 关闭指定数据通道并发送流重置/关闭通知。
  int CloseDataChannel(int channel_id);

  // 处理从 DTLS 应用数据层解密出的原始 SCTP 报文。
  void OnInboundSctpPacket(ArrayView<const uint8_t> packet, Timestamp now);

  // 周期性驱动 T1 握手重传、T3 数据重传、延迟 SACK 与 PR-SCTP 超时推进（建议每 20~25ms 调用一次）。
  void OnPeriodicTick(Timestamp now);

 private:
  enum class AssocState {
    kClosed = 0,
    kCookieWait = 1,
    kCookieEchoed = 2,
    kEstablished = 3,
  };

  struct TsnLess {
    bool operator()(uint32_t a, uint32_t b) const {
      return static_cast<int32_t>(a - b) < 0;
    }
  };

  struct SsnLess {
    bool operator()(uint16_t a, uint16_t b) const {
      return static_cast<int16_t>(a - b) < 0;
    }
  };

  struct PendingUserMessage {
    std::vector<uint8_t> payload;
    bool is_binary = true;
    Timestamp queued_at = Timestamp::MinusInfinity();
  };

  struct ChannelEntry {
    int channel_id = 0;
    DataChannelConfig config;
    std::optional<uint16_t> sctp_sid;
    rtc_data_channel_state_e state = RTC_DATA_CHANNEL_CONNECTING;
    bool open_sent = false;
    bool open_notified = false;
    uint16_t next_tx_ssn = 0;
    std::deque<PendingUserMessage> pending_messages;
  };

  struct OutboundDataChunk {
    uint64_t msg_seq_id = 0;
    uint32_t tsn = 0;
    uint16_t sid = 0;
    uint16_t ssn = 0;
    uint32_t ppid = 0;
    uint8_t flags = 0;  // B=0x02, E=0x01, U=0x04
    std::vector<uint8_t> payload;
    bool ordered = true;
    int32_t max_retransmits = -1;
    int32_t max_lifetime_ms = -1;
    Timestamp created_at = Timestamp::MinusInfinity();
    Timestamp last_sent_at = Timestamp::MinusInfinity();
    uint32_t tx_count = 0;
    uint32_t gap_reports = 0;
    bool in_flight = false;
    bool acked = false;
    bool abandoned = false;
    bool needs_retransmit = false;
  };

  struct InboundDataFragment {
    uint32_t tsn = 0;
    uint16_t sid = 0;
    uint16_t ssn = 0;
    uint32_t ppid = 0;
    uint8_t flags = 0;
    std::vector<uint8_t> payload;
  };

  struct ReassembledMessage {
    uint32_t ppid = 0;
    std::vector<uint8_t> payload;
  };

  static bool IsTsnBefore(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) < 0;
  }
  static bool IsTsnBeforeOrEqual(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) <= 0;
  }
  static bool IsSsnBeforeOrEqual(uint16_t a, uint16_t b) {
    return static_cast<int16_t>(a - b) <= 0;
  }

  std::vector<uint8_t> BuildSctpPacket(
      uint32_t vtag,
      ArrayView<const uint8_t> chunks_bytes) const;
  bool SendChunksPacket(uint32_t vtag, ArrayView<const uint8_t> chunks_bytes);

  void SendInitChunk(Timestamp now);
  void HandleInitChunk(ArrayView<const uint8_t> chunk_body, Timestamp now);
  void HandleInitAckChunk(ArrayView<const uint8_t> chunk_body, Timestamp now);
  void HandleCookieEchoChunk(ArrayView<const uint8_t> chunk_body, Timestamp now);
  void HandleCookieAckChunk(Timestamp now);
  void OnAssociationEstablished(Timestamp now);

  void HandleDataChunk(uint8_t chunk_flags,
                       ArrayView<const uint8_t> chunk_body,
                       Timestamp now);
  void HandleSackChunk(ArrayView<const uint8_t> chunk_body, Timestamp now);
  void HandleHeartbeatChunk(ArrayView<const uint8_t> chunk_body);
  void HandleForwardTsnChunk(ArrayView<const uint8_t> chunk_body);
  void HandleReconfigChunk(ArrayView<const uint8_t> chunk_body);

  void TryReassembleAround(uint32_t pivot_tsn);
  void DeliverReassembledMessage(uint16_t sid,
                                 uint16_t ssn,
                                 uint32_t ppid,
                                 bool unordered,
                                 std::vector<uint8_t> payload);
  void DrainOrderedStream(uint16_t sid);
  void HandleDcepMessage(uint16_t sid, ArrayView<const uint8_t> payload);
  void DeliverUserPayloadOnStream(uint16_t sid,
                                  uint32_t ppid,
                                  std::vector<uint8_t> payload);

  uint16_t AllocateNextLocalStreamId();
  void ActivateChannelIfReady(ChannelEntry* ch, Timestamp now);
  void SendDcepOpen(const ChannelEntry& ch, Timestamp now);
  void SendDcepAck(uint16_t sid, Timestamp now);
  void EnqueueSctpMessage(uint16_t sid,
                          bool ordered,
                          uint16_t ssn,
                          uint32_t ppid,
                          ArrayView<const uint8_t> payload,
                          int32_t max_retransmits,
                          int32_t max_lifetime_ms,
                          Timestamp now);
  void FlushTransmitQueue(Timestamp now);
  void CheckAbandonedAndSendForwardTsn(Timestamp now);
  void SendSackChunk(Timestamp now);

  Clock* const clock_;
  SctpDataChannelObserver* const observer_;

  bool started_ = false;
  DtlsRole dtls_role_ = DtlsRole::kClient;
  uint16_t local_port_ = 5000;
  uint16_t remote_port_ = 5000;
  AssocState assoc_state_ = AssocState::kClosed;

  uint32_t local_vtag_ = 0;
  uint32_t peer_vtag_ = 0;
  uint32_t local_initial_tsn_ = 0;
  uint32_t next_tx_tsn_ = 0;
  uint32_t last_acked_tx_tsn_ = 0;
  uint32_t advanced_peer_ack_point_ = 0;
  bool peer_supports_prsctp_ = true;

  bool has_peer_initial_tsn_ = false;
  uint32_t peer_cum_tsn_ack_ = 0;
  std::set<uint32_t, TsnLess> rx_seen_tsns_;
  std::map<uint32_t, InboundDataFragment, TsnLess> rx_fragments_;
  std::map<uint16_t, uint16_t> next_expected_ssn_;
  std::map<uint16_t, std::map<uint16_t, ReassembledMessage, SsnLess>>
      ordered_ready_;
  bool sack_needed_ = false;
  uint32_t packets_since_sack_ = 0;
  Timestamp sack_deadline_ = Timestamp::PlusInfinity();

  std::vector<uint8_t> pending_cookie_;
  Timestamp handshake_started_at_ = Timestamp::MinusInfinity();
  Timestamp last_handshake_tx_ = Timestamp::MinusInfinity();
  uint32_t handshake_rtx_count_ = 0;

  // 拥塞窗口与重传定时器参数（遵循 RFC 4960 第 6 / 7 节）。
  size_t cwnd_bytes_ = 4 * 1200;
  size_t ssthresh_bytes_ = 128 * 1024;
  size_t partial_bytes_acked_ = 0;
  size_t flight_bytes_ = 0;
  int64_t srtt_us_ = 100'000;
  int64_t rttvar_us_ = 50'000;
  int64_t rto_us_ = 200'000;
  bool has_rtt_sample_ = false;
  Timestamp t3_rtx_deadline_ = Timestamp::PlusInfinity();

  uint64_t next_msg_seq_id_ = 1;
  std::map<uint32_t, OutboundDataChunk, TsnLess> outbound_chunks_;
  uint32_t next_reconfig_seq_ = 1;

  int next_channel_id_ = 0;
  uint16_t next_even_sid_ = 0;
  uint16_t next_odd_sid_ = 1;
  std::map<int, ChannelEntry> channels_;
  std::map<uint16_t, int> sid_to_channel_id_;
  std::map<uint16_t, std::deque<std::pair<bool, std::vector<uint8_t>>>>
      early_rx_messages_;
};

}  // namespace rtc

#endif  // SRC_PC_SCTP_DATA_CHANNEL_H_
