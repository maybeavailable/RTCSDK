#ifndef SRC_PC_SCTP_DATA_CHANNEL_H_
#define SRC_PC_SCTP_DATA_CHANNEL_H_

// 标准 WebRTC SCTP over DTLS 数据通道协议栈实现，完整遵循：
//   - RFC 4960 / RFC 3309：SCTP 核心协议、CRC-32c 校验、四次握手、分片重组、SACK 与拥塞控制
//   - RFC 3758：SCTP 部分可靠性扩展（PR-SCTP / FORWARD-TSN，支持限次重传与生存期超时跳过）
//   - RFC 6525：SCTP 流重置扩展（RE-CONFIG 双向通道优雅关闭与流 ID 安全复用）
//   - RFC 8261 / RFC 8831 / RFC 8832：SCTP over DTLS 封装、DCEP 带内通道协商与二进制/UTF-8 帧传输

#include <array>
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

  // 数据通道状态变更通知（CONNECTING / OPEN / CLOSING / CLOSED）。
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
  static constexpr uint32_t kMaxSctpMessageSize = 4 * 1024 * 1024;

  SctpDataChannelManager(Clock* clock, SctpDataChannelObserver* observer);
  ~SctpDataChannelManager() = default;

  SctpDataChannelManager(const SctpDataChannelManager&) = delete;
  SctpDataChannelManager& operator=(const SctpDataChannelManager&) = delete;

  // 配置本端与远端 SCTP 端口及 DTLS 角色，并在 DTLS 就绪后启动四次握手。
  void ConfigureAndStart(DtlsRole dtls_role,
                         uint16_t local_port,
                         uint16_t remote_port);

  // 关闭关联并清理所有挂起队列与握手/流状态。
  void Shutdown();

  // 设置远端 SDP `a=max-message-size:` 上限（0 表示不额外限制，最高允许 kMaxSctpMessageSize）。
  void set_remote_max_message_size(uint32_t max_bytes);
  uint32_t remote_max_message_size() const { return remote_max_message_size_; }

  bool IsAssociationEstablished() const {
    return assoc_state_ == AssocState::kEstablished;
  }

  // 创建本地数据通道（支持连接前预创建，返回 >=0 的稳定 channel_id）。
  int CreateDataChannel(const DataChannelConfig& config);

  // 在指定数据通道上发送消息（若通道尚在握手中则进入发送预备队列）。
  int SendData(int channel_id,
               ArrayView<const uint8_t> payload,
               bool is_binary);

  // 关闭指定数据通道并执行 RFC 6525 / RFC 8831 双向流重置。
  int CloseDataChannel(int channel_id);

  // 处理从 DTLS 应用数据层解密出的原始 SCTP 报文。
  void OnInboundSctpPacket(ArrayView<const uint8_t> packet, Timestamp now);

  // 周期性驱动 T1 握手重传、T3 数据重传、延迟 SACK、RE-CONFIG 与 PR-SCTP 超时推进。
  void OnPeriodicTick(Timestamp now);

 private:
  enum class AssocState {
    kClosed = 0,
    kCookieWait = 1,
    kCookieEchoed = 2,
    kEstablished = 3,
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
    bool outbound_reset_queued = false;
    bool outbound_reset_done = false;
    bool inbound_reset_done = false;
    uint16_t next_tx_ssn = 0;
    size_t pending_bytes = 0;
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
    bool fast_retransmitted = false;
  };

  struct AbandonedStreamRecord {
    uint16_t ssn = 0;
    int64_t adv_tsn_unwrapped = -1;
  };

  struct OutgoingResetReq {
    uint32_t req_seq = 0;
    uint32_t last_assigned_tsn = 0;
    std::vector<uint16_t> sids;
    Timestamp last_sent_at = Timestamp::MinusInfinity();
    uint32_t rtx_count = 0;
  };

  struct DeferredInboundReset {
    uint32_t req_seq = 0;
    int64_t req_last_tsn_unwrapped = 0;
    std::vector<uint16_t> sids;
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

  struct PartialUserMessage {
    bool is_binary = true;
    std::vector<uint8_t> data;
  };

  uint32_t CurrentAdvertisedRwnd() const;
  size_t ComputeBufferedRxBytes() const;
  size_t EffectiveMaxMessageSize() const;
  uint32_t CurrentPeerReconfigRespSeq() const;
  void InitializeLocalAssociationParams();
  void ResetAssociationTransportState();
  void ClearStreamRxState(uint16_t sid, bool clear_early_rx);

  static bool IsTsnBefore(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) < 0;
  }
  static bool IsTsnBeforeOrEqual(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) <= 0;
  }
  static bool IsSsnBeforeOrEqual(uint16_t a, uint16_t b) {
    return static_cast<int16_t>(a - b) <= 0;
  }

  std::vector<uint8_t> BuildSctpPacketToPort(
      uint16_t dst_port,
      uint32_t vtag,
      ArrayView<const uint8_t> chunks_bytes) const;
  std::vector<uint8_t> BuildSctpPacket(
      uint32_t vtag,
      ArrayView<const uint8_t> chunks_bytes) const;
  bool SendChunksPacketToPort(uint16_t dst_port,
                              uint32_t vtag,
                              ArrayView<const uint8_t> chunks_bytes);
  bool SendChunksPacket(uint32_t vtag, ArrayView<const uint8_t> chunks_bytes);

  void SendInitChunk(Timestamp now);
  void HandleInitChunk(uint16_t src_port,
                       ArrayView<const uint8_t> chunk_body,
                       Timestamp now);
  void HandleInitAckChunk(ArrayView<const uint8_t> chunk_body, Timestamp now);
  void HandleCookieEchoChunk(uint32_t rx_vtag,
                             uint16_t src_port,
                             ArrayView<const uint8_t> chunk_body,
                             Timestamp now);
  void HandleCookieAckChunk(Timestamp now);
  void OnAssociationEstablished(Timestamp now);

  void HandleDataChunk(uint8_t chunk_flags,
                       ArrayView<const uint8_t> chunk_body,
                       Timestamp now);
  void HandleSackChunk(ArrayView<const uint8_t> chunk_body, Timestamp now);
  void HandleHeartbeatChunk(ArrayView<const uint8_t> chunk_body);
  void HandleForwardTsnChunk(ArrayView<const uint8_t> chunk_body, Timestamp now);
  void HandleReconfigChunk(ArrayView<const uint8_t> chunk_body, Timestamp now);

  void EnqueueOutgoingStreamReset(uint16_t sid, Timestamp now);
  void PumpOutboundStreamResetQueue(Timestamp now);
  void SendInflightOutboundReset(Timestamp now);
  void SendReconfigResponse(uint32_t resp_seq, uint32_t result);
  void ExecuteInboundStreamReset(const std::vector<uint16_t>& sids,
                                 Timestamp now);
  void ProcessPendingInboundResetIfReady(Timestamp now);
  void FinalizeChannelCloseIfReady(int channel_id);

  void TryReassembleAround(int64_t pivot_tsn);
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

  std::optional<uint16_t> AllocateNextLocalStreamId();
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
                          Timestamp created_at);
  void FlushTransmitQueue(Timestamp now,
                          bool allow_one_fast_rtx_packet = false);
  void CheckAbandonedAndSendForwardTsn(Timestamp now);
  void SendForwardTsnChunk(Timestamp now);
  void SendSackChunk(Timestamp now);

  Clock* const clock_;
  SctpDataChannelObserver* const observer_;

  bool started_ = false;
  DtlsRole dtls_role_ = DtlsRole::kClient;
  uint16_t local_port_ = 5000;
  uint16_t remote_port_ = 5000;
  AssocState assoc_state_ = AssocState::kClosed;
  uint32_t remote_max_message_size_ = 0;

  std::array<uint8_t, 32> cookie_hmac_key_{};
  uint32_t local_vtag_ = 0;
  uint32_t peer_vtag_ = 0;
  uint32_t local_initial_tsn_ = 0;
  uint32_t peer_initial_tsn_ = 0;
  uint16_t negotiated_mis_ = 1024;
  uint16_t peer_mis_ = 1024;
  uint32_t peer_rwnd_ = 1024 * 1024;
  int64_t next_tx_tsn_unwrapped_ = 0;
  int64_t last_acked_tx_tsn_unwrapped_ = -1;
  int64_t advanced_peer_ack_point_unwrapped_ = -1;
  bool peer_supports_prsctp_ = true;

  bool has_peer_initial_tsn_ = false;
  int64_t peer_cum_tsn_ack_unwrapped_ = 0;
  std::optional<uint32_t> last_peer_reconfig_seq_;
  std::set<int64_t> rx_seen_tsns_;
  std::map<int64_t, InboundDataFragment> rx_fragments_;
  std::map<uint16_t, int64_t> next_expected_ssn_;
  std::map<uint16_t, std::map<int64_t, ReassembledMessage>> ordered_ready_;
  std::map<uint16_t, PartialUserMessage> partial_rx_messages_;
  size_t rx_frag_bytes_ = 0;
  size_t ordered_ready_bytes_ = 0;
  size_t ordered_ready_count_ = 0;
  size_t partial_rx_bytes_ = 0;
  size_t early_rx_bytes_ = 0;
  size_t early_rx_count_ = 0;
  bool sack_needed_ = false;
  uint32_t packets_since_sack_ = 0;
  Timestamp sack_deadline_ = Timestamp::PlusInfinity();

  std::vector<uint8_t> pending_cookie_;
  Timestamp handshake_started_at_ = Timestamp::MinusInfinity();
  Timestamp last_handshake_tx_ = Timestamp::MinusInfinity();
  uint32_t handshake_rtx_count_ = 0;

  // 拥塞窗口、对端接收窗口与重传定时器参数（遵循 RFC 4960 第 6 / 7 节）。
  size_t cwnd_bytes_ = 4 * 1200;
  size_t ssthresh_bytes_ = 128 * 1024;
  size_t partial_bytes_acked_ = 0;
  size_t flight_bytes_ = 0;
  bool in_fast_recovery_ = false;
  int64_t fast_recovery_exit_point_ = -1;
  int64_t srtt_us_ = 100'000;
  int64_t rttvar_us_ = 50'000;
  int64_t rto_us_ = 200'000;
  bool has_rtt_sample_ = false;
  Timestamp t3_rtx_deadline_ = Timestamp::PlusInfinity();

  uint64_t next_msg_seq_id_ = 1;
  size_t outbound_buffered_bytes_ = 0;
  std::map<int64_t, OutboundDataChunk> outbound_chunks_;
  std::map<uint16_t, AbandonedStreamRecord> abandoned_ordered_streams_;
  uint32_t dup_sack_below_adv_count_ = 0;
  Timestamp last_forward_tsn_tx_ = Timestamp::MinusInfinity();
  bool in_flush_transmit_ = false;
  bool pending_reentrant_flush_ = false;
  bool pending_reentrant_fast_rtx_ = false;

  uint32_t next_reconfig_seq_ = 1;
  std::deque<uint16_t> queued_outbound_reset_sids_;
  std::optional<OutgoingResetReq> inflight_outbound_reset_;
  std::set<uint16_t> outbound_reset_pending_sids_;
  std::optional<DeferredInboundReset> pending_inbound_reset_;

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
