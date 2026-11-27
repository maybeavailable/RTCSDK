#include "pc/sctp_data_channel.h"

#include <algorithm>
#include <array>
#include <climits>
#include <cstdlib>
#include <cstring>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "modules/rtp_rtcp/byte_io.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {

// SCTP 数据块类型常量定义（RFC 4960 / RFC 3758 / RFC 6525）。
constexpr uint8_t kChunkData = 0x00;
constexpr uint8_t kChunkInit = 0x01;
constexpr uint8_t kChunkInitAck = 0x02;
constexpr uint8_t kChunkSack = 0x03;
constexpr uint8_t kChunkHeartbeat = 0x04;
constexpr uint8_t kChunkHeartbeatAck = 0x05;
constexpr uint8_t kChunkAbort = 0x06;
constexpr uint8_t kChunkShutdown = 0x07;
constexpr uint8_t kChunkShutdownAck = 0x08;
constexpr uint8_t kChunkCookieEcho = 0x0A;
constexpr uint8_t kChunkCookieAck = 0x0B;
constexpr uint8_t kChunkReconfig = 0x82;
constexpr uint8_t kChunkForwardTsn = 0xC0;

// SCTP DATA 块标志位（RFC 4960 第 3.3.1 节）。
constexpr uint8_t kDataFlagEnd = 0x01;
constexpr uint8_t kDataFlagBegin = 0x02;
constexpr uint8_t kDataFlagUnordered = 0x04;
constexpr uint8_t kDataFlagImmediateSack = 0x08;

// SCTP 可选参数类型（RFC 4960 / RFC 3758 / RFC 6525）。
constexpr uint16_t kParamStateCookie = 0x0007;
constexpr uint16_t kParamSupportedExtensions = 0x8008;
constexpr uint16_t kParamForwardTsnSupported = 0xC000;
constexpr uint16_t kParamOutgoingSsnResetReq = 0x000D;
constexpr uint16_t kParamReconfigResponse = 0x0010;

// RFC 6525 Re-configuration Response Result 编码。
constexpr uint32_t kReconfigResultSuccessPerformed = 1;
constexpr uint32_t kReconfigResultInProgress = 6;

// WebRTC DataChannel 负载协议标识符 PPID（RFC 8831 第 6.6 节 / RFC 8832）。
constexpr uint32_t kPpidDcep = 50;
constexpr uint32_t kPpidWebRtcString = 51;
constexpr uint32_t kPpidWebRtcBinaryPartial = 52;
constexpr uint32_t kPpidWebRtcBinary = 53;
constexpr uint32_t kPpidWebRtcStringPartial = 54;
constexpr uint32_t kPpidWebRtcStringEmpty = 56;
constexpr uint32_t kPpidWebRtcBinaryEmpty = 57;

// DCEP 消息类型（RFC 8832 第 5 节）。
constexpr uint8_t kDcepMsgAck = 0x02;
constexpr uint8_t kDcepMsgOpen = 0x03;

// 分片、流数量与接收窗口边界常量。
constexpr size_t kMaxSctpFragmentPayload = 1000;
constexpr size_t kMaxSctpPacketBytes = 1160;
constexpr uint16_t kDefaultMaxStreams = 1024;
constexpr uint32_t kDefaultAdvertisedRwnd = 1024 * 1024;
constexpr size_t kRxEntryOverheadBytes = 64;
constexpr size_t kMaxSeenTsns = 4096;
constexpr size_t kMaxRxFragments = 2048;
constexpr size_t kMaxStreamOrderedBufferedMsgs = 1024;
constexpr size_t kMaxTotalOrderedBufferedMsgs = 2048;
constexpr size_t kMaxEarlyRxStreams = 64;
constexpr size_t kMaxEarlyRxMsgsPerStream = 32;

// 状态 Cookie 结构常量：44B 载荷 + 32B HMAC-SHA256 = 76B（TLV 长度 80B）。
constexpr uint32_t kStateCookieMagic = 0x5254434Bu;
constexpr size_t kCookieDataBytes = 44;
constexpr size_t kCookieHmacBytes = 32;
constexpr size_t kCookieTotalBytes = kCookieDataBytes + kCookieHmacBytes;
constexpr TimeDelta kMaxCookieLifetime = TimeDelta::Seconds(60);

const std::array<uint32_t, 256>& GetCrc32cTable() {
  static const std::array<uint32_t, 256> kTable = []() {
    std::array<uint32_t, 256> tbl{};
    for (uint32_t i = 0; i < 256; ++i) {
      uint32_t crc = i;
      for (int bit = 0; bit < 8; ++bit) {
        if ((crc & 1u) != 0u) {
          crc = (crc >> 1) ^ 0x82F63B78u;
        } else {
          crc >>= 1;
        }
      }
      tbl[i] = crc;
    }
    return tbl;
  }();
  return kTable;
}

uint32_t GenerateNonZeroRandom32() {
  uint32_t v = 0;
  do {
    RAND_bytes(reinterpret_cast<uint8_t*>(&v), sizeof(v));
  } while (v == 0);
  return v;
}

void PadTo4Bytes(std::vector<uint8_t>* buf) {
  while ((buf->size() & 0x03u) != 0u) {
    buf->push_back(0);
  }
}

void AppendChunkHeader(uint8_t type,
                       uint8_t flags,
                       uint16_t unpadded_length,
                       std::vector<uint8_t>* dst) {
  dst->push_back(type);
  dst->push_back(flags);
  uint8_t len_bytes[2];
  WriteBigEndian16(len_bytes, unpadded_length);
  dst->push_back(len_bytes[0]);
  dst->push_back(len_bytes[1]);
}

}  // namespace

uint32_t ComputeSctpCrc32c(ArrayView<const uint8_t> data) {
  const auto& tbl = GetCrc32cTable();
  uint32_t crc = 0xFFFFFFFFu;
  for (uint8_t b : data) {
    crc = (crc >> 8) ^ tbl[(crc ^ b) & 0xFFu];
  }
  return ~crc;
}

uint32_t ComputeSctpPacketCrc32c(ArrayView<const uint8_t> packet) {
  const auto& tbl = GetCrc32cTable();
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < packet.size(); ++i) {
    const uint8_t b = (i >= 8 && i < 12) ? 0u : packet[i];
    crc = (crc >> 8) ^ tbl[(crc ^ b) & 0xFFu];
  }
  return ~crc;
}

SctpDataChannelManager::SctpDataChannelManager(
    Clock* clock,
    SctpDataChannelObserver* observer)
    : clock_(clock), observer_(observer) {
  InitializeLocalAssociationParams();
}

void SctpDataChannelManager::InitializeLocalAssociationParams() {
  RAND_bytes(cookie_hmac_key_.data(), cookie_hmac_key_.size());
  local_vtag_ = GenerateNonZeroRandom32();
  local_initial_tsn_ = GenerateNonZeroRandom32();
  next_tx_tsn_unwrapped_ = static_cast<int64_t>(local_initial_tsn_);
  last_acked_tx_tsn_unwrapped_ = next_tx_tsn_unwrapped_ - 1;
  advanced_peer_ack_point_unwrapped_ = last_acked_tx_tsn_unwrapped_;
  next_reconfig_seq_ = local_initial_tsn_;
}

void SctpDataChannelManager::ResetAssociationTransportState() {
  peer_vtag_ = 0;
  peer_initial_tsn_ = 0;
  negotiated_mis_ = kDefaultMaxStreams;
  peer_mis_ = kDefaultMaxStreams;
  peer_rwnd_ = kDefaultAdvertisedRwnd;
  peer_supports_prsctp_ = true;

  has_peer_initial_tsn_ = false;
  peer_cum_tsn_ack_unwrapped_ = 0;
  last_peer_reconfig_seq_.reset();
  rx_seen_tsns_.clear();
  rx_fragments_.clear();
  next_expected_ssn_.clear();
  ordered_ready_.clear();
  partial_rx_messages_.clear();
  early_rx_messages_.clear();
  rx_frag_bytes_ = 0;
  ordered_ready_bytes_ = 0;
  ordered_ready_count_ = 0;
  partial_rx_bytes_ = 0;
  early_rx_bytes_ = 0;
  early_rx_count_ = 0;
  sack_needed_ = false;
  packets_since_sack_ = 0;
  sack_deadline_ = Timestamp::PlusInfinity();

  pending_cookie_.clear();
  handshake_started_at_ = Timestamp::MinusInfinity();
  last_handshake_tx_ = Timestamp::MinusInfinity();
  handshake_rtx_count_ = 0;

  cwnd_bytes_ = 4 * 1200;
  ssthresh_bytes_ = 128 * 1024;
  partial_bytes_acked_ = 0;
  flight_bytes_ = 0;
  in_fast_recovery_ = false;
  fast_recovery_exit_point_ = -1;
  srtt_us_ = 100'000;
  rttvar_us_ = 50'000;
  rto_us_ = 200'000;
  has_rtt_sample_ = false;
  t3_rtx_deadline_ = Timestamp::PlusInfinity();

  outbound_buffered_bytes_ = 0;
  outbound_chunks_.clear();
  abandoned_ordered_streams_.clear();
  dup_sack_below_adv_count_ = 0;
  last_forward_tsn_tx_ = Timestamp::MinusInfinity();
  in_flush_transmit_ = false;
  pending_reentrant_flush_ = false;
  pending_reentrant_fast_rtx_ = false;

  queued_outbound_reset_sids_.clear();
  inflight_outbound_reset_.reset();
  outbound_reset_pending_sids_.clear();
  pending_inbound_reset_.reset();

  sid_to_channel_id_.clear();
  next_even_sid_ = 0;
  next_odd_sid_ = 1;
}

void SctpDataChannelManager::set_remote_max_message_size(uint32_t max_bytes) {
  remote_max_message_size_ = max_bytes;
}

size_t SctpDataChannelManager::EffectiveMaxMessageSize() const {
  if (remote_max_message_size_ == 0) {
    return kMaxSctpMessageSize;
  }
  return std::min<size_t>(remote_max_message_size_, kMaxSctpMessageSize);
}

uint32_t SctpDataChannelManager::CurrentPeerReconfigRespSeq() const {
  return last_peer_reconfig_seq_.value_or(peer_initial_tsn_ - 1u);
}

void SctpDataChannelManager::ConfigureAndStart(DtlsRole dtls_role,
                                               uint16_t local_port,
                                               uint16_t remote_port) {
  dtls_role_ = dtls_role;
  local_port_ = (local_port > 0) ? local_port : 5000;
  remote_port_ = (remote_port > 0) ? remote_port : 5000;
  if (started_) {
    return;
  }
  if (local_vtag_ == 0) {
    InitializeLocalAssociationParams();
  }
  started_ = true;
  const Timestamp now = clock_->CurrentTime();
  handshake_started_at_ = now;
  if (dtls_role_ == DtlsRole::kClient) {
    assoc_state_ = AssocState::kCookieWait;
    SendInitChunk(now);
  }
}

void SctpDataChannelManager::Shutdown() {
  started_ = false;
  assoc_state_ = AssocState::kClosed;
  remote_max_message_size_ = 0;
  local_vtag_ = 0;
  local_initial_tsn_ = 0;
  next_tx_tsn_unwrapped_ = 0;
  last_acked_tx_tsn_unwrapped_ = -1;
  advanced_peer_ack_point_unwrapped_ = -1;
  next_reconfig_seq_ = 1;

  ResetAssociationTransportState();
  channels_.clear();
}

void SctpDataChannelManager::ClearStreamRxState(uint16_t sid,
                                                bool clear_early_rx) {
  const auto ord_it = ordered_ready_.find(sid);
  if (ord_it != ordered_ready_.end()) {
    for (const auto& [ssn_k, m] : ord_it->second) {
      (void)ssn_k;
      ordered_ready_bytes_ = (ordered_ready_bytes_ >= m.payload.size())
                                 ? (ordered_ready_bytes_ - m.payload.size())
                                 : 0;
    }
    ordered_ready_count_ = (ordered_ready_count_ >= ord_it->second.size())
                               ? (ordered_ready_count_ - ord_it->second.size())
                               : 0;
    ordered_ready_.erase(ord_it);
  }
  const auto part_it = partial_rx_messages_.find(sid);
  if (part_it != partial_rx_messages_.end()) {
    partial_rx_bytes_ = (partial_rx_bytes_ >= part_it->second.data.size())
                            ? (partial_rx_bytes_ - part_it->second.data.size())
                            : 0;
    partial_rx_messages_.erase(part_it);
  }
  next_expected_ssn_.erase(sid);
  if (clear_early_rx) {
    const auto early_it = early_rx_messages_.find(sid);
    if (early_it != early_rx_messages_.end()) {
      for (const auto& [is_bin, msg_data] : early_it->second) {
        (void)is_bin;
        early_rx_bytes_ = (early_rx_bytes_ >= msg_data.size())
                              ? (early_rx_bytes_ - msg_data.size())
                              : 0;
      }
      early_rx_count_ = (early_rx_count_ >= early_it->second.size())
                            ? (early_rx_count_ - early_it->second.size())
                            : 0;
      early_rx_messages_.erase(early_it);
    }
  }
}

size_t SctpDataChannelManager::ComputeBufferedRxBytes() const {
  const size_t payload_bytes = rx_frag_bytes_ + ordered_ready_bytes_ +
                               partial_rx_bytes_ + early_rx_bytes_;
  const size_t entry_count = rx_fragments_.size() + ordered_ready_count_ +
                             partial_rx_messages_.size() + early_rx_count_;
  return payload_bytes + entry_count * kRxEntryOverheadBytes;
}

uint32_t SctpDataChannelManager::CurrentAdvertisedRwnd() const {
  const size_t used = ComputeBufferedRxBytes();
  return (used < kDefaultAdvertisedRwnd)
             ? static_cast<uint32_t>(kDefaultAdvertisedRwnd - used)
             : 0u;
}

std::optional<uint16_t> SctpDataChannelManager::AllocateNextLocalStreamId() {
  const uint16_t base = (dtls_role_ == DtlsRole::kClient) ? 0u : 1u;
  if (peer_mis_ <= base) {
    return std::nullopt;
  }
  uint16_t& cursor =
      (dtls_role_ == DtlsRole::kClient) ? next_even_sid_ : next_odd_sid_;
  if (cursor >= peer_mis_ || (cursor & 1u) != base) {
    cursor = base;
  }
  const size_t max_candidates =
      static_cast<size_t>((peer_mis_ - 1u - base) / 2u) + 1u;
  for (size_t step = 0; step < max_candidates; ++step) {
    const uint16_t cand = cursor;
    cursor = static_cast<uint16_t>(cursor + 2u);
    if (cursor >= peer_mis_) {
      cursor = base;
    }
    if (cand < peer_mis_ && cand != 0xFFFFu &&
        sid_to_channel_id_.find(cand) == sid_to_channel_id_.end() &&
        outbound_reset_pending_sids_.find(cand) ==
            outbound_reset_pending_sids_.end()) {
      return cand;
    }
  }
  return std::nullopt;
}

int SctpDataChannelManager::CreateDataChannel(const DataChannelConfig& config) {
  if (config.label.size() > 65535 || config.protocol.size() > 65535 ||
      (config.max_retransmits >= 0 && config.max_packet_lifetime_ms >= 0) ||
      channels_.size() >= 2048) {
    return RTC_ERR_INVALID_ARG;
  }
  std::optional<uint16_t> preallocated_sid;
  if (config.negotiated) {
    if (config.id < 0 || config.id > 65534 ||
        static_cast<uint16_t>(config.id) >= peer_mis_) {
      return RTC_ERR_INVALID_ARG;
    }
    const uint16_t sid = static_cast<uint16_t>(config.id);
    if (sid_to_channel_id_.find(sid) != sid_to_channel_id_.end() ||
        outbound_reset_pending_sids_.find(sid) !=
            outbound_reset_pending_sids_.end()) {
      return RTC_ERR_INVALID_ARG;
    }
    preallocated_sid = sid;
  } else if (assoc_state_ == AssocState::kEstablished) {
    preallocated_sid = AllocateNextLocalStreamId();
    if (!preallocated_sid.has_value()) {
      return RTC_ERR_NO_MEMORY;
    }
  }

  const int channel_id = next_channel_id_++;
  ChannelEntry entry;
  entry.channel_id = channel_id;
  entry.config = config;
  if (entry.config.label.empty()) {
    entry.config.label = "data_" + std::to_string(channel_id);
  }
  if (preallocated_sid.has_value()) {
    entry.sctp_sid = *preallocated_sid;
    sid_to_channel_id_[*preallocated_sid] = channel_id;
  }

  auto [it, inserted] = channels_.emplace(channel_id, std::move(entry));
  (void)inserted;
  if (assoc_state_ == AssocState::kEstablished) {
    ActivateChannelIfReady(&it->second, clock_->CurrentTime());
  }
  return channel_id;
}

int SctpDataChannelManager::SendData(int channel_id,
                                     ArrayView<const uint8_t> payload,
                                     bool is_binary) {
  constexpr size_t kMaxOutboundBufferedBytes = kMaxSctpMessageSize;
  if (payload.size() > EffectiveMaxMessageSize()) {
    return RTC_ERR_INVALID_ARG;
  }
  const auto it = channels_.find(channel_id);
  if (it == channels_.end()) {
    return RTC_ERR_INVALID_ARG;
  }
  ChannelEntry& ch = it->second;
  if (ch.state == RTC_DATA_CHANNEL_CLOSING ||
      ch.state == RTC_DATA_CHANNEL_CLOSED) {
    return RTC_ERR_NOT_CONNECTED;
  }

  const Timestamp now = clock_->CurrentTime();
  if (assoc_state_ != AssocState::kEstablished || !ch.sctp_sid.has_value()) {
    if (ch.pending_messages.size() >= 512 ||
        ch.pending_bytes > kMaxOutboundBufferedBytes - payload.size()) {
      return RTC_ERR_NO_MEMORY;
    }
    ch.pending_bytes += payload.size();
    PendingUserMessage pending;
    pending.payload.assign(payload.begin(), payload.end());
    pending.is_binary = is_binary;
    pending.queued_at = now;
    ch.pending_messages.push_back(std::move(pending));
    return RTC_OK;
  }

  if (outbound_buffered_bytes_ > kMaxOutboundBufferedBytes - payload.size()) {
    return RTC_ERR_NO_MEMORY;
  }

  uint32_t ppid = is_binary ? kPpidWebRtcBinary : kPpidWebRtcString;
  std::vector<uint8_t> empty_placeholder(1, 0);
  ArrayView<const uint8_t> wire_payload = payload;
  if (payload.empty()) {
    // RFC 8831 第 6.6 节：SCTP DATA 不允许 0 字节负载，空消息使用 PPID 56/57 携带 1 个零字节。
    ppid = is_binary ? kPpidWebRtcBinaryEmpty : kPpidWebRtcStringEmpty;
    wire_payload = empty_placeholder;
  }

  const uint16_t ssn = ch.config.ordered ? ch.next_tx_ssn++ : 0;
  EnqueueSctpMessage(*ch.sctp_sid, ch.config.ordered, ssn, ppid, wire_payload,
                     ch.config.max_retransmits,
                     ch.config.max_packet_lifetime_ms, now);
  FlushTransmitQueue(now);
  return RTC_OK;
}

int SctpDataChannelManager::CloseDataChannel(int channel_id) {
  const auto it = channels_.find(channel_id);
  if (it == channels_.end()) {
    return RTC_ERR_INVALID_ARG;
  }
  ChannelEntry& ch = it->second;
  if (ch.state == RTC_DATA_CHANNEL_CLOSED) {
    return RTC_OK;
  }

  ch.pending_messages.clear();
  ch.pending_bytes = 0;

  if (assoc_state_ != AssocState::kEstablished || !ch.sctp_sid.has_value()) {
    const std::string label = ch.config.label;
    if (ch.sctp_sid.has_value()) {
      const uint16_t sid = *ch.sctp_sid;
      sid_to_channel_id_.erase(sid);
      ClearStreamRxState(sid, /*clear_early_rx=*/true);
    }
    channels_.erase(it);
    if (observer_ != nullptr) {
      observer_->OnSctpDataChannelState(channel_id, label,
                                        RTC_DATA_CHANNEL_CLOSED);
    }
    return RTC_OK;
  }

  const uint16_t sid = *ch.sctp_sid;
  const std::string label = ch.config.label;
  const bool notify_closing = (ch.state != RTC_DATA_CHANNEL_CLOSING);
  ch.state = RTC_DATA_CHANNEL_CLOSING;
  if (notify_closing && observer_ != nullptr) {
    observer_->OnSctpDataChannelState(channel_id, label,
                                      RTC_DATA_CHANNEL_CLOSING);
  }

  const auto refreshed_it = channels_.find(channel_id);
  if (refreshed_it != channels_.end()) {
    ChannelEntry& cur_ch = refreshed_it->second;
    if (!cur_ch.outbound_reset_queued && !cur_ch.outbound_reset_done) {
      cur_ch.outbound_reset_queued = true;
      EnqueueOutgoingStreamReset(sid, clock_->CurrentTime());
    }
    FinalizeChannelCloseIfReady(channel_id);
  }
  return RTC_OK;
}

void SctpDataChannelManager::EnqueueOutgoingStreamReset(uint16_t sid,
                                                        Timestamp now) {
  outbound_reset_pending_sids_.insert(sid);
  if (inflight_outbound_reset_.has_value()) {
    const auto& cur_sids = inflight_outbound_reset_->sids;
    if (std::find(cur_sids.begin(), cur_sids.end(), sid) != cur_sids.end()) {
      return;
    }
  }
  if (std::find(queued_outbound_reset_sids_.begin(),
                queued_outbound_reset_sids_.end(),
                sid) == queued_outbound_reset_sids_.end()) {
    queued_outbound_reset_sids_.push_back(sid);
  }
  PumpOutboundStreamResetQueue(now);
}

void SctpDataChannelManager::PumpOutboundStreamResetQueue(Timestamp now) {
  if (assoc_state_ != AssocState::kEstablished || peer_vtag_ == 0 ||
      inflight_outbound_reset_.has_value() ||
      queued_outbound_reset_sids_.empty()) {
    return;
  }

  OutgoingResetReq req;
  req.req_seq = next_reconfig_seq_++;
  req.last_assigned_tsn =
      static_cast<uint32_t>((next_tx_tsn_unwrapped_ - 1) & 0xFFFFFFFFULL);
  constexpr size_t kMaxSidsPerResetReq = 128;
  while (!queued_outbound_reset_sids_.empty() &&
         req.sids.size() < kMaxSidsPerResetReq) {
    req.sids.push_back(queued_outbound_reset_sids_.front());
    queued_outbound_reset_sids_.pop_front();
  }
  inflight_outbound_reset_ = std::move(req);
  SendInflightOutboundReset(now);
}

void SctpDataChannelManager::SendInflightOutboundReset(Timestamp now) {
  if (!inflight_outbound_reset_.has_value() || peer_vtag_ == 0) {
    return;
  }
  auto& req = *inflight_outbound_reset_;
  const uint16_t param_len =
      static_cast<uint16_t>(16 + req.sids.size() * sizeof(uint16_t));
  const uint16_t chunk_len = static_cast<uint16_t>(4 + param_len);

  std::vector<uint8_t> chunk;
  chunk.reserve((static_cast<size_t>(chunk_len) + 3u) & ~size_t{3});
  AppendChunkHeader(kChunkReconfig, 0, chunk_len, &chunk);

  uint8_t hdr[16]{};
  WriteBigEndian16(hdr, kParamOutgoingSsnResetReq);
  WriteBigEndian16(hdr + 2, param_len);
  WriteBigEndian32(hdr + 4, req.req_seq);
  WriteBigEndian32(hdr + 8, CurrentPeerReconfigRespSeq());
  WriteBigEndian32(hdr + 12, req.last_assigned_tsn);
  chunk.insert(chunk.end(), hdr, hdr + sizeof(hdr));

  for (uint16_t sid : req.sids) {
    uint8_t sid_bytes[2];
    WriteBigEndian16(sid_bytes, sid);
    chunk.push_back(sid_bytes[0]);
    chunk.push_back(sid_bytes[1]);
  }
  PadTo4Bytes(&chunk);
  SendChunksPacket(peer_vtag_, chunk);
  req.last_sent_at = now;
  ++req.rtx_count;
}

void SctpDataChannelManager::SendReconfigResponse(uint32_t resp_seq,
                                                  uint32_t result) {
  if (peer_vtag_ == 0) {
    return;
  }
  std::vector<uint8_t> resp;
  AppendChunkHeader(kChunkReconfig, 0, 16, &resp);
  uint8_t body[12]{};
  WriteBigEndian16(body, kParamReconfigResponse);
  WriteBigEndian16(body + 2, 12);
  WriteBigEndian32(body + 4, resp_seq);
  WriteBigEndian32(body + 8, result);
  resp.insert(resp.end(), body, body + sizeof(body));
  SendChunksPacket(peer_vtag_, resp);
}

void SctpDataChannelManager::FinalizeChannelCloseIfReady(int channel_id) {
  const auto ch_it = channels_.find(channel_id);
  if (ch_it == channels_.end()) {
    return;
  }
  ChannelEntry& ch = ch_it->second;
  if (!ch.outbound_reset_done || !ch.inbound_reset_done) {
    return;
  }

  const std::string label = ch.config.label;
  if (ch.sctp_sid.has_value()) {
    const uint16_t sid = *ch.sctp_sid;
    outbound_reset_pending_sids_.erase(sid);
    abandoned_ordered_streams_.erase(sid);
    const auto sid_it = sid_to_channel_id_.find(sid);
    if (sid_it != sid_to_channel_id_.end() && sid_it->second == channel_id) {
      sid_to_channel_id_.erase(sid_it);
      ClearStreamRxState(sid, /*clear_early_rx=*/true);
    }
  }
  channels_.erase(ch_it);
  if (observer_ != nullptr) {
    observer_->OnSctpDataChannelState(channel_id, label,
                                      RTC_DATA_CHANNEL_CLOSED);
  }
}

std::vector<uint8_t> SctpDataChannelManager::BuildSctpPacketToPort(
    uint16_t dst_port,
    uint32_t vtag,
    ArrayView<const uint8_t> chunks_bytes) const {
  std::vector<uint8_t> pkt(12 + chunks_bytes.size(), 0);
  WriteBigEndian16(pkt.data(), local_port_);
  WriteBigEndian16(pkt.data() + 2, dst_port);
  WriteBigEndian32(pkt.data() + 4, vtag);
  if (!chunks_bytes.empty()) {
    std::memcpy(pkt.data() + 12, chunks_bytes.data(), chunks_bytes.size());
  }
  // RFC 4960 第 6.8 节与 RFC 3309：CRC-32c 校验和以小端字节序写入头部偏移 8..11。
  const uint32_t crc = ComputeSctpPacketCrc32c(pkt);
  pkt[8] = static_cast<uint8_t>(crc & 0xFFu);
  pkt[9] = static_cast<uint8_t>((crc >> 8) & 0xFFu);
  pkt[10] = static_cast<uint8_t>((crc >> 16) & 0xFFu);
  pkt[11] = static_cast<uint8_t>((crc >> 24) & 0xFFu);
  return pkt;
}

std::vector<uint8_t> SctpDataChannelManager::BuildSctpPacket(
    uint32_t vtag,
    ArrayView<const uint8_t> chunks_bytes) const {
  return BuildSctpPacketToPort(remote_port_, vtag, chunks_bytes);
}

bool SctpDataChannelManager::SendChunksPacketToPort(
    uint16_t dst_port,
    uint32_t vtag,
    ArrayView<const uint8_t> chunks_bytes) {
  if (observer_ == nullptr || chunks_bytes.empty()) {
    return false;
  }
  const auto wire = BuildSctpPacketToPort(dst_port, vtag, chunks_bytes);
  return observer_->SendSctpPacketOverDtls(wire);
}

bool SctpDataChannelManager::SendChunksPacket(
    uint32_t vtag,
    ArrayView<const uint8_t> chunks_bytes) {
  return SendChunksPacketToPort(remote_port_, vtag, chunks_bytes);
}

void SctpDataChannelManager::SendInitChunk(Timestamp now) {
  if (local_vtag_ == 0) {
    InitializeLocalAssociationParams();
  }
  std::vector<uint8_t> chunk;
  // INIT 固定体 16B + Forward-TSN-Supported (4B) + Supported-Extensions (8B, 含对齐) + Chunk 头 (4B) = 32B。
  AppendChunkHeader(kChunkInit, 0, 32, &chunk);
  uint8_t body[28]{};
  WriteBigEndian32(body, local_vtag_);
  WriteBigEndian32(body + 4, CurrentAdvertisedRwnd());
  WriteBigEndian16(body + 8, kDefaultMaxStreams);
  WriteBigEndian16(body + 10, kDefaultMaxStreams);
  WriteBigEndian32(body + 12, local_initial_tsn_);
  WriteBigEndian16(body + 16, kParamForwardTsnSupported);
  WriteBigEndian16(body + 18, 4);
  WriteBigEndian16(body + 20, kParamSupportedExtensions);
  WriteBigEndian16(body + 22, 6);
  body[24] = kChunkReconfig;
  body[25] = kChunkForwardTsn;
  chunk.insert(chunk.end(), body, body + sizeof(body));
  SendChunksPacket(0, chunk);
  last_handshake_tx_ = now;
}

void SctpDataChannelManager::HandleInitChunk(
    uint16_t src_port,
    ArrayView<const uint8_t> chunk_body,
    Timestamp now) {
  if (chunk_body.size() < 16) {
    return;
  }
  const uint32_t init_tag = ReadBigEndian32(chunk_body.data());
  const uint32_t peer_arwnd = ReadBigEndian32(chunk_body.data() + 4);
  const uint16_t peer_os = ReadBigEndian16(chunk_body.data() + 8);
  const uint16_t peer_mis = ReadBigEndian16(chunk_body.data() + 10);
  const uint32_t peer_init_tsn = ReadBigEndian32(chunk_body.data() + 12);
  if (init_tag == 0 || peer_os == 0 || peer_mis == 0) {
    return;
  }

  bool prsctp = false;
  size_t off = 16;
  while (off + 4 <= chunk_body.size()) {
    const uint16_t ptype = ReadBigEndian16(chunk_body.data() + off);
    const uint16_t plen = ReadBigEndian16(chunk_body.data() + off + 2);
    if (plen < 4 || off + plen > chunk_body.size()) {
      break;
    }
    if (ptype == kParamForwardTsnSupported) {
      prsctp = true;
    } else if (ptype == kParamSupportedExtensions && plen > 4) {
      for (size_t k = 4; k < plen; ++k) {
        if (chunk_body[off + k] == kChunkForwardTsn) {
          prsctp = true;
        }
      }
    }
    off += (static_cast<size_t>(plen) + 3u) & ~size_t{3};
  }

  if (local_vtag_ == 0) {
    InitializeLocalAssociationParams();
  }

  // RFC 4960 第 5.2.2 节：若关联已建立，不修改当前 TCB，生成新的临时 VTag/TSN 封入签名 Cookie。
  uint32_t resp_local_vtag = local_vtag_;
  uint32_t resp_local_tsn = local_initial_tsn_;
  if (assoc_state_ == AssocState::kEstablished &&
      (init_tag != peer_vtag_ || peer_init_tsn != peer_initial_tsn_)) {
    do {
      resp_local_vtag = GenerateNonZeroRandom32();
    } while (resp_local_vtag == local_vtag_);
    resp_local_tsn = GenerateNonZeroRandom32();
  }

  const uint16_t ack_os = std::min<uint16_t>(kDefaultMaxStreams, peer_mis);
  const uint16_t ack_mis = kDefaultMaxStreams;

  // 构造带 HMAC-SHA256 签名与时间戳的状态 Cookie (0x0007, TLV 长度 80B)。
  constexpr uint16_t kCookieParamLen = static_cast<uint16_t>(4 + kCookieTotalBytes);
  constexpr uint16_t kInitAckLen = 4 + 16 + kCookieParamLen + 4 + 6;
  std::vector<uint8_t> chunk;
  chunk.reserve(112);
  AppendChunkHeader(kChunkInitAck, 0, kInitAckLen, &chunk);

  uint8_t fixed[16]{};
  WriteBigEndian32(fixed, resp_local_vtag);
  WriteBigEndian32(fixed + 4, CurrentAdvertisedRwnd());
  WriteBigEndian16(fixed + 8, ack_os);
  WriteBigEndian16(fixed + 10, ack_mis);
  WriteBigEndian32(fixed + 12, resp_local_tsn);
  chunk.insert(chunk.end(), fixed, fixed + sizeof(fixed));

  uint8_t cookie_param[4 + kCookieTotalBytes]{};
  WriteBigEndian16(cookie_param, kParamStateCookie);
  WriteBigEndian16(cookie_param + 2, kCookieParamLen);
  uint8_t* cdata = cookie_param + 4;
  const int64_t cookie_ts_us = now.IsFinite() ? now.us() : 0;
  WriteBigEndian32(cdata + 0, kStateCookieMagic);
  WriteBigEndian64(cdata + 4, static_cast<uint64_t>(cookie_ts_us));
  WriteBigEndian32(cdata + 12, resp_local_vtag);
  WriteBigEndian32(cdata + 16, resp_local_tsn);
  WriteBigEndian32(cdata + 20, init_tag);
  WriteBigEndian32(cdata + 24, peer_init_tsn);
  WriteBigEndian32(cdata + 28, peer_arwnd);
  WriteBigEndian16(cdata + 32, peer_os);
  WriteBigEndian16(cdata + 34, peer_mis);
  WriteBigEndian16(cdata + 36, local_port_);
  WriteBigEndian16(cdata + 38, src_port);
  WriteBigEndian32(cdata + 40, prsctp ? 1u : 0u);

  unsigned int mac_len = 0;
  HMAC(EVP_sha256(), cookie_hmac_key_.data(),
       static_cast<int>(cookie_hmac_key_.size()), cdata, kCookieDataBytes,
       cdata + kCookieDataBytes, &mac_len);
  chunk.insert(chunk.end(), cookie_param, cookie_param + sizeof(cookie_param));

  uint8_t ext_params[12]{};
  WriteBigEndian16(ext_params, kParamForwardTsnSupported);
  WriteBigEndian16(ext_params + 2, 4);
  WriteBigEndian16(ext_params + 4, kParamSupportedExtensions);
  WriteBigEndian16(ext_params + 6, 6);
  ext_params[8] = kChunkReconfig;
  ext_params[9] = kChunkForwardTsn;
  chunk.insert(chunk.end(), ext_params, ext_params + sizeof(ext_params));

  SendChunksPacketToPort(src_port, init_tag, chunk);
}

void SctpDataChannelManager::HandleInitAckChunk(
    ArrayView<const uint8_t> chunk_body,
    Timestamp now) {
  if (assoc_state_ != AssocState::kCookieWait || chunk_body.size() < 16) {
    return;
  }
  const uint32_t init_tag = ReadBigEndian32(chunk_body.data());
  const uint32_t peer_arwnd = ReadBigEndian32(chunk_body.data() + 4);
  const uint16_t peer_os = ReadBigEndian16(chunk_body.data() + 8);
  const uint16_t peer_mis = ReadBigEndian16(chunk_body.data() + 10);
  const uint32_t peer_init_tsn = ReadBigEndian32(chunk_body.data() + 12);
  if (init_tag == 0 || peer_os == 0 || peer_mis == 0) {
    return;
  }

  std::vector<uint8_t> cookie;
  bool prsctp = false;
  size_t off = 16;
  while (off + 4 <= chunk_body.size()) {
    const uint16_t ptype = ReadBigEndian16(chunk_body.data() + off);
    const uint16_t plen = ReadBigEndian16(chunk_body.data() + off + 2);
    if (plen < 4 || off + plen > chunk_body.size()) {
      break;
    }
    if (ptype == kParamStateCookie && plen > 4 && plen <= 1024) {
      cookie.assign(chunk_body.data() + off + 4,
                    chunk_body.data() + off + plen);
    } else if (ptype == kParamForwardTsnSupported) {
      prsctp = true;
    } else if (ptype == kParamSupportedExtensions && plen > 4) {
      for (size_t k = 4; k < plen; ++k) {
        if (chunk_body[off + k] == kChunkForwardTsn) {
          prsctp = true;
        }
      }
    }
    off += (static_cast<size_t>(plen) + 3u) & ~size_t{3};
  }
  if (cookie.empty()) {
    return;
  }

  peer_vtag_ = init_tag;
  peer_rwnd_ = peer_arwnd;
  negotiated_mis_ = std::min<uint16_t>(kDefaultMaxStreams, peer_os);
  peer_mis_ = std::min<uint16_t>(kDefaultMaxStreams, peer_mis);
  peer_supports_prsctp_ = prsctp;
  peer_initial_tsn_ = peer_init_tsn;
  peer_cum_tsn_ack_unwrapped_ = static_cast<int64_t>(peer_init_tsn) - 1;
  has_peer_initial_tsn_ = true;

  pending_cookie_ = std::move(cookie);
  assoc_state_ = AssocState::kCookieEchoed;
  handshake_rtx_count_ = 0;

  std::vector<uint8_t> echo_chunk;
  AppendChunkHeader(kChunkCookieEcho, 0,
                    static_cast<uint16_t>(4 + pending_cookie_.size()),
                    &echo_chunk);
  echo_chunk.insert(echo_chunk.end(), pending_cookie_.begin(),
                    pending_cookie_.end());
  PadTo4Bytes(&echo_chunk);
  SendChunksPacket(peer_vtag_, echo_chunk);
  last_handshake_tx_ = now;
}

void SctpDataChannelManager::HandleCookieEchoChunk(
    uint32_t rx_vtag,
    uint16_t src_port,
    ArrayView<const uint8_t> chunk_body,
    Timestamp now) {
  if (chunk_body.size() != kCookieTotalBytes) {
    return;
  }

  unsigned char expected_mac[kCookieHmacBytes]{};
  unsigned int mac_len = 0;
  HMAC(EVP_sha256(), cookie_hmac_key_.data(),
       static_cast<int>(cookie_hmac_key_.size()), chunk_body.data(),
       kCookieDataBytes, expected_mac, &mac_len);
  if (mac_len != kCookieHmacBytes ||
      CRYPTO_memcmp(expected_mac, chunk_body.data() + kCookieDataBytes,
                    kCookieHmacBytes) != 0) {
    RTC_LOG(kWarning) << "Dropped SCTP COOKIE-ECHO with invalid HMAC";
    return;
  }

  const uint8_t* cdata = chunk_body.data();
  const uint32_t c_magic = ReadBigEndian32(cdata + 0);
  const int64_t c_ts_us = static_cast<int64_t>(ReadBigEndian64(cdata + 4));
  const uint32_t c_local_vtag = ReadBigEndian32(cdata + 12);
  const uint32_t c_local_tsn = ReadBigEndian32(cdata + 16);
  const uint32_t c_peer_vtag = ReadBigEndian32(cdata + 20);
  const uint32_t c_peer_tsn = ReadBigEndian32(cdata + 24);
  const uint32_t c_peer_rwnd = ReadBigEndian32(cdata + 28);
  const uint16_t c_peer_os = ReadBigEndian16(cdata + 32);
  const uint16_t c_peer_mis = ReadBigEndian16(cdata + 34);
  const uint16_t c_local_port = ReadBigEndian16(cdata + 36);
  const uint16_t c_remote_port = ReadBigEndian16(cdata + 38);
  const bool c_prsctp = ReadBigEndian32(cdata + 40) != 0u;

  if (c_magic != kStateCookieMagic || c_local_vtag == 0 || c_peer_vtag == 0 ||
      c_peer_os == 0 || c_peer_mis == 0 || c_local_vtag != rx_vtag ||
      c_local_port != local_port_ || c_remote_port != src_port) {
    return;
  }

  if (now.IsFinite()) {
    const TimeDelta age = now - Timestamp::Micros(c_ts_us);
    if (age < TimeDelta::Zero() || age > kMaxCookieLifetime) {
      RTC_LOG(kWarning) << "Dropped expired SCTP State Cookie";
      return;
    }
  }

  remote_port_ = src_port;

  // RFC 4960 第 5.2.4 节：区分重复 COOKIE-ECHO 与对端关联重启（Association Restart）。
  if (assoc_state_ == AssocState::kEstablished) {
    if (c_local_vtag == local_vtag_ && c_peer_vtag == peer_vtag_ &&
        c_peer_tsn == peer_initial_tsn_) {
      std::vector<uint8_t> ack_chunk;
      AppendChunkHeader(kChunkCookieAck, 0, 4, &ack_chunk);
      SendChunksPacket(peer_vtag_, ack_chunk);
      return;
    }

    std::vector<std::pair<int, std::string>> restarted_channels;
    for (auto ch_it = channels_.begin(); ch_it != channels_.end();) {
      if (ch_it->second.open_notified ||
          ch_it->second.state != RTC_DATA_CHANNEL_CONNECTING) {
        if (ch_it->second.state != RTC_DATA_CHANNEL_CLOSED) {
          restarted_channels.emplace_back(ch_it->first,
                                          ch_it->second.config.label);
        }
        ch_it = channels_.erase(ch_it);
      } else {
        ch_it->second.sctp_sid.reset();
        ch_it->second.open_sent = false;
        ch_it->second.next_tx_ssn = 0;
        ++ch_it;
      }
    }

    ResetAssociationTransportState();
    local_vtag_ = c_local_vtag;
    local_initial_tsn_ = c_local_tsn;
    next_tx_tsn_unwrapped_ = static_cast<int64_t>(local_initial_tsn_);
    last_acked_tx_tsn_unwrapped_ = next_tx_tsn_unwrapped_ - 1;
    advanced_peer_ack_point_unwrapped_ = last_acked_tx_tsn_unwrapped_;
    next_reconfig_seq_ = local_initial_tsn_;

    for (auto& [cid, ch] : channels_) {
      if (ch.config.negotiated && ch.config.id >= 0) {
        const uint16_t sid = static_cast<uint16_t>(ch.config.id);
        ch.sctp_sid = sid;
        sid_to_channel_id_[sid] = cid;
      }
    }

    if (observer_ != nullptr) {
      for (const auto& [cid, label] : restarted_channels) {
        observer_->OnSctpDataChannelState(cid, label, RTC_DATA_CHANNEL_CLOSED);
      }
    }
  } else if (c_local_vtag != local_vtag_) {
    return;
  }

  peer_vtag_ = c_peer_vtag;
  peer_rwnd_ = c_peer_rwnd;
  negotiated_mis_ = std::min<uint16_t>(kDefaultMaxStreams, c_peer_os);
  peer_mis_ = std::min<uint16_t>(kDefaultMaxStreams, c_peer_mis);
  peer_supports_prsctp_ = c_prsctp;
  peer_initial_tsn_ = c_peer_tsn;
  peer_cum_tsn_ack_unwrapped_ = static_cast<int64_t>(c_peer_tsn) - 1;
  has_peer_initial_tsn_ = true;
  pending_cookie_.clear();

  std::vector<uint8_t> ack_chunk;
  AppendChunkHeader(kChunkCookieAck, 0, 4, &ack_chunk);
  SendChunksPacket(peer_vtag_, ack_chunk);

  OnAssociationEstablished(now);
}

void SctpDataChannelManager::HandleCookieAckChunk(Timestamp now) {
  if (assoc_state_ == AssocState::kCookieEchoed) {
    pending_cookie_.clear();
    OnAssociationEstablished(now);
  }
}

void SctpDataChannelManager::OnAssociationEstablished(Timestamp now) {
  assoc_state_ = AssocState::kEstablished;
  RTC_LOG(kInfo) << "SCTP association established (local_port=" << local_port_
                 << ", remote_port=" << remote_port_
                 << ", role="
                 << (dtls_role_ == DtlsRole::kClient ? "client" : "server")
                 << ", pr_sctp=" << (peer_supports_prsctp_ ? "on" : "off")
                 << ")";

  std::vector<int> existing_cids;
  existing_cids.reserve(channels_.size());
  for (const auto& [cid, ch] : channels_) {
    (void)ch;
    existing_cids.push_back(cid);
  }
  for (int cid : existing_cids) {
    const auto it = channels_.find(cid);
    if (it != channels_.end()) {
      ActivateChannelIfReady(&it->second, now);
    }
  }
  FlushTransmitQueue(now);
}

void SctpDataChannelManager::ActivateChannelIfReady(ChannelEntry* ch,
                                                    Timestamp now) {
  if (ch == nullptr || ch->state == RTC_DATA_CHANNEL_CLOSING ||
      ch->state == RTC_DATA_CHANNEL_CLOSED ||
      assoc_state_ != AssocState::kEstablished) {
    return;
  }
  if (ch->sctp_sid.has_value() && *ch->sctp_sid >= peer_mis_) {
    const int cid = ch->channel_id;
    const std::string label = ch->config.label;
    sid_to_channel_id_.erase(*ch->sctp_sid);
    channels_.erase(cid);
    if (observer_ != nullptr) {
      observer_->OnSctpDataChannelState(cid, label, RTC_DATA_CHANNEL_CLOSED);
    }
    return;
  }
  if (!ch->sctp_sid.has_value()) {
    const auto sid_opt = AllocateNextLocalStreamId();
    if (!sid_opt.has_value()) {
      return;
    }
    ch->sctp_sid = *sid_opt;
    sid_to_channel_id_[*sid_opt] = ch->channel_id;
  }
  if (!ch->config.negotiated && !ch->open_sent) {
    SendDcepOpen(*ch, now);
    ch->open_sent = true;
  }
  const int cid = ch->channel_id;
  ch->state = RTC_DATA_CHANNEL_OPEN;
  if (!ch->open_notified && observer_ != nullptr) {
    ch->open_notified = true;
    const std::string label = ch->config.label;
    observer_->OnSctpDataChannelState(cid, label, RTC_DATA_CHANNEL_OPEN);
  }

  const auto ch_it = channels_.find(cid);
  if (ch_it == channels_.end() ||
      ch_it->second.state != RTC_DATA_CHANNEL_OPEN ||
      !ch_it->second.sctp_sid.has_value()) {
    return;
  }
  ChannelEntry& active_ch = ch_it->second;

  // 按入队顺序冲刷在握手完成前预先缓存的应用消息，保留原始入队时间戳供 PR-SCTP 生存期判定。
  const size_t max_msg_sz = EffectiveMaxMessageSize();
  while (!active_ch.pending_messages.empty()) {
    PendingUserMessage msg = std::move(active_ch.pending_messages.front());
    active_ch.pending_messages.pop_front();
    active_ch.pending_bytes =
        (active_ch.pending_bytes >= msg.payload.size())
            ? (active_ch.pending_bytes - msg.payload.size())
            : 0;
    if (msg.payload.size() > max_msg_sz) {
      RTC_LOG(kWarning) << "Dropped pre-queued SCTP message exceeding remote "
                           "max-message-size ("
                        << msg.payload.size() << " > " << max_msg_sz << ")";
      continue;
    }

    uint32_t ppid = msg.is_binary ? kPpidWebRtcBinary : kPpidWebRtcString;
    std::vector<uint8_t> empty_placeholder(1, 0);
    ArrayView<const uint8_t> wire_payload = msg.payload;
    if (msg.payload.empty()) {
      ppid = msg.is_binary ? kPpidWebRtcBinaryEmpty : kPpidWebRtcStringEmpty;
      wire_payload = empty_placeholder;
    }
    const uint16_t ssn = active_ch.config.ordered ? active_ch.next_tx_ssn++ : 0;
    const Timestamp created_at = msg.queued_at.IsFinite() ? msg.queued_at : now;
    EnqueueSctpMessage(*active_ch.sctp_sid, active_ch.config.ordered, ssn, ppid,
                       wire_payload, active_ch.config.max_retransmits,
                       active_ch.config.max_packet_lifetime_ms, created_at);
  }
  FlushTransmitQueue(now);
}

void SctpDataChannelManager::SendDcepOpen(const ChannelEntry& ch,
                                          Timestamp now) {
  uint8_t chan_type = ch.config.ordered ? 0x00u : 0x80u;
  uint32_t rel_param = 0;
  if (ch.config.max_packet_lifetime_ms >= 0) {
    chan_type |= 0x02u;
    rel_param = static_cast<uint32_t>(ch.config.max_packet_lifetime_ms);
  } else if (ch.config.max_retransmits >= 0) {
    chan_type |= 0x01u;
    rel_param = static_cast<uint32_t>(ch.config.max_retransmits);
  }

  const std::string& label = ch.config.label;
  const std::string& proto = ch.config.protocol;
  std::vector<uint8_t> dcep(12 + label.size() + proto.size(), 0);
  dcep[0] = kDcepMsgOpen;
  dcep[1] = chan_type;
  WriteBigEndian16(dcep.data() + 2, 256);
  WriteBigEndian32(dcep.data() + 4, rel_param);
  WriteBigEndian16(dcep.data() + 8, static_cast<uint16_t>(label.size()));
  WriteBigEndian16(dcep.data() + 10, static_cast<uint16_t>(proto.size()));
  if (!label.empty()) {
    std::memcpy(dcep.data() + 12, label.data(), label.size());
  }
  if (!proto.empty()) {
    std::memcpy(dcep.data() + 12 + label.size(), proto.data(), proto.size());
  }

  // RFC 8832 第 5.1 节：DATA_CHANNEL_OPEN 必须按序可靠发送；占用该流首个有序 SSN。
  auto it = channels_.find(ch.channel_id);
  const uint16_t open_ssn =
      (it != channels_.end()) ? it->second.next_tx_ssn++ : 0;
  EnqueueSctpMessage(*ch.sctp_sid, /*ordered=*/true, open_ssn, kPpidDcep, dcep,
                     /*max_retransmits=*/-1, /*max_lifetime_ms=*/-1, now);
}

void SctpDataChannelManager::SendDcepAck(uint16_t sid, Timestamp now) {
  const uint8_t ack_byte = kDcepMsgAck;
  uint16_t ssn = 0;
  const auto cid_it = sid_to_channel_id_.find(sid);
  if (cid_it != sid_to_channel_id_.end()) {
    const auto ch_it = channels_.find(cid_it->second);
    if (ch_it != channels_.end()) {
      ssn = ch_it->second.next_tx_ssn++;
    }
  }
  EnqueueSctpMessage(sid, /*ordered=*/true, ssn, kPpidDcep,
                     MakeArrayView(&ack_byte, 1), /*max_retransmits=*/-1,
                     /*max_lifetime_ms=*/-1, now);
  FlushTransmitQueue(now);
}

void SctpDataChannelManager::EnqueueSctpMessage(
    uint16_t sid,
    bool ordered,
    uint16_t ssn,
    uint32_t ppid,
    ArrayView<const uint8_t> payload,
    int32_t max_retransmits,
    int32_t max_lifetime_ms,
    Timestamp created_at) {
  const uint64_t msg_seq = next_msg_seq_id_++;
  const size_t total = payload.size();
  const size_t frag_count =
      std::max<size_t>(1, (total + kMaxSctpFragmentPayload - 1) /
                              kMaxSctpFragmentPayload);

  size_t offset = 0;
  for (size_t i = 0; i < frag_count; ++i) {
    const size_t len = std::min(kMaxSctpFragmentPayload, total - offset);
    const int64_t uw_tsn = next_tx_tsn_unwrapped_++;
    OutboundDataChunk chunk;
    chunk.msg_seq_id = msg_seq;
    chunk.tsn = static_cast<uint32_t>(uw_tsn & 0xFFFFFFFFULL);
    chunk.sid = sid;
    chunk.ssn = ordered ? ssn : 0;
    chunk.ppid = ppid;
    chunk.flags = ordered ? 0u : kDataFlagUnordered;
    if (i == 0) {
      chunk.flags |= kDataFlagBegin;
    }
    if (i + 1 == frag_count) {
      chunk.flags |= kDataFlagEnd;
    }
    if (len > 0) {
      chunk.payload.assign(payload.data() + offset,
                           payload.data() + offset + len);
    }
    chunk.ordered = ordered;
    chunk.max_retransmits = max_retransmits;
    chunk.max_lifetime_ms = max_lifetime_ms;
    chunk.created_at = created_at;
    outbound_buffered_bytes_ += len;
    outbound_chunks_.emplace(uw_tsn, std::move(chunk));
    offset += len;
  }
}

void SctpDataChannelManager::FlushTransmitQueue(
    Timestamp now,
    bool allow_one_fast_rtx_packet) {
  if (assoc_state_ != AssocState::kEstablished || peer_vtag_ == 0) {
    return;
  }
  if (in_flush_transmit_) {
    pending_reentrant_flush_ = true;
    pending_reentrant_fast_rtx_ =
        pending_reentrant_fast_rtx_ || allow_one_fast_rtx_packet;
    return;
  }
  in_flush_transmit_ = true;
  bool fast_rtx_flag = allow_one_fast_rtx_packet;

  do {
    pending_reentrant_flush_ = false;
    CheckAbandonedAndSendForwardTsn(now);
    if (assoc_state_ != AssocState::kEstablished || peer_vtag_ == 0) {
      break;
    }

    std::vector<std::vector<uint8_t>> packets_to_send;
    std::vector<uint8_t> bundle;
    bundle.reserve(kMaxSctpPacketBytes);
    bool fast_rtx_packet_open = fast_rtx_flag;
    fast_rtx_flag = false;

    auto seal_bundle = [&]() {
      if (!bundle.empty()) {
        packets_to_send.push_back(std::move(bundle));
        bundle.clear();
        bundle.reserve(kMaxSctpPacketBytes);
        fast_rtx_packet_open = false;
      }
    };

    for (auto& [tsn, ch] : outbound_chunks_) {
      (void)tsn;
      if (ch.acked || ch.abandoned) {
        continue;
      }
      if (ch.tx_count > 0 && !ch.needs_retransmit) {
        continue;
      }

      const size_t chunk_wire_len = 16 + ch.payload.size();
      const size_t padded_len = (chunk_wire_len + 3u) & ~size_t{3};
      const bool bypass_cwnd_for_fast_rtx =
          fast_rtx_packet_open && ch.needs_retransmit &&
          (bundle.empty() ||
           12 + bundle.size() + padded_len <= kMaxSctpPacketBytes);

      // RFC 4960 第 6.1 / 7.2 节：同时遵守 cwnd 与对端 a_rwnd（flight_bytes_ == 0 时允许 1 个零窗口探测块）。
      if (flight_bytes_ > 0) {
        if (flight_bytes_ + chunk_wire_len > peer_rwnd_) {
          break;
        }
        if (!bypass_cwnd_for_fast_rtx &&
            flight_bytes_ + chunk_wire_len > cwnd_bytes_) {
          break;
        }
      }

      if (!bundle.empty() &&
          12 + bundle.size() + padded_len > kMaxSctpPacketBytes) {
        seal_bundle();
        if (flight_bytes_ > 0 && flight_bytes_ + chunk_wire_len > cwnd_bytes_) {
          break;
        }
      }

      uint8_t flags = ch.flags;
      if ((flags & kDataFlagEnd) != 0u) {
        flags |= kDataFlagImmediateSack;
      }
      AppendChunkHeader(kChunkData, flags,
                        static_cast<uint16_t>(chunk_wire_len), &bundle);
      uint8_t meta[12]{};
      WriteBigEndian32(meta, ch.tsn);
      WriteBigEndian16(meta + 4, ch.sid);
      WriteBigEndian16(meta + 6, ch.ssn);
      WriteBigEndian32(meta + 8, ch.ppid);
      bundle.insert(bundle.end(), meta, meta + sizeof(meta));
      bundle.insert(bundle.end(), ch.payload.begin(), ch.payload.end());
      PadTo4Bytes(&bundle);

      if (!ch.in_flight) {
        ch.in_flight = true;
        flight_bytes_ += chunk_wire_len;
      }
      ch.needs_retransmit = false;
      ch.last_sent_at = now;
      ++ch.tx_count;
      if (!t3_rtx_deadline_.IsFinite()) {
        t3_rtx_deadline_ = now + TimeDelta::Micros(rto_us_);
      }
    }

    seal_bundle();

    const uint32_t vtag = peer_vtag_;
    for (const auto& pkt_chunks : packets_to_send) {
      if (assoc_state_ != AssocState::kEstablished || peer_vtag_ == 0 ||
          peer_vtag_ != vtag) {
        break;
      }
      SendChunksPacket(vtag, pkt_chunks);
    }

    if (pending_reentrant_fast_rtx_) {
      fast_rtx_flag = true;
      pending_reentrant_fast_rtx_ = false;
    }
  } while (pending_reentrant_flush_ &&
           assoc_state_ == AssocState::kEstablished && peer_vtag_ != 0);

  in_flush_transmit_ = false;
}

void SctpDataChannelManager::SendForwardTsnChunk(Timestamp now) {
  if (!peer_supports_prsctp_ || peer_vtag_ == 0 ||
      advanced_peer_ack_point_unwrapped_ <= last_acked_tx_tsn_unwrapped_) {
    return;
  }

  std::vector<std::pair<uint16_t, uint16_t>> stream_entries;
  stream_entries.reserve(abandoned_ordered_streams_.size());
  for (const auto& [sid, rec] : abandoned_ordered_streams_) {
    if (rec.adv_tsn_unwrapped > last_acked_tx_tsn_unwrapped_) {
      stream_entries.emplace_back(sid, rec.ssn);
      if (stream_entries.size() >= 256) {
        break;
      }
    }
  }

  std::vector<uint8_t> ftsn;
  const uint16_t chunk_len =
      static_cast<uint16_t>(8 + stream_entries.size() * 4);
  AppendChunkHeader(kChunkForwardTsn, 0, chunk_len, &ftsn);
  uint8_t cum_bytes[4];
  WriteBigEndian32(cum_bytes,
                   static_cast<uint32_t>(advanced_peer_ack_point_unwrapped_ &
                                         0xFFFFFFFFULL));
  ftsn.insert(ftsn.end(), cum_bytes, cum_bytes + 4);
  for (const auto& [sid, ssn] : stream_entries) {
    uint8_t entry[4];
    WriteBigEndian16(entry, sid);
    WriteBigEndian16(entry + 2, ssn);
    ftsn.insert(ftsn.end(), entry, entry + 4);
  }
  SendChunksPacket(peer_vtag_, ftsn);
  last_forward_tsn_tx_ = now;
  dup_sack_below_adv_count_ = 0;

  if (!t3_rtx_deadline_.IsFinite()) {
    t3_rtx_deadline_ = now + TimeDelta::Micros(rto_us_);
  }
}

void SctpDataChannelManager::CheckAbandonedAndSendForwardTsn(Timestamp now) {
  if (!peer_supports_prsctp_) {
    return;
  }

  std::set<uint64_t> newly_abandoned_msgs;
  for (const auto& [tsn, ch] : outbound_chunks_) {
    (void)tsn;
    if (ch.acked || ch.abandoned) {
      continue;
    }
    // RFC 3758：仅当分片真正需要重传且已耗尽允许重传次数时才视为超过重传预算。
    const bool rtx_exceeded =
        (ch.max_retransmits >= 0) && ch.needs_retransmit &&
        (ch.tx_count > static_cast<uint32_t>(ch.max_retransmits));
    const bool ttl_expired =
        (ch.max_lifetime_ms >= 0) && ch.created_at.IsFinite() &&
        now.IsFinite() && ((now - ch.created_at).ms() >= ch.max_lifetime_ms);
    if (rtx_exceeded || ttl_expired) {
      newly_abandoned_msgs.insert(ch.msg_seq_id);
    }
  }

  if (!newly_abandoned_msgs.empty()) {
    for (auto& [tsn, ch] : outbound_chunks_) {
      (void)tsn;
      if (!ch.abandoned &&
          newly_abandoned_msgs.find(ch.msg_seq_id) !=
              newly_abandoned_msgs.end()) {
        ch.abandoned = true;
        ch.needs_retransmit = false;
        if (ch.in_flight) {
          const size_t sz = 16 + ch.payload.size();
          flight_bytes_ = (flight_bytes_ >= sz) ? (flight_bytes_ - sz) : 0;
          ch.in_flight = false;
        }
      }
    }
  }

  // 推进 advanced_peer_ack_point_unwrapped_ 并持久化被跳过有序流的最大 SSN（RFC 3758 第 3.5 节）。
  const int64_t prev_adv = advanced_peer_ack_point_unwrapped_;
  std::set<uint16_t> updated_sids;
  for (auto it = outbound_chunks_.begin(); it != outbound_chunks_.end();) {
    if (it->first <= advanced_peer_ack_point_unwrapped_) {
      if (it->first <= last_acked_tx_tsn_unwrapped_ ||
          it->second.abandoned || it->second.acked) {
        const size_t p_sz = it->second.payload.size();
        outbound_buffered_bytes_ = (outbound_buffered_bytes_ >= p_sz)
                                       ? (outbound_buffered_bytes_ - p_sz)
                                       : 0;
        it = outbound_chunks_.erase(it);
        continue;
      }
      ++it;
      continue;
    }
    if (it->first != advanced_peer_ack_point_unwrapped_ + 1) {
      break;
    }
    if (!it->second.acked && !it->second.abandoned) {
      break;
    }
    advanced_peer_ack_point_unwrapped_ = it->first;
    if (it->second.abandoned && it->second.ordered) {
      auto st_it = abandoned_ordered_streams_.find(it->second.sid);
      if (st_it == abandoned_ordered_streams_.end() ||
          IsSsnBeforeOrEqual(st_it->second.ssn, it->second.ssn)) {
        abandoned_ordered_streams_[it->second.sid] =
            AbandonedStreamRecord{it->second.ssn, it->first};
      }
      updated_sids.insert(it->second.sid);
    }
    const size_t p_sz = it->second.payload.size();
    outbound_buffered_bytes_ = (outbound_buffered_bytes_ >= p_sz)
                                   ? (outbound_buffered_bytes_ - p_sz)
                                   : 0;
    it = outbound_chunks_.erase(it);
  }

  if (prev_adv < advanced_peer_ack_point_unwrapped_) {
    for (uint16_t sid : updated_sids) {
      auto st_it = abandoned_ordered_streams_.find(sid);
      if (st_it != abandoned_ordered_streams_.end()) {
        st_it->second.adv_tsn_unwrapped = advanced_peer_ack_point_unwrapped_;
      }
    }
    SendForwardTsnChunk(now);
  }
}

void SctpDataChannelManager::OnInboundSctpPacket(
    ArrayView<const uint8_t> packet,
    Timestamp now) {
  if (packet.size() < 12) {
    return;
  }

  // 校验 SCTP CRC-32c 完整性（RFC 4960 第 6.8 节）。
  const uint32_t rx_crc = static_cast<uint32_t>(packet[8]) |
                          (static_cast<uint32_t>(packet[9]) << 8) |
                          (static_cast<uint32_t>(packet[10]) << 16) |
                          (static_cast<uint32_t>(packet[11]) << 24);
  if (ComputeSctpPacketCrc32c(packet) != rx_crc) {
    RTC_LOG(kWarning) << "Dropped inbound SCTP packet with invalid CRC-32c";
    return;
  }

  const uint16_t src_port = ReadBigEndian16(packet.data());
  const uint16_t dst_port = ReadBigEndian16(packet.data() + 2);
  const uint32_t rx_vtag = ReadBigEndian32(packet.data() + 4);
  if (src_port == 0 || dst_port != local_port_) {
    return;
  }
  if (local_vtag_ != 0 && rx_vtag == local_vtag_) {
    remote_port_ = src_port;
  }

  const bool had_rx_gaps_before = !rx_seen_tsns_.empty();
  size_t off = 12;
  bool immediate_sack = false;
  while (off + 4 <= packet.size()) {
    const uint8_t ctype = packet[off];
    const uint8_t cflags = packet[off + 1];
    const uint16_t clen = ReadBigEndian16(packet.data() + off + 2);
    if (clen < 4 || off + clen > packet.size()) {
      break;
    }

    if (ctype == kChunkInit) {
      if (rx_vtag != 0 || off != 12) {
        break;
      }
    } else if (ctype == kChunkCookieEcho) {
      if (rx_vtag == 0 ||
          (rx_vtag != local_vtag_ && assoc_state_ != AssocState::kEstablished)) {
        break;
      }
    } else if (ctype == kChunkAbort) {
      const bool valid_t_vtag =
          ((cflags & 0x01u) != 0u) && peer_vtag_ != 0 && rx_vtag == peer_vtag_;
      if (rx_vtag != local_vtag_ && !valid_t_vtag) {
        break;
      }
    } else if (local_vtag_ == 0 || rx_vtag != local_vtag_) {
      break;
    }

    const ArrayView<const uint8_t> body =
        packet.subview(off + 4, static_cast<size_t>(clen - 4));
    switch (ctype) {
      case kChunkInit:
        HandleInitChunk(src_port, body, now);
        return;
      case kChunkInitAck:
        HandleInitAckChunk(body, now);
        break;
      case kChunkCookieEcho:
        HandleCookieEchoChunk(rx_vtag, src_port, body, now);
        break;
      case kChunkCookieAck:
        HandleCookieAckChunk(now);
        break;
      case kChunkData:
        if (body.size() > 12 && (cflags & kDataFlagImmediateSack) != 0u) {
          immediate_sack = true;
        }
        HandleDataChunk(cflags, body, now);
        break;
      case kChunkSack:
        HandleSackChunk(body, now);
        break;
      case kChunkHeartbeat:
        HandleHeartbeatChunk(body);
        break;
      case kChunkForwardTsn:
        HandleForwardTsnChunk(body, now);
        immediate_sack = true;
        break;
      case kChunkReconfig:
        HandleReconfigChunk(body, now);
        break;
      case kChunkShutdown: {
        if (assoc_state_ == AssocState::kEstablished && peer_vtag_ != 0) {
          std::vector<uint8_t> sack;
          AppendChunkHeader(kChunkShutdownAck, 0, 4, &sack);
          SendChunksPacket(peer_vtag_, sack);
        }
        break;
      }
      case kChunkAbort: {
        std::vector<std::pair<int, std::string>> to_close;
        for (const auto& [cid, ch] : channels_) {
          if (ch.state != RTC_DATA_CHANNEL_CLOSED) {
            to_close.emplace_back(cid, ch.config.label);
          }
        }
        Shutdown();
        if (observer_ != nullptr) {
          for (const auto& [cid, label] : to_close) {
            observer_->OnSctpDataChannelState(cid, label,
                                              RTC_DATA_CHANNEL_CLOSED);
          }
        }
        return;
      }
      default:
        break;
    }

    off += (static_cast<size_t>(clen) + 3u) & ~size_t{3};
  }

  if (sack_needed_) {
    if (immediate_sack || packets_since_sack_ >= 2 || had_rx_gaps_before ||
        !rx_seen_tsns_.empty()) {
      SendSackChunk(now);
    } else if (!sack_deadline_.IsFinite()) {
      sack_deadline_ = now + TimeDelta::Millis(40);
    }
  }
}

void SctpDataChannelManager::HandleHeartbeatChunk(
    ArrayView<const uint8_t> chunk_body) {
  if (assoc_state_ != AssocState::kEstablished || chunk_body.size() > 1100) {
    return;
  }
  std::vector<uint8_t> ack;
  AppendChunkHeader(kChunkHeartbeatAck, 0,
                    static_cast<uint16_t>(4 + chunk_body.size()), &ack);
  ack.insert(ack.end(), chunk_body.begin(), chunk_body.end());
  PadTo4Bytes(&ack);
  SendChunksPacket(peer_vtag_, ack);
}

void SctpDataChannelManager::HandleDataChunk(
    uint8_t chunk_flags,
    ArrayView<const uint8_t> chunk_body,
    Timestamp now) {
  // RFC 4960 第 6.2 节：严禁接收 0 字节负载 DATA 块（chunk_body.size() <= 12）。
  if (assoc_state_ != AssocState::kEstablished || chunk_body.size() <= 12) {
    return;
  }
  const uint32_t tsn = ReadBigEndian32(chunk_body.data());
  const uint16_t sid = ReadBigEndian16(chunk_body.data() + 4);
  const uint16_t ssn = ReadBigEndian16(chunk_body.data() + 6);
  const uint32_t ppid = ReadBigEndian32(chunk_body.data() + 8);
  if (sid >= negotiated_mis_) {
    return;
  }

  const ArrayView<const uint8_t> user_data =
      chunk_body.subview(12, chunk_body.size() - 12);
  const int64_t base_cum_tsn = has_peer_initial_tsn_
                                   ? peer_cum_tsn_ack_unwrapped_
                                   : (static_cast<int64_t>(tsn) - 1);
  const int32_t tsn_delta = static_cast<int32_t>(
      tsn - static_cast<uint32_t>(base_cum_tsn & 0xFFFFFFFFULL));
  const int64_t uw_tsn = base_cum_tsn + tsn_delta;

  if (has_peer_initial_tsn_ &&
      (tsn_delta <= 0 || rx_seen_tsns_.find(uw_tsn) != rx_seen_tsns_.end())) {
    // 收到重复 TSN，立即通过 SACK 通知发送端更新确认点。
    sack_needed_ = true;
    packets_since_sack_ = 2;
    return;
  }

  auto drop_before_sack = [&]() {
    if (has_peer_initial_tsn_) {
      sack_needed_ = true;
      packets_since_sack_ = 2;
    }
  };

  if (tsn_delta > 32768) {
    drop_before_sack();
    return;
  }

  // 在将 TSN 计入 SACK 确认集合之前执行所有接收缓冲区与队列容量准入检查，严禁先 SACK 后丢包！
  const size_t cur_buffered = ComputeBufferedRxBytes();
  const size_t new_chunk_cost = user_data.size() + kRxEntryOverheadBytes;
  const bool zero_win_probe_ok =
      (tsn_delta == 1 && cur_buffered == 0 &&
       user_data.size() <= kDefaultAdvertisedRwnd);
  if (!zero_win_probe_ok &&
      (cur_buffered + new_chunk_cost > kDefaultAdvertisedRwnd ||
       rx_seen_tsns_.size() >= kMaxSeenTsns ||
       rx_fragments_.size() >= kMaxRxFragments)) {
    drop_before_sack();
    return;
  }

  const bool unordered = (chunk_flags & kDataFlagUnordered) != 0u;
  int16_t ssn_delta = 0;
  int64_t expected_ssn = 0;
  if (!unordered) {
    const auto exp_it = next_expected_ssn_.find(sid);
    expected_ssn = (exp_it != next_expected_ssn_.end()) ? exp_it->second : 0;
    ssn_delta = static_cast<int16_t>(
        ssn - static_cast<uint16_t>(expected_ssn & 0xFFFFLL));
    if (ssn_delta >= 16384) {
      drop_before_sack();
      return;
    }
    if (ssn_delta > 0) {
      const int64_t uw_ssn = expected_ssn + ssn_delta;
      const auto ord_it = ordered_ready_.find(sid);
      const bool already_has_ssn =
          (ord_it != ordered_ready_.end() &&
           ord_it->second.find(uw_ssn) != ord_it->second.end());
      if (!already_has_ssn) {
        if (ordered_ready_count_ >= kMaxTotalOrderedBufferedMsgs ||
            (ord_it != ordered_ready_.end() &&
             ord_it->second.size() >= kMaxStreamOrderedBufferedMsgs)) {
          drop_before_sack();
          return;
        }
      }
    }
  }

  if (ppid != kPpidDcep &&
      sid_to_channel_id_.find(sid) == sid_to_channel_id_.end()) {
    const auto early_it = early_rx_messages_.find(sid);
    if (early_it == early_rx_messages_.end() &&
        early_rx_messages_.size() >= kMaxEarlyRxStreams) {
      drop_before_sack();
      return;
    }
    const size_t cur_early =
        (early_it != early_rx_messages_.end()) ? early_it->second.size() : 0;
    const auto ord_it = ordered_ready_.find(sid);
    const size_t cur_ord =
        (ord_it != ordered_ready_.end()) ? ord_it->second.size() : 0;
    if (cur_early + cur_ord >= kMaxEarlyRxMsgsPerStream) {
      drop_before_sack();
      return;
    }
  }

  if (!has_peer_initial_tsn_) {
    peer_initial_tsn_ = tsn;
    peer_cum_tsn_ack_unwrapped_ = base_cum_tsn;
    has_peer_initial_tsn_ = true;
  }

  sack_needed_ = true;
  ++packets_since_sack_;

  rx_seen_tsns_.insert(uw_tsn);
  while (true) {
    const auto next_it = rx_seen_tsns_.find(peer_cum_tsn_ack_unwrapped_ + 1);
    if (next_it == rx_seen_tsns_.end()) {
      break;
    }
    peer_cum_tsn_ack_unwrapped_ = *next_it;
    rx_seen_tsns_.erase(next_it);
  }

  InboundDataFragment frag;
  frag.tsn = tsn;
  frag.sid = sid;
  frag.ssn = ssn;
  frag.ppid = ppid;
  frag.flags = chunk_flags;
  frag.payload.assign(user_data.begin(), user_data.end());
  const size_t frag_sz = frag.payload.size();
  auto [ins_it, inserted] = rx_fragments_.emplace(uw_tsn, std::move(frag));
  (void)ins_it;
  if (inserted) {
    rx_frag_bytes_ += frag_sz;
  }

  TryReassembleAround(uw_tsn);
  ProcessPendingInboundResetIfReady(now);
}

void SctpDataChannelManager::TryReassembleAround(int64_t pivot_tsn) {
  auto pivot_it = rx_fragments_.find(pivot_tsn);
  if (pivot_it == rx_fragments_.end()) {
    return;
  }

  // 向回查找连续 TSN 直至定位起始分片（B=1）。
  int64_t start_tsn = pivot_tsn;
  while ((rx_fragments_[start_tsn].flags & kDataFlagBegin) == 0u) {
    const auto prev_it = rx_fragments_.find(start_tsn - 1);
    if (prev_it == rx_fragments_.end() ||
        (prev_it->second.flags & kDataFlagEnd) != 0u) {
      return;
    }
    start_tsn = prev_it->first;
  }

  // 向前查找连续 TSN 直至定位结束分片（E=1）。
  int64_t end_tsn = pivot_tsn;
  while ((rx_fragments_[end_tsn].flags & kDataFlagEnd) == 0u) {
    const auto next_it = rx_fragments_.find(end_tsn + 1);
    if (next_it == rx_fragments_.end() ||
        (next_it->second.flags & kDataFlagBegin) != 0u) {
      return;
    }
    end_tsn = next_it->first;
  }

  const auto first_it = rx_fragments_.find(start_tsn);
  const uint16_t sid = first_it->second.sid;
  const uint16_t ssn = first_it->second.ssn;
  const uint32_t ppid = first_it->second.ppid;
  const bool unordered = (first_it->second.flags & kDataFlagUnordered) != 0u;

  size_t total_bytes = 0;
  bool valid_chain = true;
  for (int64_t cur = start_tsn; cur <= end_tsn; ++cur) {
    const auto& f = rx_fragments_[cur];
    const bool f_unordered = (f.flags & kDataFlagUnordered) != 0u;
    if (f.sid != sid || f_unordered != unordered ||
        (!unordered && f.ssn != ssn)) {
      valid_chain = false;
      break;
    }
    total_bytes += f.payload.size();
    if (total_bytes > kDefaultAdvertisedRwnd) {
      valid_chain = false;
      break;
    }
  }

  std::vector<uint8_t> full_payload;
  if (valid_chain) {
    full_payload.reserve(total_bytes);
  }
  for (int64_t cur = start_tsn; cur <= end_tsn; ++cur) {
    const auto it = rx_fragments_.find(cur);
    const size_t piece_sz = it->second.payload.size();
    if (valid_chain) {
      full_payload.insert(full_payload.end(), it->second.payload.begin(),
                          it->second.payload.end());
    }
    rx_frag_bytes_ =
        (rx_frag_bytes_ >= piece_sz) ? (rx_frag_bytes_ - piece_sz) : 0;
    rx_fragments_.erase(it);
  }
  if (!valid_chain) {
    return;
  }

  DeliverReassembledMessage(sid, ssn, ppid, unordered, std::move(full_payload));
}

void SctpDataChannelManager::DeliverReassembledMessage(
    uint16_t sid,
    uint16_t ssn,
    uint32_t ppid,
    bool unordered,
    std::vector<uint8_t> payload) {
  if (unordered) {
    if (ppid == kPpidDcep) {
      HandleDcepMessage(sid, payload);
    } else {
      DeliverUserPayloadOnStream(sid, ppid, std::move(payload));
    }
    return;
  }

  auto& expected = next_expected_ssn_[sid];
  const int16_t ssn_delta =
      static_cast<int16_t>(ssn - static_cast<uint16_t>(expected & 0xFFFFLL));
  if (ssn_delta < 0 || ssn_delta >= 16384) {
    return;
  }
  const int64_t uw_ssn = expected + ssn_delta;
  auto& stream_map = ordered_ready_[sid];
  const size_t msg_sz = payload.size();
  auto [it, inserted] =
      stream_map.emplace(uw_ssn, ReassembledMessage{ppid, std::move(payload)});
  (void)it;
  if (inserted) {
    ordered_ready_bytes_ += msg_sz;
    ++ordered_ready_count_;
  }
  DrainOrderedStream(sid);
}

void SctpDataChannelManager::DrainOrderedStream(uint16_t sid) {
  auto exp_it = next_expected_ssn_.find(sid);
  if (exp_it == next_expected_ssn_.end()) {
    exp_it = next_expected_ssn_.emplace(sid, 0).first;
  }
  auto ord_it = ordered_ready_.find(sid);
  if (ord_it == ordered_ready_.end()) {
    return;
  }

  while (!ord_it->second.empty()) {
    auto msg_it = ord_it->second.begin();
    if (msg_it->first < exp_it->second) {
      const size_t drop_sz = msg_it->second.payload.size();
      ordered_ready_bytes_ = (ordered_ready_bytes_ >= drop_sz)
                                 ? (ordered_ready_bytes_ - drop_sz)
                                 : 0;
      ordered_ready_count_ =
          (ordered_ready_count_ > 0) ? (ordered_ready_count_ - 1) : 0;
      ord_it->second.erase(msg_it);
      continue;
    }
    if (msg_it->first != exp_it->second) {
      break;
    }
    ++exp_it->second;
    const size_t msg_sz = msg_it->second.payload.size();
    ordered_ready_bytes_ =
        (ordered_ready_bytes_ >= msg_sz) ? (ordered_ready_bytes_ - msg_sz) : 0;
    ordered_ready_count_ =
        (ordered_ready_count_ > 0) ? (ordered_ready_count_ - 1) : 0;
    ReassembledMessage msg = std::move(msg_it->second);
    ord_it->second.erase(msg_it);

    if (msg.ppid == kPpidDcep) {
      HandleDcepMessage(sid, msg.payload);
    } else {
      DeliverUserPayloadOnStream(sid, msg.ppid, std::move(msg.payload));
    }

    // 回调期间通道可能被关闭或流被重置，重新校验迭代器有效性。
    exp_it = next_expected_ssn_.find(sid);
    ord_it = ordered_ready_.find(sid);
    if (exp_it == next_expected_ssn_.end() || ord_it == ordered_ready_.end()) {
      return;
    }
  }
  if (ord_it->second.empty()) {
    ordered_ready_.erase(ord_it);
  }
}

void SctpDataChannelManager::HandleDcepMessage(
    uint16_t sid,
    ArrayView<const uint8_t> payload) {
  if (payload.empty()) {
    return;
  }
  const uint8_t msg_type = payload[0];
  if (msg_type == kDcepMsgAck) {
    return;
  }
  if (msg_type != kDcepMsgOpen || payload.size() < 12) {
    return;
  }

  // RFC 8832 第 5.1 节：拒绝在已打开本地流上的 DCEP OPEN 冲突（Glare），禁止静默合并。
  if (sid_to_channel_id_.find(sid) != sid_to_channel_id_.end()) {
    RTC_LOG(kWarning) << "Rejected DCEP OPEN glare on already-open stream sid="
                      << sid;
    return;
  }
  if (channels_.size() >= 2048) {
    return;
  }

  const uint8_t chan_type = payload[1];
  const uint32_t rel_param = ReadBigEndian32(payload.data() + 4);
  const uint16_t label_len = ReadBigEndian16(payload.data() + 8);
  const uint16_t proto_len = ReadBigEndian16(payload.data() + 10);
  if (12u + label_len + proto_len > payload.size()) {
    return;
  }

  const uint8_t rel_kind = static_cast<uint8_t>(chan_type & 0x7Fu);
  if (rel_kind > 0x02u) {
    RTC_LOG(kWarning) << "Rejected DCEP OPEN with unsupported channel_type="
                      << static_cast<int>(chan_type);
    return;
  }
  const int32_t clamped_rel = static_cast<int32_t>(
      std::min<uint32_t>(rel_param, static_cast<uint32_t>(INT32_MAX)));

  std::string label(reinterpret_cast<const char*>(payload.data() + 12),
                    label_len);
  std::string proto(
      reinterpret_cast<const char*>(payload.data() + 12 + label_len),
      proto_len);

  const int channel_id = next_channel_id_++;
  ChannelEntry entry;
  entry.channel_id = channel_id;
  entry.config.label = label;
  entry.config.protocol = proto;
  entry.config.ordered = (chan_type & 0x80u) == 0u;
  if (rel_kind == 0x01u) {
    entry.config.max_retransmits = clamped_rel;
  } else if (rel_kind == 0x02u) {
    entry.config.max_packet_lifetime_ms = clamped_rel;
  }
  entry.sctp_sid = sid;
  entry.state = RTC_DATA_CHANNEL_OPEN;
  entry.open_sent = true;
  entry.open_notified = true;
  channels_.emplace(channel_id, std::move(entry));
  sid_to_channel_id_[sid] = channel_id;

  if (observer_ != nullptr) {
    observer_->OnSctpDataChannelState(channel_id, label, RTC_DATA_CHANNEL_OPEN);
  }

  SendDcepAck(sid, clock_->CurrentTime());

  // 冲刷可能在无序模式下先于 DATA_CHANNEL_OPEN 到达的应用消息并归还接收缓冲计数。
  const auto early_it = early_rx_messages_.find(sid);
  if (early_it != early_rx_messages_.end()) {
    auto queue = std::move(early_it->second);
    early_rx_messages_.erase(early_it);
    for (const auto& [is_bin, msg_data] : queue) {
      (void)is_bin;
      early_rx_bytes_ = (early_rx_bytes_ >= msg_data.size())
                            ? (early_rx_bytes_ - msg_data.size())
                            : 0;
    }
    early_rx_count_ =
        (early_rx_count_ >= queue.size()) ? (early_rx_count_ - queue.size()) : 0;
    for (auto& [is_bin, msg_data] : queue) {
      if (observer_ != nullptr) {
        observer_->OnSctpDataChannelMessage(channel_id, is_bin,
                                            std::move(msg_data));
      }
    }
  }
}

void SctpDataChannelManager::DeliverUserPayloadOnStream(
    uint16_t sid,
    uint32_t ppid,
    std::vector<uint8_t> payload) {
  // RFC 8831 第 6.6 节：PPID 52/54 为旧式非 EOR 分块消息，须按流累积至收到终止 PPID 53/51 后再合并投递。
  if (ppid == kPpidWebRtcBinaryPartial || ppid == kPpidWebRtcStringPartial) {
    const bool partial_is_bin = (ppid == kPpidWebRtcBinaryPartial);
    auto& part = partial_rx_messages_[sid];
    if (!part.data.empty() && part.is_binary != partial_is_bin) {
      partial_rx_bytes_ = (partial_rx_bytes_ >= part.data.size())
                              ? (partial_rx_bytes_ - part.data.size())
                              : 0;
      part.data.clear();
    }
    part.is_binary = partial_is_bin;
    if (part.data.size() + payload.size() + kRxEntryOverheadBytes >
        kDefaultAdvertisedRwnd) {
      partial_rx_bytes_ = (partial_rx_bytes_ >= part.data.size())
                              ? (partial_rx_bytes_ - part.data.size())
                              : 0;
      partial_rx_messages_.erase(sid);
      return;
    }
    part.data.insert(part.data.end(), payload.begin(), payload.end());
    partial_rx_bytes_ += payload.size();
    return;
  }

  bool is_binary = true;
  if (ppid == kPpidWebRtcString) {
    is_binary = false;
  } else if (ppid == kPpidWebRtcStringEmpty) {
    is_binary = false;
    payload.clear();
  } else if (ppid == kPpidWebRtcBinaryEmpty) {
    is_binary = true;
    payload.clear();
  } else if (ppid == kPpidWebRtcBinary) {
    is_binary = true;
  } else {
    RTC_LOG(kWarning) << "Rejected SCTP user message with unknown PPID=" << ppid;
    return;
  }

  const auto part_it = partial_rx_messages_.find(sid);
  if (part_it != partial_rx_messages_.end()) {
    const bool same_mode = (part_it->second.is_binary == is_binary);
    partial_rx_bytes_ =
        (partial_rx_bytes_ >= part_it->second.data.size())
            ? (partial_rx_bytes_ - part_it->second.data.size())
            : 0;
    std::vector<uint8_t> merged = std::move(part_it->second.data);
    partial_rx_messages_.erase(part_it);
    if (!same_mode) {
      RTC_LOG(kWarning) << "Dropped mismatched partial PPID prefix on sid="
                        << sid;
    } else {
      merged.insert(merged.end(), payload.begin(), payload.end());
      payload = std::move(merged);
    }
  }

  const auto cid_it = sid_to_channel_id_.find(sid);
  if (cid_it == sid_to_channel_id_.end()) {
    if (early_rx_messages_.find(sid) == early_rx_messages_.end() &&
        early_rx_messages_.size() >= kMaxEarlyRxStreams) {
      return;
    }
    auto& q = early_rx_messages_[sid];
    if (q.size() < kMaxEarlyRxMsgsPerStream) {
      early_rx_bytes_ += payload.size();
      ++early_rx_count_;
      q.emplace_back(is_binary, std::move(payload));
    } else if (q.empty()) {
      early_rx_messages_.erase(sid);
    }
    return;
  }
  if (observer_ != nullptr) {
    observer_->OnSctpDataChannelMessage(cid_it->second, is_binary,
                                        std::move(payload));
  }
}

void SctpDataChannelManager::HandleForwardTsnChunk(
    ArrayView<const uint8_t> chunk_body,
    Timestamp now) {
  if (assoc_state_ != AssocState::kEstablished || chunk_body.size() < 4 ||
       !has_peer_initial_tsn_) {
    return;
  }
  const uint32_t new_cum_tsn = ReadBigEndian32(chunk_body.data());
  const int32_t fwd_delta = static_cast<int32_t>(
      new_cum_tsn -
      static_cast<uint32_t>(peer_cum_tsn_ack_unwrapped_ & 0xFFFFFFFFULL));
  if (fwd_delta > 0 && fwd_delta <= 65536) {
    peer_cum_tsn_ack_unwrapped_ += fwd_delta;
  } else if (fwd_delta > 65536) {
    return;
  }

  for (auto it = rx_seen_tsns_.begin(); it != rx_seen_tsns_.end();) {
    if (*it <= peer_cum_tsn_ack_unwrapped_) {
      it = rx_seen_tsns_.erase(it);
    } else {
      break;
    }
  }
  while (true) {
    const auto next_it = rx_seen_tsns_.find(peer_cum_tsn_ack_unwrapped_ + 1);
    if (next_it == rx_seen_tsns_.end()) {
      break;
    }
    peer_cum_tsn_ack_unwrapped_ = *next_it;
    rx_seen_tsns_.erase(next_it);
  }
  for (auto it = rx_fragments_.begin(); it != rx_fragments_.end();) {
    if (it->first <= peer_cum_tsn_ack_unwrapped_) {
      const size_t fsz = it->second.payload.size();
      rx_frag_bytes_ = (rx_frag_bytes_ >= fsz) ? (rx_frag_bytes_ - fsz) : 0;
      it = rx_fragments_.erase(it);
    } else {
      break;
    }
  }

  // RFC 3758 第 3.6 节：推进被跳过的有序流 SSN 并立即投递后续已就绪消息。
  for (size_t off = 4; off + 4 <= chunk_body.size(); off += 4) {
    const uint16_t sid = ReadBigEndian16(chunk_body.data() + off);
    if (sid >= negotiated_mis_) {
      continue;
    }
    const uint16_t skipped_ssn = ReadBigEndian16(chunk_body.data() + off + 2);
    auto& expected = next_expected_ssn_[sid];
    const int16_t skip_delta = static_cast<int16_t>(
        skipped_ssn - static_cast<uint16_t>(expected & 0xFFFFLL));
    if (skip_delta >= 0 && skip_delta < 16384) {
      expected += static_cast<int64_t>(skip_delta) + 1;
    }
    DrainOrderedStream(sid);
  }
  ProcessPendingInboundResetIfReady(now);
  sack_needed_ = true;
}

void SctpDataChannelManager::ExecuteInboundStreamReset(
    const std::vector<uint16_t>& sids,
    Timestamp now) {
  for (uint16_t sid : sids) {
    if (sid >= negotiated_mis_) {
      continue;
    }
    ClearStreamRxState(sid, /*clear_early_rx=*/true);

    const auto cid_it = sid_to_channel_id_.find(sid);
    if (cid_it == sid_to_channel_id_.end()) {
      continue;
    }
    const int cid = cid_it->second;
    sid_to_channel_id_.erase(cid_it);

    const auto ch_it = channels_.find(cid);
    if (ch_it == channels_.end()) {
      continue;
    }
    ch_it->second.inbound_reset_done = true;

    // RFC 8831 第 6.7 节：收到对端 Outgoing SSN Reset Request 后自动回发本端流重置请求以完成双向关闭。
    if (!ch_it->second.outbound_reset_queued &&
        !ch_it->second.outbound_reset_done) {
      const bool notify_closing =
          (ch_it->second.state != RTC_DATA_CHANNEL_CLOSING &&
           ch_it->second.state != RTC_DATA_CHANNEL_CLOSED);
      ch_it->second.state = RTC_DATA_CHANNEL_CLOSING;
      ch_it->second.pending_messages.clear();
      ch_it->second.pending_bytes = 0;
      const std::string label = ch_it->second.config.label;
      if (notify_closing && observer_ != nullptr) {
        observer_->OnSctpDataChannelState(cid, label, RTC_DATA_CHANNEL_CLOSING);
      }
      const auto recheck_it = channels_.find(cid);
      if (recheck_it != channels_.end() &&
          !recheck_it->second.outbound_reset_queued &&
          !recheck_it->second.outbound_reset_done) {
        recheck_it->second.outbound_reset_queued = true;
        EnqueueOutgoingStreamReset(sid, now);
      }
    }
    FinalizeChannelCloseIfReady(cid);
  }
}

void SctpDataChannelManager::ProcessPendingInboundResetIfReady(Timestamp now) {
  if (!pending_inbound_reset_.has_value() || !has_peer_initial_tsn_) {
    return;
  }
  if (peer_cum_tsn_ack_unwrapped_ <
      pending_inbound_reset_->req_last_tsn_unwrapped) {
    return;
  }

  DeferredInboundReset ready = std::move(*pending_inbound_reset_);
  pending_inbound_reset_.reset();
  last_peer_reconfig_seq_ = ready.req_seq;
  SendReconfigResponse(ready.req_seq, kReconfigResultSuccessPerformed);
  ExecuteInboundStreamReset(ready.sids, now);
}

void SctpDataChannelManager::HandleReconfigChunk(
    ArrayView<const uint8_t> chunk_body,
    Timestamp now) {
  if (assoc_state_ != AssocState::kEstablished || !has_peer_initial_tsn_) {
    return;
  }
  size_t off = 0;
  while (off + 4 <= chunk_body.size()) {
    const uint16_t ptype = ReadBigEndian16(chunk_body.data() + off);
    const uint16_t plen = ReadBigEndian16(chunk_body.data() + off + 2);
    if (plen < 4 || off + plen > chunk_body.size()) {
      break;
    }
    if (ptype == kParamOutgoingSsnResetReq && plen >= 16) {
      const uint32_t req_seq = ReadBigEndian32(chunk_body.data() + off + 4);
      const uint32_t req_last_tsn =
          ReadBigEndian32(chunk_body.data() + off + 12);

      std::vector<uint16_t> sids;
      for (size_t s_off = off + 16; s_off + 2 <= off + plen; s_off += 2) {
        const uint16_t sid = ReadBigEndian16(chunk_body.data() + s_off);
        if (sid < negotiated_mis_) {
          sids.push_back(sid);
        }
      }

      if (pending_inbound_reset_.has_value() &&
          req_seq == pending_inbound_reset_->req_seq) {
        if (peer_cum_tsn_ack_unwrapped_ >=
            pending_inbound_reset_->req_last_tsn_unwrapped) {
          ProcessPendingInboundResetIfReady(now);
        } else {
          SendReconfigResponse(req_seq, kReconfigResultInProgress);
        }
      } else if (last_peer_reconfig_seq_.has_value() &&
                 req_seq == *last_peer_reconfig_seq_) {
        SendReconfigResponse(req_seq, kReconfigResultSuccessPerformed);
      } else if (!last_peer_reconfig_seq_.has_value() ||
                 static_cast<int32_t>(req_seq - *last_peer_reconfig_seq_) > 0) {
        const int32_t last_tsn_delta = static_cast<int32_t>(
            req_last_tsn - static_cast<uint32_t>(peer_cum_tsn_ack_unwrapped_ &
                                                 0xFFFFFFFFULL));
        if (last_tsn_delta <= 1048576) {
          const int64_t req_last_tsn_uw =
              peer_cum_tsn_ack_unwrapped_ + last_tsn_delta;
          if (peer_cum_tsn_ack_unwrapped_ < req_last_tsn_uw) {
            pending_inbound_reset_ =
                DeferredInboundReset{req_seq, req_last_tsn_uw, std::move(sids)};
            SendReconfigResponse(req_seq, kReconfigResultInProgress);
          } else {
            pending_inbound_reset_.reset();
            last_peer_reconfig_seq_ = req_seq;
            SendReconfigResponse(req_seq, kReconfigResultSuccessPerformed);
            ExecuteInboundStreamReset(sids, now);
          }
        }
      }
    } else if (ptype == kParamReconfigResponse && plen >= 12) {
      const uint32_t resp_seq = ReadBigEndian32(chunk_body.data() + off + 4);
      const uint32_t result = ReadBigEndian32(chunk_body.data() + off + 8);
      if (inflight_outbound_reset_.has_value() &&
          resp_seq == inflight_outbound_reset_->req_seq) {
        if (result == kReconfigResultInProgress) {
          inflight_outbound_reset_->last_sent_at = now;
          inflight_outbound_reset_->rtx_count = 1;
        } else {
          const std::vector<uint16_t> reset_sids =
              std::move(inflight_outbound_reset_->sids);
          inflight_outbound_reset_.reset();

          std::vector<int> affected_cids;
          for (uint16_t sid : reset_sids) {
            outbound_reset_pending_sids_.erase(sid);
            abandoned_ordered_streams_.erase(sid);
            for (auto& [cid, ch] : channels_) {
              if (ch.sctp_sid.has_value() && *ch.sctp_sid == sid &&
                  !ch.outbound_reset_done) {
                ch.outbound_reset_done = true;
                ch.next_tx_ssn = 0;
                affected_cids.push_back(cid);
              }
            }
          }
          for (int cid : affected_cids) {
            FinalizeChannelCloseIfReady(cid);
          }
          PumpOutboundStreamResetQueue(now);
        }
      }
    }
    off += (static_cast<size_t>(plen) + 3u) & ~size_t{3};
  }
}

void SctpDataChannelManager::SendSackChunk(Timestamp /*now*/) {
  if (!has_peer_initial_tsn_ || peer_vtag_ == 0) {
    return;
  }

  std::vector<std::pair<uint16_t, uint16_t>> gaps;
  if (!rx_seen_tsns_.empty()) {
    int64_t range_start = *rx_seen_tsns_.begin();
    int64_t range_end = range_start;
    for (auto it = std::next(rx_seen_tsns_.begin()); it != rx_seen_tsns_.end();
         ++it) {
      if (*it == range_end + 1) {
        range_end = *it;
      } else {
        const int64_t s_off = range_start - peer_cum_tsn_ack_unwrapped_;
        const int64_t e_off = range_end - peer_cum_tsn_ack_unwrapped_;
        if (s_off > 0 && s_off <= 65535 && e_off >= s_off && e_off <= 65535 &&
            gaps.size() < 32) {
          gaps.emplace_back(static_cast<uint16_t>(s_off),
                            static_cast<uint16_t>(e_off));
        }
        range_start = *it;
        range_end = *it;
      }
    }
    const int64_t s_off = range_start - peer_cum_tsn_ack_unwrapped_;
    const int64_t e_off = range_end - peer_cum_tsn_ack_unwrapped_;
    if (s_off > 0 && s_off <= 65535 && e_off >= s_off && e_off <= 65535 &&
        gaps.size() < 32) {
      gaps.emplace_back(static_cast<uint16_t>(s_off),
                        static_cast<uint16_t>(e_off));
    }
  }

  std::vector<uint8_t> sack;
  const uint16_t len = static_cast<uint16_t>(16 + gaps.size() * 4);
  AppendChunkHeader(kChunkSack, 0, len, &sack);
  uint8_t fixed[12]{};
  WriteBigEndian32(fixed,
                   static_cast<uint32_t>(peer_cum_tsn_ack_unwrapped_ &
                                         0xFFFFFFFFULL));
  WriteBigEndian32(fixed + 4, CurrentAdvertisedRwnd());
  WriteBigEndian16(fixed + 8, static_cast<uint16_t>(gaps.size()));
  WriteBigEndian16(fixed + 10, 0);
  sack.insert(sack.end(), fixed, fixed + sizeof(fixed));
  for (const auto& [g_start, g_end] : gaps) {
    uint8_t gbuf[4];
    WriteBigEndian16(gbuf, g_start);
    WriteBigEndian16(gbuf + 2, g_end);
    sack.insert(sack.end(), gbuf, gbuf + 4);
  }

  SendChunksPacket(peer_vtag_, sack);
  sack_needed_ = false;
  packets_since_sack_ = 0;
  sack_deadline_ = Timestamp::PlusInfinity();
}

void SctpDataChannelManager::HandleSackChunk(ArrayView<const uint8_t> chunk_body,
                                             Timestamp now) {
  if (assoc_state_ != AssocState::kEstablished || chunk_body.size() < 12) {
    return;
  }
  const uint32_t cum_ack = ReadBigEndian32(chunk_body.data());
  const uint32_t sack_arwnd = ReadBigEndian32(chunk_body.data() + 4);
  const uint16_t num_gaps = ReadBigEndian16(chunk_body.data() + 8);
  if (12u + static_cast<size_t>(num_gaps) * 4u > chunk_body.size()) {
    return;
  }

  // RFC 4960 第 6.2.1 节：丢弃乱序旧 SACK（cum_delta < 0）及越界伪造 SACK（cum_ack > max_sent_tsn）。
  const int32_t cum_delta = static_cast<int32_t>(
      cum_ack -
      static_cast<uint32_t>(last_acked_tx_tsn_unwrapped_ & 0xFFFFFFFFULL));
  if (cum_delta < 0) {
    return;
  }
  const int64_t cum_ack_uw = last_acked_tx_tsn_unwrapped_ + cum_delta;
  const int64_t max_sent_tsn_uw = next_tx_tsn_unwrapped_ - 1;
  if (cum_ack_uw > max_sent_tsn_uw) {
    RTC_LOG(kWarning) << "Dropped SCTP SACK acknowledging unsent cum_ack="
                      << cum_ack << " > max_sent_tsn="
                      << static_cast<uint32_t>(max_sent_tsn_uw & 0xFFFFFFFFULL);
    return;
  }

  std::vector<std::pair<int64_t, int64_t>> gap_ranges;
  gap_ranges.reserve(num_gaps);
  for (uint16_t i = 0; i < num_gaps; ++i) {
    const uint16_t s_off = ReadBigEndian16(chunk_body.data() + 12 + i * 4);
    const uint16_t e_off = ReadBigEndian16(chunk_body.data() + 14 + i * 4);
    if (s_off > 0 && e_off >= s_off) {
      const int64_t gs = cum_ack_uw + s_off;
      const int64_t ge = cum_ack_uw + e_off;
      if (ge > max_sent_tsn_uw) {
        RTC_LOG(kWarning) << "Dropped SCTP SACK with unsent gap_end=" << ge;
        return;
      }
      gap_ranges.emplace_back(gs, ge);
    }
  }

  peer_rwnd_ = sack_arwnd;

  const int64_t prev_last_acked = last_acked_tx_tsn_unwrapped_;
  const int64_t prev_adv_ack = advanced_peer_ack_point_unwrapped_;
  const bool cum_ack_advanced = (cum_ack_uw > last_acked_tx_tsn_unwrapped_);
  if (cum_ack_advanced) {
    last_acked_tx_tsn_unwrapped_ = cum_ack_uw;
    if (cum_ack_uw > advanced_peer_ack_point_unwrapped_) {
      advanced_peer_ack_point_unwrapped_ = cum_ack_uw;
    }
    if (in_fast_recovery_ && cum_ack_uw >= fast_recovery_exit_point_) {
      in_fast_recovery_ = false;
      fast_recovery_exit_point_ = -1;
    }
    if (last_acked_tx_tsn_unwrapped_ >= advanced_peer_ack_point_unwrapped_) {
      abandoned_ordered_streams_.clear();
      dup_sack_below_adv_count_ = 0;
    } else {
      for (auto st_it = abandoned_ordered_streams_.begin();
           st_it != abandoned_ordered_streams_.end();) {
        if (st_it->second.adv_tsn_unwrapped <= last_acked_tx_tsn_unwrapped_) {
          st_it = abandoned_ordered_streams_.erase(st_it);
        } else {
          ++st_it;
        }
      }
    }
  }

  int64_t highest_sacked_tsn_uw = cum_ack_uw;
  if (!gap_ranges.empty()) {
    highest_sacked_tsn_uw =
        std::max(highest_sacked_tsn_uw, gap_ranges.back().second);
  }

  auto in_any_gap = [&gap_ranges](int64_t tsn_uw) {
    for (const auto& [gs, ge] : gap_ranges) {
      if (gs <= tsn_uw && tsn_uw <= ge) {
        return true;
      }
    }
    return false;
  };

  size_t newly_acked_bytes = 0;
  bool fast_rtx_triggered = false;
  for (auto it = outbound_chunks_.begin(); it != outbound_chunks_.end();) {
    const int64_t tsn_uw = it->first;
    OutboundDataChunk& ch = it->second;
    const bool acked_now = (tsn_uw <= cum_ack_uw) || in_any_gap(tsn_uw);
    if (acked_now && !ch.acked) {
      ch.acked = true;
      ch.needs_retransmit = false;
      const size_t sz = 16 + ch.payload.size();
      newly_acked_bytes += sz;
      if (ch.in_flight) {
        flight_bytes_ = (flight_bytes_ >= sz) ? (flight_bytes_ - sz) : 0;
        ch.in_flight = false;
      }
      if (ch.tx_count == 1 && ch.last_sent_at.IsFinite() && now.IsFinite()) {
        const int64_t rtt =
            std::max<int64_t>(1000, (now - ch.last_sent_at).us());
        if (!has_rtt_sample_) {
          srtt_us_ = rtt;
          rttvar_us_ = rtt / 2;
          has_rtt_sample_ = true;
        } else {
          const int64_t diff = std::abs(srtt_us_ - rtt);
          rttvar_us_ = (3 * rttvar_us_ + diff) / 4;
          srtt_us_ = (7 * srtt_us_ + rtt) / 8;
        }
        rto_us_ = std::clamp<int64_t>(srtt_us_ + 4 * rttvar_us_, 60'000,
                                      2'000'000);
      }
    } else if (!ch.acked && !ch.abandoned && ch.tx_count > 0 &&
               !ch.fast_retransmitted && !ch.needs_retransmit &&
               tsn_uw < highest_sacked_tsn_uw) {
      // RFC 4960 第 7.2.4 节：累计 3 次 Gap Ack 缺失报告触发单次快速重传。
      ++ch.gap_reports;
      if (ch.gap_reports >= 3) {
        ch.needs_retransmit = true;
        ch.fast_retransmitted = true;
        ch.gap_reports = 0;
        if (ch.in_flight) {
          const size_t sz = 16 + ch.payload.size();
          flight_bytes_ = (flight_bytes_ >= sz) ? (flight_bytes_ - sz) : 0;
          ch.in_flight = false;
        }
        if (ch.max_retransmits < 0 ||
            ch.tx_count <= static_cast<uint32_t>(ch.max_retransmits)) {
          fast_rtx_triggered = true;
        }
      }
    }

    if (tsn_uw <= last_acked_tx_tsn_unwrapped_) {
      if (tsn_uw == advanced_peer_ack_point_unwrapped_ + 1) {
        advanced_peer_ack_point_unwrapped_ = tsn_uw;
      }
      const size_t p_sz = ch.payload.size();
      outbound_buffered_bytes_ = (outbound_buffered_bytes_ >= p_sz)
                                     ? (outbound_buffered_bytes_ - p_sz)
                                     : 0;
      it = outbound_chunks_.erase(it);
    } else {
      ++it;
    }
  }

  // RFC 4960 第 7.2.4 节：Fast Recovery 期间每个 RTT 最多减半一次 cwnd。
  if (fast_rtx_triggered) {
    if (!in_fast_recovery_) {
      ssthresh_bytes_ = std::max<size_t>(cwnd_bytes_ / 2, 4 * 1200);
      cwnd_bytes_ = ssthresh_bytes_;
      partial_bytes_acked_ = 0;
      in_fast_recovery_ = true;
      fast_recovery_exit_point_ = max_sent_tsn_uw;
    }
  } else if (cum_ack_advanced && newly_acked_bytes > 0 && !in_fast_recovery_) {
    if (cwnd_bytes_ <= ssthresh_bytes_) {
      cwnd_bytes_ = std::min<size_t>(
          cwnd_bytes_ + std::min<size_t>(newly_acked_bytes, 1200), 1024 * 1024);
    } else {
      partial_bytes_acked_ += newly_acked_bytes;
      if (partial_bytes_acked_ >= cwnd_bytes_) {
        partial_bytes_acked_ -= cwnd_bytes_;
        cwnd_bytes_ = std::min<size_t>(cwnd_bytes_ + 1200, 1024 * 1024);
      }
    }
  }

  // RFC 3758 第 3.5 节：当 SACK 指示 cum_ack 仍落后于已发送的 advanced_peer_ack_point 时驱动重发。
  bool need_reemit_ftsn = false;
  if (peer_supports_prsctp_ && last_acked_tx_tsn_unwrapped_ < prev_adv_ack &&
      (!gap_ranges.empty() || cum_ack_uw == prev_last_acked)) {
    ++dup_sack_below_adv_count_;
    const bool cooldown_ok =
        !last_forward_tsn_tx_.IsFinite() || !now.IsFinite() ||
        (now - last_forward_tsn_tx_) >= TimeDelta::Millis(20);
    if (dup_sack_below_adv_count_ >= 2 || cooldown_ok) {
      need_reemit_ftsn = true;
    }
  }

  const int64_t adv_before_flush = advanced_peer_ack_point_unwrapped_;
  FlushTransmitQueue(now, fast_rtx_triggered);
  if (need_reemit_ftsn &&
      advanced_peer_ack_point_unwrapped_ == adv_before_flush &&
      last_acked_tx_tsn_unwrapped_ < advanced_peer_ack_point_unwrapped_) {
    SendForwardTsnChunk(now);
  }

  const bool has_unacked_ftsn =
      peer_supports_prsctp_ &&
      (last_acked_tx_tsn_unwrapped_ < advanced_peer_ack_point_unwrapped_);
  if (flight_bytes_ == 0 && !has_unacked_ftsn) {
    t3_rtx_deadline_ = Timestamp::PlusInfinity();
  } else if (newly_acked_bytes > 0 || cum_ack_advanced ||
             !t3_rtx_deadline_.IsFinite()) {
    t3_rtx_deadline_ = now + TimeDelta::Micros(rto_us_);
  }
}

void SctpDataChannelManager::OnPeriodicTick(Timestamp now) {
  if (!started_) {
    return;
  }

  // 1. 驱动 SCTP 四次握手重传（以及被动端超时兜底主动握手）。
  if (assoc_state_ != AssocState::kEstablished) {
    if (assoc_state_ == AssocState::kClosed &&
        handshake_started_at_.IsFinite() &&
        (now - handshake_started_at_) >= TimeDelta::Millis(1000)) {
      assoc_state_ = AssocState::kCookieWait;
      SendInitChunk(now);
      return;
    }
    const int64_t backoff_ms = std::min<int64_t>(
        1000, 100LL << std::min<uint32_t>(handshake_rtx_count_, 4));
    if (last_handshake_tx_.IsFinite() &&
        (now - last_handshake_tx_) >= TimeDelta::Millis(backoff_ms)) {
      ++handshake_rtx_count_;
      if (assoc_state_ == AssocState::kCookieWait) {
        SendInitChunk(now);
      } else if (assoc_state_ == AssocState::kCookieEchoed &&
                 !pending_cookie_.empty()) {
        std::vector<uint8_t> echo_chunk;
        AppendChunkHeader(kChunkCookieEcho, 0,
                          static_cast<uint16_t>(4 + pending_cookie_.size()),
                          &echo_chunk);
        echo_chunk.insert(echo_chunk.end(), pending_cookie_.begin(),
                          pending_cookie_.end());
        PadTo4Bytes(&echo_chunk);
        SendChunksPacket(peer_vtag_, echo_chunk);
        last_handshake_tx_ = now;
      }
    }
    return;
  }

  // 2. 驱动延迟 SACK 定时器（40ms 上限）。
  if (sack_needed_ && sack_deadline_.IsFinite() && now >= sack_deadline_) {
    SendSackChunk(now);
  }

  // 3. 检查 PR-SCTP 报文生存期超时并推进 FORWARD-TSN。
  CheckAbandonedAndSendForwardTsn(now);

  // 4. 驱动未确认 RE-CONFIG Outgoing SSN Reset Request 重传定时器（RFC 6525 第 5.1.1 节）。
  if (inflight_outbound_reset_.has_value()) {
    const uint32_t shift =
        (inflight_outbound_reset_->rtx_count > 0)
            ? std::min<uint32_t>(inflight_outbound_reset_->rtx_count - 1, 4)
            : 0;
    const int64_t reconfig_timeout_us =
        std::min<int64_t>(2'000'000, rto_us_ << shift);
    if (!inflight_outbound_reset_->last_sent_at.IsFinite() ||
        (now - inflight_outbound_reset_->last_sent_at) >=
            TimeDelta::Micros(reconfig_timeout_us)) {
      SendInflightOutboundReset(now);
    }
  } else if (!queued_outbound_reset_sids_.empty()) {
    PumpOutboundStreamResetQueue(now);
  }

  // 5. 驱动 T3-rtx 超时重传定时器（同时覆盖 DATA 重传与未确认 FORWARD-TSN 重传）。
  if (t3_rtx_deadline_.IsFinite() && now >= t3_rtx_deadline_) {
    bool marked_any = false;
    for (auto& [tsn, ch] : outbound_chunks_) {
      (void)tsn;
      if (!ch.acked && !ch.abandoned && ch.tx_count > 0) {
        ch.needs_retransmit = true;
        if (ch.in_flight) {
          const size_t sz = 16 + ch.payload.size();
          flight_bytes_ = (flight_bytes_ >= sz) ? (flight_bytes_ - sz) : 0;
          ch.in_flight = false;
        }
        marked_any = true;
      }
    }
    const bool has_unacked_ftsn =
        peer_supports_prsctp_ &&
        (last_acked_tx_tsn_unwrapped_ < advanced_peer_ack_point_unwrapped_);
    if (marked_any || has_unacked_ftsn) {
      in_fast_recovery_ = false;
      fast_recovery_exit_point_ = -1;
      partial_bytes_acked_ = 0;
      if (marked_any) {
        ssthresh_bytes_ = std::max<size_t>(cwnd_bytes_ / 2, 4 * 1200);
        cwnd_bytes_ = 2 * 1200;
      }
      rto_us_ = std::min<int64_t>(rto_us_ * 2, 2'000'000);
      t3_rtx_deadline_ = now + TimeDelta::Micros(rto_us_);

      const int64_t adv_before = advanced_peer_ack_point_unwrapped_;
      CheckAbandonedAndSendForwardTsn(now);
      if (peer_supports_prsctp_ &&
          advanced_peer_ack_point_unwrapped_ == adv_before &&
          last_acked_tx_tsn_unwrapped_ < advanced_peer_ack_point_unwrapped_) {
        SendForwardTsnChunk(now);
      }
      FlushTransmitQueue(now);

      const bool still_unacked_ftsn =
          peer_supports_prsctp_ &&
          (last_acked_tx_tsn_unwrapped_ < advanced_peer_ack_point_unwrapped_);
      if (flight_bytes_ == 0 && !still_unacked_ftsn) {
        t3_rtx_deadline_ = Timestamp::PlusInfinity();
      }
    } else {
      t3_rtx_deadline_ = Timestamp::PlusInfinity();
    }
  }
}

}  // namespace rtc
