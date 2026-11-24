#include "pc/sctp_data_channel.h"

#include <algorithm>
#include <array>
#include <cstring>

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
constexpr uint16_t kParamForwardTsnSupported = 0xC000;
constexpr uint16_t kParamOutgoingSsnResetReq = 0x000D;
constexpr uint16_t kParamReconfigResponse = 0x0010;

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

// 分片与封包尺寸限制（预留 DTLS 1.2 记录头及 UDP/IP 头部余量，防止 IP 层分片）。
constexpr size_t kMaxSctpFragmentPayload = 1000;
constexpr size_t kMaxSctpPacketBytes = 1160;
constexpr uint32_t kDefaultAdvertisedRwnd = 1024 * 1024;
constexpr uint32_t kStateCookieMagic = 0x5254434Bu;

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
  local_vtag_ = GenerateNonZeroRandom32();
  local_initial_tsn_ = GenerateNonZeroRandom32();
  next_tx_tsn_ = local_initial_tsn_;
  last_acked_tx_tsn_ = local_initial_tsn_ - 1;
  advanced_peer_ack_point_ = last_acked_tx_tsn_;
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
  outbound_chunks_.clear();
  rx_seen_tsns_.clear();
  rx_fragments_.clear();
  ordered_ready_.clear();
  early_rx_messages_.clear();
  flight_bytes_ = 0;
  for (auto& [cid, ch] : channels_) {
    (void)cid;
    ch.pending_messages.clear();
    ch.state = RTC_DATA_CHANNEL_CLOSED;
  }
}

uint16_t SctpDataChannelManager::AllocateNextLocalStreamId() {
  uint16_t* cursor =
      (dtls_role_ == DtlsRole::kClient) ? &next_even_sid_ : &next_odd_sid_;
  while (sid_to_channel_id_.find(*cursor) != sid_to_channel_id_.end()) {
    *cursor = static_cast<uint16_t>(*cursor + 2);
  }
  const uint16_t chosen = *cursor;
  *cursor = static_cast<uint16_t>(*cursor + 2);
  return chosen;
}

int SctpDataChannelManager::CreateDataChannel(const DataChannelConfig& config) {
  if (config.negotiated) {
    if (config.id < 0 || config.id > 65534) {
      return RTC_ERR_INVALID_ARG;
    }
    const uint16_t sid = static_cast<uint16_t>(config.id);
    if (sid_to_channel_id_.find(sid) != sid_to_channel_id_.end()) {
      return RTC_ERR_INVALID_ARG;
    }
  }

  const int channel_id = next_channel_id_++;
  ChannelEntry entry;
  entry.channel_id = channel_id;
  entry.config = config;
  if (entry.config.label.empty()) {
    entry.config.label = "data_" + std::to_string(channel_id);
  }
  if (config.negotiated) {
    const uint16_t sid = static_cast<uint16_t>(config.id);
    entry.sctp_sid = sid;
    sid_to_channel_id_[sid] = channel_id;
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
    if (ch.pending_messages.size() >= 512) {
      return RTC_ERR_NO_MEMORY;
    }
    PendingUserMessage pending;
    pending.payload.assign(payload.begin(), payload.end());
    pending.is_binary = is_binary;
    pending.queued_at = now;
    ch.pending_messages.push_back(std::move(pending));
    return RTC_OK;
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
  const std::string label = ch.config.label;
  if (ch.sctp_sid.has_value()) {
    const uint16_t sid = *ch.sctp_sid;
    if (assoc_state_ == AssocState::kEstablished) {
      // 发送 RFC 6525 Outgoing SSN Reset Request (0x000D) 通知远端关闭该流。
      std::vector<uint8_t> chunk;
      AppendChunkHeader(kChunkReconfig, 0, 4 + 18, &chunk);
      uint8_t hdr[18]{};
      WriteBigEndian16(hdr, kParamOutgoingSsnResetReq);
      WriteBigEndian16(hdr + 2, 18);
      WriteBigEndian32(hdr + 4, next_reconfig_seq_++);
      WriteBigEndian32(hdr + 8, 0);
      WriteBigEndian32(hdr + 12, next_tx_tsn_ - 1);
      WriteBigEndian16(hdr + 16, sid);
      chunk.insert(chunk.end(), hdr, hdr + sizeof(hdr));
      PadTo4Bytes(&chunk);
      SendChunksPacket(peer_vtag_, chunk);
    }
    sid_to_channel_id_.erase(sid);
    ordered_ready_.erase(sid);
    next_expected_ssn_.erase(sid);
    early_rx_messages_.erase(sid);
  }
  channels_.erase(it);
  if (observer_ != nullptr) {
    observer_->OnSctpDataChannelState(channel_id, label,
                                      RTC_DATA_CHANNEL_CLOSED);
  }
  return RTC_OK;
}

std::vector<uint8_t> SctpDataChannelManager::BuildSctpPacket(
    uint32_t vtag,
    ArrayView<const uint8_t> chunks_bytes) const {
  std::vector<uint8_t> pkt(12 + chunks_bytes.size(), 0);
  WriteBigEndian16(pkt.data(), local_port_);
  WriteBigEndian16(pkt.data() + 2, remote_port_);
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

bool SctpDataChannelManager::SendChunksPacket(
    uint32_t vtag,
    ArrayView<const uint8_t> chunks_bytes) {
  if (observer_ == nullptr || chunks_bytes.empty()) {
    return false;
  }
  const auto wire = BuildSctpPacket(vtag, chunks_bytes);
  return observer_->SendSctpPacketOverDtls(wire);
}

void SctpDataChannelManager::SendInitChunk(Timestamp now) {
  std::vector<uint8_t> chunk;
  // INIT 固定体 16 字节 + Forward-TSN-Supported (4 字节) + Chunk 头 (4 字节) = 24 字节。
  AppendChunkHeader(kChunkInit, 0, 24, &chunk);
  uint8_t body[20]{};
  WriteBigEndian32(body, local_vtag_);
  WriteBigEndian32(body + 4, kDefaultAdvertisedRwnd);
  WriteBigEndian16(body + 8, 1024);
  WriteBigEndian16(body + 10, 1024);
  WriteBigEndian32(body + 12, local_initial_tsn_);
  WriteBigEndian16(body + 16, kParamForwardTsnSupported);
  WriteBigEndian16(body + 18, 4);
  chunk.insert(chunk.end(), body, body + sizeof(body));
  SendChunksPacket(0, chunk);
  last_handshake_tx_ = now;
}

void SctpDataChannelManager::HandleInitChunk(ArrayView<const uint8_t> chunk_body,
                                             Timestamp now) {
  if (chunk_body.size() < 16) {
    return;
  }
  const uint32_t init_tag = ReadBigEndian32(chunk_body.data());
  const uint32_t peer_init_tsn = ReadBigEndian32(chunk_body.data() + 12);
  if (init_tag == 0) {
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
    }
    off += (static_cast<size_t>(plen) + 3u) & ~size_t{3};
  }

  // 构造带状态 Cookie (0x0007) 与 Forward-TSN-Supported (0xC000) 的 INIT-ACK。
  std::vector<uint8_t> chunk;
  constexpr uint16_t kInitAckLen = 4 + 16 + 20 + 4;
  AppendChunkHeader(kChunkInitAck, 0, kInitAckLen, &chunk);
  uint8_t fixed[16]{};
  WriteBigEndian32(fixed, local_vtag_);
  WriteBigEndian32(fixed + 4, kDefaultAdvertisedRwnd);
  WriteBigEndian16(fixed + 8, 1024);
  WriteBigEndian16(fixed + 10, 1024);
  WriteBigEndian32(fixed + 12, local_initial_tsn_);
  chunk.insert(chunk.end(), fixed, fixed + sizeof(fixed));

  uint8_t cookie_param[20]{};
  WriteBigEndian16(cookie_param, kParamStateCookie);
  WriteBigEndian16(cookie_param + 2, 20);
  WriteBigEndian32(cookie_param + 4, kStateCookieMagic);
  WriteBigEndian32(cookie_param + 8, init_tag);
  WriteBigEndian32(cookie_param + 12, peer_init_tsn);
  WriteBigEndian32(cookie_param + 16, prsctp ? 1u : 0u);
  chunk.insert(chunk.end(), cookie_param, cookie_param + sizeof(cookie_param));

  uint8_t ftsn_param[4]{};
  WriteBigEndian16(ftsn_param, kParamForwardTsnSupported);
  WriteBigEndian16(ftsn_param + 2, 4);
  chunk.insert(chunk.end(), ftsn_param, ftsn_param + sizeof(ftsn_param));

  SendChunksPacket(init_tag, chunk);
  (void)now;
}

void SctpDataChannelManager::HandleInitAckChunk(
    ArrayView<const uint8_t> chunk_body,
    Timestamp now) {
  if (assoc_state_ != AssocState::kCookieWait || chunk_body.size() < 16) {
    return;
  }
  const uint32_t init_tag = ReadBigEndian32(chunk_body.data());
  const uint32_t peer_init_tsn = ReadBigEndian32(chunk_body.data() + 12);
  if (init_tag == 0) {
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
    if (ptype == kParamStateCookie && plen > 4) {
      cookie.assign(chunk_body.data() + off + 4,
                    chunk_body.data() + off + plen);
    } else if (ptype == kParamForwardTsnSupported) {
      prsctp = true;
    }
    off += (static_cast<size_t>(plen) + 3u) & ~size_t{3};
  }
  if (cookie.empty()) {
    return;
  }

  peer_vtag_ = init_tag;
  peer_supports_prsctp_ = prsctp;
  if (!has_peer_initial_tsn_) {
    peer_cum_tsn_ack_ = peer_init_tsn - 1;
    has_peer_initial_tsn_ = true;
  }
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
    ArrayView<const uint8_t> chunk_body,
    Timestamp now) {
  if (chunk_body.size() >= 16 &&
      ReadBigEndian32(chunk_body.data()) == kStateCookieMagic) {
    const uint32_t c_peer_vtag = ReadBigEndian32(chunk_body.data() + 4);
    const uint32_t c_peer_tsn = ReadBigEndian32(chunk_body.data() + 8);
    const bool c_prsctp = ReadBigEndian32(chunk_body.data() + 12) != 0u;
    if (c_peer_vtag != 0) {
      peer_vtag_ = c_peer_vtag;
      peer_supports_prsctp_ = c_prsctp;
      if (!has_peer_initial_tsn_) {
        peer_cum_tsn_ack_ = c_peer_tsn - 1;
        has_peer_initial_tsn_ = true;
      }
    }
  }

  std::vector<uint8_t> ack_chunk;
  AppendChunkHeader(kChunkCookieAck, 0, 4, &ack_chunk);
  SendChunksPacket(peer_vtag_, ack_chunk);

  if (assoc_state_ != AssocState::kEstablished) {
    OnAssociationEstablished(now);
  }
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
                 << ", role=" << (dtls_role_ == DtlsRole::kClient ? "client" : "server")
                 << ", pr_sctp=" << (peer_supports_prsctp_ ? "on" : "off") << ")";

  for (auto& [cid, ch] : channels_) {
    (void)cid;
    ActivateChannelIfReady(&ch, now);
  }
  FlushTransmitQueue(now);
}

void SctpDataChannelManager::ActivateChannelIfReady(ChannelEntry* ch,
                                                    Timestamp now) {
  if (ch == nullptr || ch->state == RTC_DATA_CHANNEL_CLOSED ||
      assoc_state_ != AssocState::kEstablished) {
    return;
  }
  if (!ch->sctp_sid.has_value()) {
    const uint16_t sid = AllocateNextLocalStreamId();
    ch->sctp_sid = sid;
    sid_to_channel_id_[sid] = ch->channel_id;
  }
  if (!ch->config.negotiated && !ch->open_sent) {
    SendDcepOpen(*ch, now);
    ch->open_sent = true;
  }
  ch->state = RTC_DATA_CHANNEL_OPEN;
  if (!ch->open_notified && observer_ != nullptr) {
    ch->open_notified = true;
    observer_->OnSctpDataChannelState(ch->channel_id, ch->config.label,
                                      RTC_DATA_CHANNEL_OPEN);
  }

  // 按入队顺序冲刷在握手完成前预先缓存的应用消息。
  while (!ch->pending_messages.empty()) {
    PendingUserMessage msg = std::move(ch->pending_messages.front());
    ch->pending_messages.pop_front();

    uint32_t ppid = msg.is_binary ? kPpidWebRtcBinary : kPpidWebRtcString;
    std::vector<uint8_t> empty_placeholder(1, 0);
    ArrayView<const uint8_t> wire_payload = msg.payload;
    if (msg.payload.empty()) {
      ppid = msg.is_binary ? kPpidWebRtcBinaryEmpty : kPpidWebRtcStringEmpty;
      wire_payload = empty_placeholder;
    }
    const uint16_t ssn = ch->config.ordered ? ch->next_tx_ssn++ : 0;
    EnqueueSctpMessage(*ch->sctp_sid, ch->config.ordered, ssn, ppid,
                       wire_payload, ch->config.max_retransmits,
                       ch->config.max_packet_lifetime_ms, now);
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
    Timestamp now) {
  const uint64_t msg_seq = next_msg_seq_id_++;
  const size_t total = payload.size();
  const size_t frag_count =
      std::max<size_t>(1, (total + kMaxSctpFragmentPayload - 1) /
                              kMaxSctpFragmentPayload);

  size_t offset = 0;
  for (size_t i = 0; i < frag_count; ++i) {
    const size_t len = std::min(kMaxSctpFragmentPayload, total - offset);
    OutboundDataChunk chunk;
    chunk.msg_seq_id = msg_seq;
    chunk.tsn = next_tx_tsn_++;
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
    chunk.created_at = now;
    outbound_chunks_.emplace(chunk.tsn, std::move(chunk));
    offset += len;
  }
}

void SctpDataChannelManager::FlushTransmitQueue(Timestamp now) {
  if (assoc_state_ != AssocState::kEstablished || peer_vtag_ == 0) {
    return;
  }

  CheckAbandonedAndSendForwardTsn(now);

  std::vector<uint8_t> bundle;
  bundle.reserve(kMaxSctpPacketBytes);

  auto flush_bundle = [&]() {
    if (!bundle.empty()) {
      SendChunksPacket(peer_vtag_, bundle);
      bundle.clear();
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
    if (!ch.needs_retransmit && flight_bytes_ > 0 &&
        flight_bytes_ + chunk_wire_len > cwnd_bytes_) {
      break;
    }
    if (!bundle.empty() && 12 + bundle.size() + padded_len > kMaxSctpPacketBytes) {
      flush_bundle();
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

  flush_bundle();
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
    const bool rtx_exceeded =
        (ch.max_retransmits >= 0) &&
        (ch.tx_count > static_cast<uint32_t>(ch.max_retransmits));
    const bool ttl_expired =
        (ch.max_lifetime_ms >= 0) && ch.created_at.IsFinite() &&
        ((now - ch.created_at).ms() >= ch.max_lifetime_ms);
    if ((ch.tx_count > 0 && rtx_exceeded) || ttl_expired) {
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

  // 推进 advanced_peer_ack_point_ 并采集受影响有序流的最高被跳过 SSN。
  const uint32_t prev_adv = advanced_peer_ack_point_;
  std::map<uint16_t, uint16_t> skipped_ordered_streams;
  for (auto it = outbound_chunks_.begin(); it != outbound_chunks_.end();) {
    if (IsTsnBeforeOrEqual(it->first, advanced_peer_ack_point_)) {
      if (IsTsnBeforeOrEqual(it->first, last_acked_tx_tsn_) ||
          it->second.abandoned || it->second.acked) {
        it = outbound_chunks_.erase(it);
        continue;
      }
      ++it;
      continue;
    }
    if (it->first != advanced_peer_ack_point_ + 1) {
      break;
    }
    if (!it->second.acked && !it->second.abandoned) {
      break;
    }
    advanced_peer_ack_point_ = it->first;
    if (it->second.abandoned && it->second.ordered) {
      auto st_it = skipped_ordered_streams.find(it->second.sid);
      if (st_it == skipped_ordered_streams.end() ||
          IsSsnBeforeOrEqual(st_it->second, it->second.ssn)) {
        skipped_ordered_streams[it->second.sid] = it->second.ssn;
      }
    }
    it = outbound_chunks_.erase(it);
  }

  if (IsTsnBefore(prev_adv, advanced_peer_ack_point_)) {
    std::vector<uint8_t> ftsn;
    const uint16_t chunk_len = static_cast<uint16_t>(
        8 + skipped_ordered_streams.size() * 4);
    AppendChunkHeader(kChunkForwardTsn, 0, chunk_len, &ftsn);
    uint8_t cum_bytes[4];
    WriteBigEndian32(cum_bytes, advanced_peer_ack_point_);
    ftsn.insert(ftsn.end(), cum_bytes, cum_bytes + 4);
    for (const auto& [sid, ssn] : skipped_ordered_streams) {
      uint8_t entry[4];
      WriteBigEndian16(entry, sid);
      WriteBigEndian16(entry + 2, ssn);
      ftsn.insert(ftsn.end(), entry, entry + 4);
    }
    SendChunksPacket(peer_vtag_, ftsn);
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
  const uint32_t rx_vtag = ReadBigEndian32(packet.data() + 4);
  if (src_port != 0) {
    remote_port_ = src_port;
  }

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
      if (rx_vtag != 0) {
        break;
      }
    } else if (rx_vtag != local_vtag_) {
      break;
    }

    const ArrayView<const uint8_t> body =
        packet.subview(off + 4, static_cast<size_t>(clen - 4));
    switch (ctype) {
      case kChunkInit:
        HandleInitChunk(body, now);
        break;
      case kChunkInitAck:
        HandleInitAckChunk(body, now);
        break;
      case kChunkCookieEcho:
        HandleCookieEchoChunk(body, now);
        break;
      case kChunkCookieAck:
        HandleCookieAckChunk(now);
        break;
      case kChunkData:
        if ((cflags & kDataFlagImmediateSack) != 0u) {
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
        HandleForwardTsnChunk(body);
        immediate_sack = true;
        break;
      case kChunkReconfig:
        HandleReconfigChunk(body);
        break;
      case kChunkShutdown: {
        std::vector<uint8_t> sack;
        AppendChunkHeader(kChunkShutdownAck, 0, 4, &sack);
        SendChunksPacket(peer_vtag_, sack);
        break;
      }
      case kChunkAbort:
        Shutdown();
        return;
      default:
        break;
    }

    off += (static_cast<size_t>(clen) + 3u) & ~size_t{3};
  }

  if (sack_needed_) {
    if (immediate_sack || packets_since_sack_ >= 2 || !rx_seen_tsns_.empty()) {
      SendSackChunk(now);
    } else if (!sack_deadline_.IsFinite()) {
      sack_deadline_ = now + TimeDelta::Millis(40);
    }
  }
}

void SctpDataChannelManager::HandleHeartbeatChunk(
    ArrayView<const uint8_t> chunk_body) {
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
    Timestamp /*now*/) {
  if (chunk_body.size() < 12) {
    return;
  }
  const uint32_t tsn = ReadBigEndian32(chunk_body.data());
  const uint16_t sid = ReadBigEndian16(chunk_body.data() + 4);
  const uint16_t ssn = ReadBigEndian16(chunk_body.data() + 6);
  const uint32_t ppid = ReadBigEndian32(chunk_body.data() + 8);
  const ArrayView<const uint8_t> user_data =
      chunk_body.subview(12, chunk_body.size() - 12);

  if (!has_peer_initial_tsn_) {
    peer_cum_tsn_ack_ = tsn - 1;
    has_peer_initial_tsn_ = true;
  }

  sack_needed_ = true;
  ++packets_since_sack_;

  if (IsTsnBeforeOrEqual(tsn, peer_cum_tsn_ack_) ||
      rx_seen_tsns_.find(tsn) != rx_seen_tsns_.end()) {
    // 收到重复 TSN，立即通过 SACK 通知发送端更新确认点。
    packets_since_sack_ = 2;
    return;
  }

  rx_seen_tsns_.insert(tsn);
  while (true) {
    const auto next_it = rx_seen_tsns_.find(peer_cum_tsn_ack_ + 1);
    if (next_it == rx_seen_tsns_.end()) {
      break;
    }
    peer_cum_tsn_ack_ = *next_it;
    rx_seen_tsns_.erase(next_it);
  }

  InboundDataFragment frag;
  frag.tsn = tsn;
  frag.sid = sid;
  frag.ssn = ssn;
  frag.ppid = ppid;
  frag.flags = chunk_flags;
  frag.payload.assign(user_data.begin(), user_data.end());
  rx_fragments_.emplace(tsn, std::move(frag));
  while (rx_fragments_.size() > 2048) {
    rx_fragments_.erase(rx_fragments_.begin());
  }

  TryReassembleAround(tsn);
}

void SctpDataChannelManager::TryReassembleAround(uint32_t pivot_tsn) {
  auto pivot_it = rx_fragments_.find(pivot_tsn);
  if (pivot_it == rx_fragments_.end()) {
    return;
  }

  // 向回查找连续 TSN 直至定位起始分片（B=1）。
  uint32_t start_tsn = pivot_tsn;
  while ((rx_fragments_[start_tsn].flags & kDataFlagBegin) == 0u) {
    const auto prev_it = rx_fragments_.find(start_tsn - 1);
    if (prev_it == rx_fragments_.end() ||
        (prev_it->second.flags & kDataFlagEnd) != 0u) {
      return;
    }
    start_tsn = prev_it->first;
  }

  // 向前查找连续 TSN 直至定位结束分片（E=1）。
  uint32_t end_tsn = pivot_tsn;
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
  for (uint32_t cur = start_tsn;; ++cur) {
    total_bytes += rx_fragments_[cur].payload.size();
    if (cur == end_tsn) {
      break;
    }
  }

  std::vector<uint8_t> full_payload;
  full_payload.reserve(total_bytes);
  for (uint32_t cur = start_tsn;; ++cur) {
    const auto it = rx_fragments_.find(cur);
    full_payload.insert(full_payload.end(), it->second.payload.begin(),
                        it->second.payload.end());
    rx_fragments_.erase(it);
    if (cur == end_tsn) {
      break;
    }
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

  auto& stream_map = ordered_ready_[sid];
  stream_map.emplace(ssn, ReassembledMessage{ppid, std::move(payload)});
  DrainOrderedStream(sid);
}

void SctpDataChannelManager::DrainOrderedStream(uint16_t sid) {
  auto& expected = next_expected_ssn_[sid];
  auto& stream_map = ordered_ready_[sid];
  while (!stream_map.empty()) {
    auto it = stream_map.begin();
    if (static_cast<int16_t>(it->first - expected) < 0) {
      stream_map.erase(it);
      continue;
    }
    if (it->first != expected) {
      break;
    }
    expected = static_cast<uint16_t>(expected + 1);
    ReassembledMessage msg = std::move(it->second);
    stream_map.erase(it);
    if (msg.ppid == kPpidDcep) {
      HandleDcepMessage(sid, msg.payload);
    } else {
      DeliverUserPayloadOnStream(sid, msg.ppid, std::move(msg.payload));
    }
  }
  if (stream_map.empty()) {
    ordered_ready_.erase(sid);
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

  const uint8_t chan_type = payload[1];
  const uint32_t rel_param = ReadBigEndian32(payload.data() + 4);
  const uint16_t label_len = ReadBigEndian16(payload.data() + 8);
  const uint16_t proto_len = ReadBigEndian16(payload.data() + 10);
  if (12u + label_len + proto_len > payload.size()) {
    return;
  }

  std::string label(reinterpret_cast<const char*>(payload.data() + 12),
                    label_len);
  std::string proto(
      reinterpret_cast<const char*>(payload.data() + 12 + label_len),
      proto_len);

  int channel_id = -1;
  const auto existing_it = sid_to_channel_id_.find(sid);
  if (existing_it != sid_to_channel_id_.end()) {
    channel_id = existing_it->second;
  } else {
    channel_id = next_channel_id_++;
    ChannelEntry entry;
    entry.channel_id = channel_id;
    entry.config.label = label;
    entry.config.protocol = proto;
    entry.config.ordered = (chan_type & 0x80u) == 0u;
    if ((chan_type & 0x7Fu) == 0x01u) {
      entry.config.max_retransmits = static_cast<int32_t>(rel_param);
    } else if ((chan_type & 0x7Fu) == 0x02u) {
      entry.config.max_packet_lifetime_ms = static_cast<int32_t>(rel_param);
    }
    entry.sctp_sid = sid;
    entry.state = RTC_DATA_CHANNEL_OPEN;
    entry.open_sent = true;
    entry.open_notified = true;
    channels_.emplace(channel_id, std::move(entry));
    sid_to_channel_id_[sid] = channel_id;

    if (observer_ != nullptr) {
      observer_->OnSctpDataChannelState(channel_id, label,
                                        RTC_DATA_CHANNEL_OPEN);
    }
  }

  SendDcepAck(sid, clock_->CurrentTime());

  // 冲刷可能在无序模式下先于 DATA_CHANNEL_OPEN 到达的应用消息。
  const auto early_it = early_rx_messages_.find(sid);
  if (early_it != early_rx_messages_.end()) {
    auto queue = std::move(early_it->second);
    early_rx_messages_.erase(early_it);
    for (auto& [is_bin, data] : queue) {
      if (observer_ != nullptr) {
        observer_->OnSctpDataChannelMessage(channel_id, is_bin,
                                            std::move(data));
      }
    }
  }
}

void SctpDataChannelManager::DeliverUserPayloadOnStream(
    uint16_t sid,
    uint32_t ppid,
    std::vector<uint8_t> payload) {
  bool is_binary = true;
  if (ppid == kPpidWebRtcString || ppid == kPpidWebRtcStringPartial) {
    is_binary = false;
  } else if (ppid == kPpidWebRtcStringEmpty) {
    is_binary = false;
    payload.clear();
  } else if (ppid == kPpidWebRtcBinaryEmpty) {
    is_binary = true;
    payload.clear();
  } else if (ppid == kPpidWebRtcBinary || ppid == kPpidWebRtcBinaryPartial) {
    is_binary = true;
  }

  const auto cid_it = sid_to_channel_id_.find(sid);
  if (cid_it == sid_to_channel_id_.end()) {
    if (early_rx_messages_.size() >= 64 &&
        early_rx_messages_.find(sid) == early_rx_messages_.end()) {
      early_rx_messages_.erase(early_rx_messages_.begin());
    }
    auto& q = early_rx_messages_[sid];
    if (q.size() < 32) {
      q.emplace_back(is_binary, std::move(payload));
    }
    return;
  }
  if (observer_ != nullptr) {
    observer_->OnSctpDataChannelMessage(cid_it->second, is_binary,
                                        std::move(payload));
  }
}

void SctpDataChannelManager::HandleForwardTsnChunk(
    ArrayView<const uint8_t> chunk_body) {
  if (chunk_body.size() < 4) {
    return;
  }
  const uint32_t new_cum_tsn = ReadBigEndian32(chunk_body.data());
  if (!has_peer_initial_tsn_ || IsTsnBefore(peer_cum_tsn_ack_, new_cum_tsn)) {
    peer_cum_tsn_ack_ = new_cum_tsn;
    has_peer_initial_tsn_ = true;
  }

  for (auto it = rx_seen_tsns_.begin(); it != rx_seen_tsns_.end();) {
    if (IsTsnBeforeOrEqual(*it, peer_cum_tsn_ack_)) {
      it = rx_seen_tsns_.erase(it);
    } else {
      break;
    }
  }
  while (true) {
    const auto next_it = rx_seen_tsns_.find(peer_cum_tsn_ack_ + 1);
    if (next_it == rx_seen_tsns_.end()) {
      break;
    }
    peer_cum_tsn_ack_ = *next_it;
    rx_seen_tsns_.erase(next_it);
  }
  for (auto it = rx_fragments_.begin(); it != rx_fragments_.end();) {
    if (IsTsnBeforeOrEqual(it->first, peer_cum_tsn_ack_)) {
      it = rx_fragments_.erase(it);
    } else {
      break;
    }
  }

  // RFC 3758 第 3.6 节：推进被跳过的有序流 SSN 并立即投递后续已就绪消息。
  for (size_t off = 4; off + 4 <= chunk_body.size(); off += 4) {
    const uint16_t sid = ReadBigEndian16(chunk_body.data() + off);
    const uint16_t skipped_ssn = ReadBigEndian16(chunk_body.data() + off + 2);
    auto& expected = next_expected_ssn_[sid];
    if (IsSsnBeforeOrEqual(expected, skipped_ssn)) {
      expected = static_cast<uint16_t>(skipped_ssn + 1);
    }
    DrainOrderedStream(sid);
  }
  sack_needed_ = true;
}

void SctpDataChannelManager::HandleReconfigChunk(
    ArrayView<const uint8_t> chunk_body) {
  size_t off = 0;
  while (off + 4 <= chunk_body.size()) {
    const uint16_t ptype = ReadBigEndian16(chunk_body.data() + off);
    const uint16_t plen = ReadBigEndian16(chunk_body.data() + off + 2);
    if (plen < 4 || off + plen > chunk_body.size()) {
      break;
    }
    if (ptype == kParamOutgoingSsnResetReq && plen >= 16) {
      const uint32_t req_seq = ReadBigEndian32(chunk_body.data() + off + 4);
      for (size_t s_off = off + 16; s_off + 2 <= off + plen; s_off += 2) {
        const uint16_t sid = ReadBigEndian16(chunk_body.data() + s_off);
        ordered_ready_.erase(sid);
        next_expected_ssn_.erase(sid);
        early_rx_messages_.erase(sid);
        const auto cid_it = sid_to_channel_id_.find(sid);
        if (cid_it != sid_to_channel_id_.end()) {
          const int cid = cid_it->second;
          const auto ch_it = channels_.find(cid);
          std::string label;
          if (ch_it != channels_.end()) {
            label = ch_it->second.config.label;
            channels_.erase(ch_it);
          }
          sid_to_channel_id_.erase(cid_it);
          if (observer_ != nullptr) {
            observer_->OnSctpDataChannelState(cid, label,
                                              RTC_DATA_CHANNEL_CLOSED);
          }
        }
      }

      // 回复 RFC 6525 Re-configuration Response (0x0010, Result = 1 Success)。
      std::vector<uint8_t> resp;
      AppendChunkHeader(kChunkReconfig, 0, 16, &resp);
      uint8_t body[12]{};
      WriteBigEndian16(body, kParamReconfigResponse);
      WriteBigEndian16(body + 2, 12);
      WriteBigEndian32(body + 4, req_seq);
      WriteBigEndian32(body + 8, 1);
      resp.insert(resp.end(), body, body + sizeof(body));
      SendChunksPacket(peer_vtag_, resp);
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
    uint32_t range_start = *rx_seen_tsns_.begin();
    uint32_t range_end = range_start;
    for (auto it = std::next(rx_seen_tsns_.begin()); it != rx_seen_tsns_.end();
         ++it) {
      if (*it == range_end + 1) {
        range_end = *it;
      } else {
        const uint32_t s_off = range_start - peer_cum_tsn_ack_;
        const uint32_t e_off = range_end - peer_cum_tsn_ack_;
        if (s_off <= 65535u && e_off <= 65535u && gaps.size() < 32) {
          gaps.emplace_back(static_cast<uint16_t>(s_off),
                            static_cast<uint16_t>(e_off));
        }
        range_start = *it;
        range_end = *it;
      }
    }
    const uint32_t s_off = range_start - peer_cum_tsn_ack_;
    const uint32_t e_off = range_end - peer_cum_tsn_ack_;
    if (s_off <= 65535u && e_off <= 65535u && gaps.size() < 32) {
      gaps.emplace_back(static_cast<uint16_t>(s_off),
                        static_cast<uint16_t>(e_off));
    }
  }

  std::vector<uint8_t> sack;
  const uint16_t len = static_cast<uint16_t>(16 + gaps.size() * 4);
  AppendChunkHeader(kChunkSack, 0, len, &sack);
  uint8_t fixed[12]{};
  WriteBigEndian32(fixed, peer_cum_tsn_ack_);
  WriteBigEndian32(fixed + 4, kDefaultAdvertisedRwnd);
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
  if (chunk_body.size() < 12) {
    return;
  }
  const uint32_t cum_ack = ReadBigEndian32(chunk_body.data());
  const uint16_t num_gaps = ReadBigEndian16(chunk_body.data() + 8);
  if (12u + static_cast<size_t>(num_gaps) * 4u > chunk_body.size()) {
    return;
  }

  size_t newly_acked_bytes = 0;
  if (IsTsnBefore(last_acked_tx_tsn_, cum_ack)) {
    last_acked_tx_tsn_ = cum_ack;
    if (IsTsnBefore(advanced_peer_ack_point_, cum_ack)) {
      advanced_peer_ack_point_ = cum_ack;
    }
  }

  std::vector<std::pair<uint32_t, uint32_t>> gap_ranges;
  gap_ranges.reserve(num_gaps);
  for (uint16_t i = 0; i < num_gaps; ++i) {
    const uint16_t s_off = ReadBigEndian16(chunk_body.data() + 12 + i * 4);
    const uint16_t e_off = ReadBigEndian16(chunk_body.data() + 14 + i * 4);
    if (s_off > 0 && e_off >= s_off) {
      gap_ranges.emplace_back(cum_ack + s_off, cum_ack + e_off);
    }
  }

  uint32_t highest_sacked_tsn = cum_ack;
  if (!gap_ranges.empty()) {
    highest_sacked_tsn = gap_ranges.back().second;
  }

  auto in_any_gap = [&gap_ranges](uint32_t tsn) {
    for (const auto& [gs, ge] : gap_ranges) {
      if (IsTsnBeforeOrEqual(gs, tsn) && IsTsnBeforeOrEqual(tsn, ge)) {
        return true;
      }
    }
    return false;
  };

  bool fast_rtx_triggered = false;
  for (auto it = outbound_chunks_.begin(); it != outbound_chunks_.end();) {
    const uint32_t tsn = it->first;
    OutboundDataChunk& ch = it->second;
    const bool acked_now = IsTsnBeforeOrEqual(tsn, cum_ack) || in_any_gap(tsn);
    if (acked_now && !ch.acked) {
      ch.acked = true;
      ch.needs_retransmit = false;
      const size_t sz = 16 + ch.payload.size();
      newly_acked_bytes += sz;
      if (ch.in_flight) {
        flight_bytes_ = (flight_bytes_ >= sz) ? (flight_bytes_ - sz) : 0;
        ch.in_flight = false;
      }
      if (ch.tx_count == 1 && ch.last_sent_at.IsFinite()) {
        const int64_t rtt = std::max<int64_t>(1000, (now - ch.last_sent_at).us());
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
               IsTsnBefore(tsn, highest_sacked_tsn)) {
      // RFC 4960 第 7.2.4 节：累计 3 次 Gap Ack 缺失报告触发快速重传。
      ++ch.gap_reports;
      if (ch.gap_reports >= 3 && !ch.needs_retransmit) {
        ch.needs_retransmit = true;
        ch.gap_reports = 0;
        if (ch.in_flight) {
          const size_t sz = 16 + ch.payload.size();
          flight_bytes_ = (flight_bytes_ >= sz) ? (flight_bytes_ - sz) : 0;
          ch.in_flight = false;
        }
        fast_rtx_triggered = true;
      }
    }

    if (IsTsnBeforeOrEqual(tsn, last_acked_tx_tsn_)) {
      if (tsn == advanced_peer_ack_point_ + 1) {
        advanced_peer_ack_point_ = tsn;
      }
      it = outbound_chunks_.erase(it);
    } else {
      ++it;
    }
  }

  if (fast_rtx_triggered) {
    ssthresh_bytes_ = std::max<size_t>(cwnd_bytes_ / 2, 4 * 1200);
    cwnd_bytes_ = ssthresh_bytes_;
  } else if (newly_acked_bytes > 0) {
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

  if (flight_bytes_ == 0) {
    t3_rtx_deadline_ = Timestamp::PlusInfinity();
  } else if (newly_acked_bytes > 0) {
    t3_rtx_deadline_ = now + TimeDelta::Micros(rto_us_);
  }

  FlushTransmitQueue(now);
}

void SctpDataChannelManager::OnPeriodicTick(Timestamp now) {
  if (!started_) {
    return;
  }

  // 1. 驱动 SCTP 四次握手重传（以及被动端超时兜底主动握手）。
  if (assoc_state_ != AssocState::kEstablished) {
    if (assoc_state_ == AssocState::kClosed &&
        handshake_started_at_.IsFinite() &&
        (now - handshake_started_at_) >= TimeDelta::Millis(200)) {
      assoc_state_ = AssocState::kCookieWait;
      SendInitChunk(now);
      return;
    }
    const int64_t backoff_ms =
        std::min<int64_t>(1000, 100LL << std::min<uint32_t>(handshake_rtx_count_, 4));
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

  // 4. 驱动 T3-rtx 超时重传定时器。
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
    if (marked_any) {
      ssthresh_bytes_ = std::max<size_t>(cwnd_bytes_ / 2, 4 * 1200);
      cwnd_bytes_ = 2 * 1200;
      rto_us_ = std::min<int64_t>(rto_us_ * 2, 2'000'000);
      t3_rtx_deadline_ = now + TimeDelta::Micros(rto_us_);
      CheckAbandonedAndSendForwardTsn(now);
      FlushTransmitQueue(now);
    } else {
      t3_rtx_deadline_ = Timestamp::PlusInfinity();
    }
  }
}

}  // namespace rtc
