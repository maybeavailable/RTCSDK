#include "modules/rtp_rtcp/rtcp_packets.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>

#include "modules/rtp_rtcp/byte_io.h"
#include "rtc_base/seq_num_unwrapper.h"

namespace rtc {

namespace {
constexpr int64_t kTwccDeltaScaleUs = 250;
constexpr int64_t kTwccBaseScaleUs = 64'000;

void WriteRtcpHeader(uint8_t* dst,
                     uint8_t fmt_or_count,
                     uint8_t pt,
                     size_t total_bytes) {
  dst[0] = static_cast<uint8_t>(0x80 | (fmt_or_count & 0x1F));
  dst[1] = pt;
  WriteBigEndian16(dst + 2, static_cast<uint16_t>((total_bytes / 4) - 1));
}

void WriteReportBlock(uint8_t* dst, const RtcpReportBlock& rb) {
  WriteBigEndian32(dst, rb.source_ssrc);
  dst[4] = rb.fraction_lost;
  const int32_t clamped_lost =
      std::clamp(rb.cumulative_lost, -0x800000, 0x7FFFFF);
  WriteBigEndian24(dst + 5, static_cast<uint32_t>(clamped_lost) & 0xFFFFFFu);
  WriteBigEndian32(dst + 8, rb.extended_high_seq_num);
  WriteBigEndian32(dst + 12, rb.jitter);
  WriteBigEndian32(dst + 16, rb.last_sr);
  WriteBigEndian32(dst + 20, rb.delay_since_last_sr);
}

RtcpReportBlock ReadReportBlock(const uint8_t* src) {
  RtcpReportBlock rb;
  rb.source_ssrc = ReadBigEndian32(src);
  rb.fraction_lost = src[4];
  uint32_t raw24 = ReadBigEndian24(src + 5);
  if ((raw24 & 0x800000u) != 0) {
    raw24 |= 0xFF000000u;
  }
  rb.cumulative_lost = static_cast<int32_t>(raw24);
  rb.extended_high_seq_num = ReadBigEndian32(src + 8);
  rb.jitter = ReadBigEndian32(src + 12);
  rb.last_sr = ReadBigEndian32(src + 16);
  rb.delay_since_last_sr = ReadBigEndian32(src + 20);
  return rb;
}
}  // namespace

// ======================= SR / RR 发送端与接收端报告 =======================

std::vector<uint8_t> RtcpSenderReport::Build() const {
  const size_t rc = std::min<size_t>(report_blocks.size(), 31);
  const size_t total = 4 + 24 + rc * 24;
  std::vector<uint8_t> out(total, 0);
  WriteRtcpHeader(out.data(), static_cast<uint8_t>(rc),
                  rtcp_type::kSenderReport, total);
  WriteBigEndian32(out.data() + 4, sender_ssrc);
  WriteBigEndian32(out.data() + 8, ntp_seconds);
  WriteBigEndian32(out.data() + 12, ntp_fractions);
  WriteBigEndian32(out.data() + 16, rtp_timestamp);
  WriteBigEndian32(out.data() + 20, sender_packet_count);
  WriteBigEndian32(out.data() + 24, sender_octet_count);
  for (size_t i = 0; i < rc; ++i) {
    WriteReportBlock(out.data() + 28 + i * 24, report_blocks[i]);
  }
  return out;
}

std::optional<RtcpSenderReport> RtcpSenderReport::Parse(
    ArrayView<const uint8_t> payload,
    uint8_t report_count) {
  if (payload.size() < 24 + static_cast<size_t>(report_count) * 24) {
    return std::nullopt;
  }
  const uint8_t* raw = payload.data();
  RtcpSenderReport sr;
  sr.sender_ssrc = ReadBigEndian32(raw);
  sr.ntp_seconds = ReadBigEndian32(raw + 4);
  sr.ntp_fractions = ReadBigEndian32(raw + 8);
  sr.rtp_timestamp = ReadBigEndian32(raw + 12);
  sr.sender_packet_count = ReadBigEndian32(raw + 16);
  sr.sender_octet_count = ReadBigEndian32(raw + 20);
  for (uint8_t i = 0; i < report_count; ++i) {
    sr.report_blocks.push_back(ReadReportBlock(raw + 24 + i * 24));
  }
  return sr;
}

std::vector<uint8_t> RtcpReceiverReport::Build() const {
  const size_t rc = std::min<size_t>(report_blocks.size(), 31);
  const size_t total = 4 + 4 + rc * 24;
  std::vector<uint8_t> out(total, 0);
  WriteRtcpHeader(out.data(), static_cast<uint8_t>(rc),
                  rtcp_type::kReceiverReport, total);
  WriteBigEndian32(out.data() + 4, sender_ssrc);
  for (size_t i = 0; i < rc; ++i) {
    WriteReportBlock(out.data() + 8 + i * 24, report_blocks[i]);
  }
  return out;
}

std::optional<RtcpReceiverReport> RtcpReceiverReport::Parse(
    ArrayView<const uint8_t> payload,
    uint8_t report_count) {
  if (payload.size() < 4 + static_cast<size_t>(report_count) * 24) {
    return std::nullopt;
  }
  const uint8_t* raw = payload.data();
  RtcpReceiverReport rr;
  rr.sender_ssrc = ReadBigEndian32(raw);
  for (uint8_t i = 0; i < report_count; ++i) {
    rr.report_blocks.push_back(ReadReportBlock(raw + 4 + i * 24));
  }
  return rr;
}

// ======================= 通用 NACK 丢包重传请求（RFC 4585） =======================

std::vector<uint8_t> RtcpNack::Build() const {
  if (packet_ids.empty()) {
    return {};
  }

  std::vector<uint16_t> sorted = packet_ids;
  const uint16_t anchor = sorted.front();
  std::sort(sorted.begin(), sorted.end(), [anchor](uint16_t a, uint16_t b) {
    return static_cast<uint16_t>(a - anchor) <
           static_cast<uint16_t>(b - anchor);
  });
  sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

  struct FciItem {
    uint16_t pid;
    uint16_t blp;
  };
  std::vector<FciItem> fcis;
  size_t idx = 0;
  while (idx < sorted.size()) {
    const uint16_t pid = sorted[idx];
    uint16_t blp = 0;
    ++idx;
    while (idx < sorted.size()) {
      const uint16_t diff = static_cast<uint16_t>(sorted[idx] - pid);
      if (diff >= 1 && diff <= 16) {
        blp |= static_cast<uint16_t>(1u << (diff - 1));
        ++idx;
      } else {
        break;
      }
    }
    fcis.push_back(FciItem{pid, blp});
  }

  const size_t total = 12 + fcis.size() * 4;
  std::vector<uint8_t> out(total, 0);
  WriteRtcpHeader(out.data(), 1, rtcp_type::kRtpfb, total);
  WriteBigEndian32(out.data() + 4, sender_ssrc);
  WriteBigEndian32(out.data() + 8, media_ssrc);
  for (size_t i = 0; i < fcis.size(); ++i) {
    WriteBigEndian16(out.data() + 12 + i * 4, fcis[i].pid);
    WriteBigEndian16(out.data() + 14 + i * 4, fcis[i].blp);
  }
  return out;
}

std::optional<RtcpNack> RtcpNack::Parse(ArrayView<const uint8_t> payload) {
  if (payload.size() < 12 || ((payload.size() - 8) % 4) != 0) {
    return std::nullopt;
  }
  const uint8_t* raw = payload.data();
  RtcpNack nack;
  nack.sender_ssrc = ReadBigEndian32(raw);
  nack.media_ssrc = ReadBigEndian32(raw + 4);
  for (size_t off = 8; off + 4 <= payload.size(); off += 4) {
    const uint16_t pid = ReadBigEndian16(raw + off);
    const uint16_t blp = ReadBigEndian16(raw + off + 2);
    nack.packet_ids.push_back(pid);
    for (uint16_t bit = 0; bit < 16; ++bit) {
      if ((blp & (1u << bit)) != 0) {
        nack.packet_ids.push_back(static_cast<uint16_t>(pid + bit + 1));
      }
    }
  }
  return nack;
}

// ======================= PLI / FIR 关键帧请求 =======================

std::vector<uint8_t> RtcpPli::Build() const {
  std::vector<uint8_t> out(12, 0);
  WriteRtcpHeader(out.data(), 1, rtcp_type::kPsfb, 12);
  WriteBigEndian32(out.data() + 4, sender_ssrc);
  WriteBigEndian32(out.data() + 8, media_ssrc);
  return out;
}

std::optional<RtcpPli> RtcpPli::Parse(ArrayView<const uint8_t> payload) {
  if (payload.size() < 8) {
    return std::nullopt;
  }
  RtcpPli pli;
  pli.sender_ssrc = ReadBigEndian32(payload.data());
  pli.media_ssrc = ReadBigEndian32(payload.data() + 4);
  return pli;
}

std::vector<uint8_t> RtcpFir::Build() const {
  std::vector<uint8_t> out(20, 0);
  WriteRtcpHeader(out.data(), 4, rtcp_type::kPsfb, 20);
  WriteBigEndian32(out.data() + 4, sender_ssrc);
  WriteBigEndian32(out.data() + 8, 0);
  WriteBigEndian32(out.data() + 12, media_ssrc);
  out[16] = command_seq_num;
  return out;
}

std::optional<RtcpFir> RtcpFir::Parse(ArrayView<const uint8_t> payload) {
  if (payload.size() < 16) {
    return std::nullopt;
  }
  RtcpFir fir;
  fir.sender_ssrc = ReadBigEndian32(payload.data());
  fir.media_ssrc = ReadBigEndian32(payload.data() + 8);
  fir.command_seq_num = payload[12];
  return fir;
}

// ======================= TWCC TransportFeedback 传输层反馈（FMT=15） =======================

void RtcpTransportFeedback::SetBase(uint16_t base_sequence,
                                    Timestamp ref_timestamp) {
  base_seq_no_ = base_sequence;
  full_base_ticks_ = ref_timestamp.us() / kTwccBaseScaleUs;
  uint32_t raw_ref = static_cast<uint32_t>(full_base_ticks_) & 0xFFFFFFu;
  if ((raw_ref & 0x800000u) != 0) {
    raw_ref |= 0xFF000000u;
  }
  base_time_ticks_ = static_cast<int32_t>(raw_ref);
  has_base_ = true;
  num_seq_no_ = 0;
  received_packets_.clear();
}

Timestamp RtcpTransportFeedback::BaseTime() const {
  return Timestamp::Micros(static_cast<int64_t>(base_time_ticks_) *
                           kTwccBaseScaleUs);
}

bool RtcpTransportFeedback::AddReceivedPacket(uint16_t sequence_number,
                                              Timestamp timestamp) {
  if (!has_base_) {
    SetBase(sequence_number, timestamp);
  }
  const uint16_t offset = static_cast<uint16_t>(sequence_number - base_seq_no_);
  if (offset >= 8192) {
    return false;
  }
  const int64_t quantized_us =
      (timestamp.us() / kTwccDeltaScaleUs) * kTwccDeltaScaleUs;
  received_packets_.push_back(
      ReceivedPacket{sequence_number, Timestamp::Micros(quantized_us)});
  num_seq_no_ = std::max<uint16_t>(num_seq_no_, static_cast<uint16_t>(offset + 1));
  return true;
}

std::vector<RtcpTransportFeedback::PacketStatus>
RtcpTransportFeedback::AllPacketStatuses() const {
  std::map<uint16_t, Timestamp> rx_map;
  for (const auto& p : received_packets_) {
    rx_map[p.sequence_number] = p.receive_time;
  }
  std::vector<PacketStatus> out;
  out.reserve(num_seq_no_);
  for (uint16_t i = 0; i < num_seq_no_; ++i) {
    const uint16_t seq = static_cast<uint16_t>(base_seq_no_ + i);
    const auto it = rx_map.find(seq);
    if (it != rx_map.end()) {
      out.push_back(PacketStatus{seq, it->second});
    } else {
      out.push_back(PacketStatus{seq, Timestamp::PlusInfinity()});
    }
  }
  return out;
}

std::vector<uint8_t> RtcpTransportFeedback::Build() const {
  if (!has_base_ || num_seq_no_ == 0) {
    return {};
  }

  std::map<uint16_t, Timestamp> rx_map;
  for (const auto& p : received_packets_) {
    rx_map[p.sequence_number] = p.receive_time;
  }

  std::vector<uint8_t> symbols;
  symbols.reserve(num_seq_no_);
  std::vector<uint8_t> deltas;
  deltas.reserve(received_packets_.size() * 2);

  // 使用未截断的 64 位基准刻度计算相邻包到达增量，避免主机运行超过 6.21 天时发生 24 位回绕溢出。
  int64_t prev_ticks =
      full_base_ticks_ * (kTwccBaseScaleUs / kTwccDeltaScaleUs);

  for (uint16_t i = 0; i < num_seq_no_; ++i) {
    const uint16_t seq = static_cast<uint16_t>(base_seq_no_ + i);
    const auto it = rx_map.find(seq);
    if (it == rx_map.end()) {
      symbols.push_back(0);
    } else {
      const int64_t cur_ticks = it->second.us() / kTwccDeltaScaleUs;
      const int64_t delta_ticks =
          std::clamp<int64_t>(cur_ticks - prev_ticks, -32768, 32767);
      prev_ticks += delta_ticks;

      if (delta_ticks >= 0 && delta_ticks <= 255) {
        symbols.push_back(1);
        deltas.push_back(static_cast<uint8_t>(delta_ticks));
      } else {
        symbols.push_back(2);
        uint8_t b[2];
        WriteBigEndian16(
            b, static_cast<uint16_t>(static_cast<int16_t>(delta_ticks)));
        deltas.push_back(b[0]);
        deltas.push_back(b[1]);
      }
    }
  }

  std::vector<uint16_t> chunks;
  for (size_t idx = 0; idx < symbols.size(); idx += 7) {
    uint16_t chunk = 0xC000u;
    for (size_t k = 0; k < 7 && (idx + k) < symbols.size(); ++k) {
      chunk |= static_cast<uint16_t>((symbols[idx + k] & 0x03u) << (12 - k * 2));
    }
    chunks.push_back(chunk);
  }

  const size_t unpadded = 20 + chunks.size() * 2 + deltas.size();
  const size_t total = (unpadded + 3) & ~size_t{3};
  const size_t pad_bytes = total - unpadded;

  std::vector<uint8_t> out(total, 0);
  WriteRtcpHeader(out.data(), 15, rtcp_type::kRtpfb, total);
  if (pad_bytes > 0) {
    out[0] |= 0x20;
    out[total - 1] = static_cast<uint8_t>(pad_bytes);
  }
  WriteBigEndian32(out.data() + 4, sender_ssrc);
  WriteBigEndian32(out.data() + 8, media_ssrc);
  WriteBigEndian16(out.data() + 12, base_seq_no_);
  WriteBigEndian16(out.data() + 14, num_seq_no_);
  WriteBigEndian24(out.data() + 16,
                   static_cast<uint32_t>(base_time_ticks_) & 0xFFFFFFu);
  out[19] = feedback_seq;

  size_t offset = 20;
  for (uint16_t c : chunks) {
    WriteBigEndian16(out.data() + offset, c);
    offset += 2;
  }
  if (!deltas.empty()) {
    std::memcpy(out.data() + offset, deltas.data(), deltas.size());
  }
  return out;
}

std::optional<RtcpTransportFeedback> RtcpTransportFeedback::Parse(
    ArrayView<const uint8_t> payload) {
  if (payload.size() < 16) {
    return std::nullopt;
  }
  const uint8_t* raw = payload.data();
  const size_t len = payload.size();

  RtcpTransportFeedback fb;
  fb.sender_ssrc = ReadBigEndian32(raw);
  fb.media_ssrc = ReadBigEndian32(raw + 4);
  fb.base_seq_no_ = ReadBigEndian16(raw + 8);
  fb.num_seq_no_ = ReadBigEndian16(raw + 10);

  uint32_t raw_ref = ReadBigEndian24(raw + 12);
  if ((raw_ref & 0x800000u) != 0) {
    raw_ref |= 0xFF000000u;
  }
  fb.base_time_ticks_ = static_cast<int32_t>(raw_ref);
  fb.full_base_ticks_ = fb.base_time_ticks_;
  fb.feedback_seq = raw[15];
  fb.has_base_ = true;

  std::vector<uint8_t> symbols;
  symbols.reserve(fb.num_seq_no_);
  size_t offset = 16;

  while (symbols.size() < fb.num_seq_no_) {
    if (offset + 2 > len) {
      return std::nullopt;
    }
    const uint16_t chunk = ReadBigEndian16(raw + offset);
    offset += 2;

    if ((chunk & 0x8000u) == 0) {
      const uint8_t sym = static_cast<uint8_t>((chunk >> 13) & 0x03u);
      const size_t run_len =
          std::min<size_t>(chunk & 0x1FFFu, fb.num_seq_no_ - symbols.size());
      if (run_len == 0) {
        return std::nullopt;
      }
      symbols.insert(symbols.end(), run_len, sym);
    } else if ((chunk & 0x4000u) == 0) {
      const size_t count =
          std::min<size_t>(14, fb.num_seq_no_ - symbols.size());
      for (size_t k = 0; k < count; ++k) {
        const uint8_t sym = (chunk >> (13 - k)) & 0x01u;
        symbols.push_back(sym);
      }
    } else {
      const size_t count = std::min<size_t>(7, fb.num_seq_no_ - symbols.size());
      for (size_t k = 0; k < count; ++k) {
        const uint8_t sym =
            static_cast<uint8_t>((chunk >> (12 - k * 2)) & 0x03u);
        symbols.push_back(sym);
      }
    }
  }

  int64_t cur_ticks = static_cast<int64_t>(fb.base_time_ticks_) *
                      (kTwccBaseScaleUs / kTwccDeltaScaleUs);

  for (uint16_t i = 0; i < fb.num_seq_no_; ++i) {
    const uint8_t sym = symbols[i];
    const uint16_t seq = static_cast<uint16_t>(fb.base_seq_no_ + i);
    if (sym == 0) {
      continue;
    } else if (sym == 1) {
      if (offset + 1 > len) {
        return std::nullopt;
      }
      cur_ticks += raw[offset];
      offset += 1;
      fb.received_packets_.push_back(
          ReceivedPacket{seq, Timestamp::Micros(cur_ticks * kTwccDeltaScaleUs)});
    } else if (sym == 2) {
      if (offset + 2 > len) {
        return std::nullopt;
      }
      const int16_t delta = ReadBigEndianSigned16(raw + offset);
      offset += 2;
      cur_ticks += delta;
      fb.received_packets_.push_back(
          ReceivedPacket{seq, Timestamp::Micros(cur_ticks * kTwccDeltaScaleUs)});
    }
  }
  return fb;
}

// ======================= 复合 RTCP 报文解析器 =======================

ParsedCompoundRtcp ParseCompoundRtcp(ArrayView<const uint8_t> data) {
  ParsedCompoundRtcp res;
  const uint8_t* raw = data.data();
  const size_t len = data.size();
  size_t offset = 0;

  while (offset + 4 <= len) {
    const uint8_t b0 = raw[offset];
    const uint8_t version = (b0 >> 6) & 0x03;
    if (version != 2) {
      break;
    }

    const bool has_padding = (b0 & 0x20) != 0;
    const uint8_t fmt_or_rc = b0 & 0x1F;
    const uint8_t pt = raw[offset + 1];
    const size_t pkt_bytes =
        (static_cast<size_t>(ReadBigEndian16(raw + offset + 2)) + 1) * 4;
    if (offset + pkt_bytes > len) {
      break;
    }

    size_t payload_len = pkt_bytes - 4;
    if (has_padding && payload_len > 0) {
      const uint8_t pad = raw[offset + pkt_bytes - 1];
      if (pad <= payload_len) {
        payload_len -= pad;
      }
    }
    const ArrayView<const uint8_t> body(raw + offset + 4, payload_len);

    switch (pt) {
      case rtcp_type::kSenderReport:
        if (auto sr = RtcpSenderReport::Parse(body, fmt_or_rc)) {
          res.sender_reports.push_back(std::move(*sr));
        }
        break;
      case rtcp_type::kReceiverReport:
        if (auto rr = RtcpReceiverReport::Parse(body, fmt_or_rc)) {
          res.receiver_reports.push_back(std::move(*rr));
        }
        break;
      case rtcp_type::kRtpfb:
        if (fmt_or_rc == 1) {
          if (auto nack = RtcpNack::Parse(body)) {
            res.nacks.push_back(std::move(*nack));
          }
        } else if (fmt_or_rc == 15) {
          if (auto twcc = RtcpTransportFeedback::Parse(body)) {
            res.transport_feedbacks.push_back(std::move(*twcc));
          }
        }
        break;
      case rtcp_type::kPsfb:
        if (fmt_or_rc == 1) {
          if (auto pli = RtcpPli::Parse(body)) {
            res.plis.push_back(std::move(*pli));
          }
        } else if (fmt_or_rc == 4) {
          if (auto fir = RtcpFir::Parse(body)) {
            res.firs.push_back(std::move(*fir));
          }
        }
        break;
      default:
        break;
    }
    offset += pkt_bytes;
  }
  return res;
}

}  // namespace rtc
