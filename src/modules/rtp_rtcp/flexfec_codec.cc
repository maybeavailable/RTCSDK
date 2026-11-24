#include "modules/rtp_rtcp/flexfec_codec.h"

#include <algorithm>
#include <cmath>
#include <cstring>

#include <openssl/rand.h>

#include "modules/rtp_rtcp/byte_io.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {

constexpr size_t kRtpFixedHeaderSize = RtpPacket::kFixedHeaderSize;  // 12 字节
constexpr size_t kFlexfecCommonHeaderSize = 8;
constexpr size_t kFlexfecRetransmitHeaderSize = 12;
constexpr size_t kMaxCachedMediaPackets = 512;
constexpr size_t kMaxPendingFecPackets = 64;
constexpr uint16_t kMaxFlexibleMaskSpan = 110;  // 覆盖偏移 0..109

bool SeqNumLess16(uint16_t a, uint16_t b) {
  return a != b && static_cast<uint16_t>(b - a) < 0x8000u;
}

uint32_t AbsRtpTimestampDiff(uint32_t a, uint32_t b) {
  const uint32_t fwd = a - b;
  const uint32_t bwd = b - a;
  return std::min(fwd, bwd);
}

uint16_t GenerateRandomInitialSeq() {
  uint8_t rnd[2] = {0x13, 0x57};
  (void)RAND_bytes(rnd, sizeof(rnd));
  return ReadBigEndian16(rnd);
}

// 计算 RFC 8627 第 6.2 节保护源包集合的异或头部字段与去头后（跳过前 12 字节）Repair Payload。
bool ComputeXorParityFields(const std::vector<const RtpPacket*>& group,
                            uint8_t* out_hdr0_xor,
                            uint8_t* out_hdr1_xor,
                            uint16_t* out_len_recovery,
                            uint32_t* out_ts_recovery,
                            std::vector<uint8_t>* out_repair_payload) {
  if (group.empty()) {
    return false;
  }

  std::vector<std::vector<uint8_t>> wires;
  wires.reserve(group.size());
  size_t max_post_hdr_len = 0;

  for (const RtpPacket* pkt : group) {
    if (pkt == nullptr) {
      return false;
    }
    std::vector<uint8_t> w = pkt->WireBytes();
    if (w.size() < kRtpFixedHeaderSize) {
      return false;
    }
    max_post_hdr_len = std::max(max_post_hdr_len, w.size() - kRtpFixedHeaderSize);
    wires.push_back(std::move(w));
  }

  uint8_t hdr0_xor = 0;
  uint8_t hdr1_xor = 0;
  uint16_t len_recovery = 0;
  uint32_t ts_recovery = 0;
  std::vector<uint8_t> repair_payload(max_post_hdr_len, 0);

  for (const auto& w : wires) {
    hdr0_xor ^= static_cast<uint8_t>(w[0] & 0x3Fu);
    hdr1_xor ^= w[1];
    const size_t post_hdr_len = w.size() - kRtpFixedHeaderSize;
    len_recovery ^= static_cast<uint16_t>(post_hdr_len);
    ts_recovery ^= ReadBigEndian32(w.data() + 4);
    for (size_t b = 0; b < post_hdr_len; ++b) {
      repair_payload[b] ^= w[kRtpFixedHeaderSize + b];
    }
  }

  *out_hdr0_xor = hdr0_xor;
  *out_hdr1_xor = hdr1_xor;
  *out_len_recovery = len_recovery;
  *out_ts_recovery = ts_recovery;
  *out_repair_payload = std::move(repair_payload);
  return true;
}

}  // namespace

void FecControllerDefault::UpdateNetworkMetrics(DataRate estimated_bitrate,
                                                TimeDelta rtt,
                                                double loss_rate_ratio) {
  loss_rate_ratio = std::clamp(loss_rate_ratio, 0.0, 0.5);
  if ((estimated_bitrate < DataRate::KilobitsPerSec(110) &&
       loss_rate_ratio < 0.12) ||
      (loss_rate_ratio < 0.02 && rtt < TimeDelta::Millis(70))) {
    keyframe_params_ = FecProtectionParams{25, 1, false, false};
    delta_params_ = FecProtectionParams{0, 1, false, false};
    return;
  }

  const double rtt_factor = (rtt >= TimeDelta::Millis(80)) ? 1.35 : 1.0;
  const double delta_ratio =
      std::clamp(loss_rate_ratio * 1.4 * rtt_factor, 0.05, 0.40);
  const double key_ratio = std::clamp(delta_ratio * 1.35 + 0.08, 0.12, 0.50);

  delta_params_.fec_rate =
      static_cast<uint8_t>(std::lround(delta_ratio * 255.0));
  delta_params_.max_fec_frames = 1;
  delta_params_.use_burst_interleaving = (loss_rate_ratio >= 0.08);
  delta_params_.use_fixed_matrix_f1 = false;

  keyframe_params_.fec_rate =
      static_cast<uint8_t>(std::lround(key_ratio * 255.0));
  keyframe_params_.max_fec_frames = 1;
  keyframe_params_.use_burst_interleaving = (loss_rate_ratio >= 0.08);
  keyframe_params_.use_fixed_matrix_f1 = false;
}

FlexfecSender::FlexfecSender(uint8_t flexfec_payload_type,
                             uint32_t flexfec_ssrc,
                             uint32_t protected_media_ssrc,
                             std::string mid,
                             uint32_t repair_window_us)
    : flexfec_pt_(flexfec_payload_type),
      flexfec_ssrc_(flexfec_ssrc),
      protected_media_ssrc_(protected_media_ssrc),
      mid_(std::move(mid)),
      repair_window_us_(repair_window_us > 0 ? repair_window_us : 10'000'000),
      seq_num_(GenerateRandomInitialSeq()) {}

void FlexfecSender::SetProtectionParameters(const FecProtectionParams& params) {
  params_ = params;
}

void FlexfecSender::EvictExpiredPendingMedia(const RtpPacket& newest_packet) {
  if (pending_media_.empty()) {
    return;
  }
  // 清理超出 110 位掩码跨度或超出协商 repair-window 的陈旧待保护包。
  const uint16_t newest_seq = newest_packet.sequence_number();
  const uint64_t max_ts_span_90k =
      (static_cast<uint64_t>(repair_window_us_) * 90ULL) / 1000ULL;

  auto it = pending_media_.begin();
  while (it != pending_media_.end()) {
    const uint16_t seq = it->sequence_number();
    const bool invalid_order = !SeqNumLess16(seq, newest_seq);
    const uint16_t seq_span = static_cast<uint16_t>(newest_seq - seq);
    const uint32_t ts_span =
        AbsRtpTimestampDiff(newest_packet.timestamp(), it->timestamp());
    if (invalid_order || seq_span >= kMaxFlexibleMaskSpan ||
        ts_span > max_ts_span_90k) {
      it = pending_media_.erase(it);
    } else {
      ++it;
    }
  }
}

void FlexfecSender::AddRtpPacketAndGenerateFec(const RtpPacket& media_packet) {
  if (media_packet.ssrc() != protected_media_ssrc_) {
    return;
  }
  // 忽略乱序或重传的旧序列号媒体包，防止冲刷正在累积的前向源包组。
  if (last_added_seq_.has_value() &&
      !SeqNumLess16(*last_added_seq_, media_packet.sequence_number())) {
    return;
  }
  last_added_seq_ = media_packet.sequence_number();

  if (params_.fec_rate == 0) {
    pending_media_.clear();
    return;
  }

  EvictExpiredPendingMedia(media_packet);
  pending_media_.push_back(media_packet);

  const size_t group_size =
      std::clamp<size_t>((255 + params_.fec_rate / 2) / params_.fec_rate, 2, 12);

  auto emit_group = [this](const std::vector<const RtpPacket*>& grp,
                           uint8_t fixed_l, uint8_t fixed_d) {
    if (grp.empty()) {
      return;
    }
    std::optional<RtpPacket> fec_pkt;
    if (params_.use_fixed_matrix_f1 && fixed_l > 0) {
      fec_pkt = BuildFixedMatrixParityPacket(
          grp, grp.front()->sequence_number(), fixed_l, fixed_d);
    } else {
      fec_pkt = BuildFlexibleMaskParityPacket(grp);
    }
    if (fec_pkt.has_value()) {
      ready_fec_packets_.push_back(std::move(*fec_pkt));
    }
  };

  if (params_.use_burst_interleaving &&
      pending_media_.size() >= group_size * 2) {
    std::vector<const RtpPacket*> even_group;
    std::vector<const RtpPacket*> odd_group;
    even_group.reserve(group_size);
    odd_group.reserve(group_size);
    bool contiguous_2x = true;
    const uint16_t first_seq = pending_media_.front().sequence_number();
    for (size_t i = 0; i < group_size * 2; ++i) {
      if (pending_media_[i].sequence_number() !=
          static_cast<uint16_t>(first_seq + i)) {
        contiguous_2x = false;
      }
      if ((i % 2) == 0) {
        even_group.push_back(&pending_media_[i]);
      } else {
        odd_group.push_back(&pending_media_[i]);
      }
    }
    const uint8_t l_val =
        contiguous_2x ? 2 : 0;  // L=2, D=group_size 表示每 2 包抽 1 包共 D 行的列纠错
    const uint8_t d_val =
        contiguous_2x ? static_cast<uint8_t>(group_size) : 0;
    emit_group(even_group, l_val, d_val);
    emit_group(odd_group, l_val, d_val);
    pending_media_.erase(
        pending_media_.begin(),
        pending_media_.begin() + static_cast<ptrdiff_t>(group_size * 2));
  } else if (!params_.use_burst_interleaving &&
             pending_media_.size() >= group_size) {
    std::vector<const RtpPacket*> group;
    group.reserve(group_size);
    bool contiguous = true;
    const uint16_t first_seq = pending_media_.front().sequence_number();
    for (size_t i = 0; i < group_size; ++i) {
      if (pending_media_[i].sequence_number() !=
          static_cast<uint16_t>(first_seq + i)) {
        contiguous = false;
      }
      group.push_back(&pending_media_[i]);
    }
    emit_group(group, contiguous ? static_cast<uint8_t>(group_size) : 0, 0);
    pending_media_.erase(
        pending_media_.begin(),
        pending_media_.begin() + static_cast<ptrdiff_t>(group_size));
  } else if (media_packet.marker() && pending_media_.size() >= 2 &&
             params_.fec_rate >= 20) {
    std::vector<const RtpPacket*> group;
    group.reserve(pending_media_.size());
    bool contiguous = true;
    const uint16_t first_seq = pending_media_.front().sequence_number();
    for (size_t i = 0; i < pending_media_.size(); ++i) {
      if (pending_media_[i].sequence_number() !=
          static_cast<uint16_t>(first_seq + i)) {
        contiguous = false;
      }
      group.push_back(&pending_media_[i]);
    }
    emit_group(group,
               contiguous ? static_cast<uint8_t>(pending_media_.size()) : 0, 0);
    pending_media_.clear();
  }
}

std::optional<RtpPacket> FlexfecSender::BuildFlexibleMaskParityPacket(
    const std::vector<const RtpPacket*>& group) {
  if (group.empty()) {
    return std::nullopt;
  }

  std::vector<const RtpPacket*> sorted = group;
  std::sort(sorted.begin(), sorted.end(),
            [](const RtpPacket* a, const RtpPacket* b) {
              return SeqNumLess16(a->sequence_number(), b->sequence_number());
            });
  sorted.erase(std::unique(sorted.begin(), sorted.end(),
                           [](const RtpPacket* a, const RtpPacket* b) {
                             return a->sequence_number() ==
                                    b->sequence_number();
                           }),
               sorted.end());

  const uint16_t base_seq = sorted.front()->sequence_number();
  uint16_t max_offset = 0;
  std::vector<const RtpPacket*> valid_group;
  valid_group.reserve(sorted.size());

  const uint64_t max_ts_span_90k =
      (static_cast<uint64_t>(repair_window_us_) * 90ULL) / 1000ULL;
  for (const RtpPacket* pkt : sorted) {
    const uint16_t offset =
        static_cast<uint16_t>(pkt->sequence_number() - base_seq);
    const uint32_t ts_span =
        AbsRtpTimestampDiff(pkt->timestamp(), sorted.front()->timestamp());
    if (offset >= kMaxFlexibleMaskSpan || ts_span > max_ts_span_90k) {
      // RFC 8627 第 4.2.2 / 5.1.2 节：超出 110 位掩码或 repair-window 的修复包禁止发送。
      return std::nullopt;
    }
    max_offset = std::max(max_offset, offset);
    valid_group.push_back(pkt);
  }

  uint8_t hdr0_xor = 0;
  uint8_t hdr1_xor = 0;
  uint16_t len_recovery = 0;
  uint32_t ts_recovery = 0;
  std::vector<uint8_t> repair_payload;
  if (!ComputeXorParityFields(valid_group, &hdr0_xor, &hdr1_xor, &len_recovery,
                              &ts_recovery, &repair_payload)) {
    return std::nullopt;
  }

  // 组装 RFC 8627 图 12（R=0, F=0）柔性位掩码块（MSB 对应 j=0）：
  //   - 第 0 块（16 位）：[k0 (1b) | Mask[0..14] (15b)]
  //   - 第 1 块（32 位，可选）：[k1 (1b) | Mask[15..45] (31b)]
  //   - 第 2 块（64 位，可选）：[Mask[46..109] (64b)]（无 k-bit）
  uint16_t mask_word0 = 0;
  uint32_t mask_word1 = 0;
  uint64_t mask_word2 = 0;
  const bool need_word1 = (max_offset >= 15);
  const bool need_word2 = (max_offset >= 46);

  for (const RtpPacket* pkt : valid_group) {
    const uint16_t j =
        static_cast<uint16_t>(pkt->sequence_number() - base_seq);
    if (j <= 14) {
      mask_word0 |= static_cast<uint16_t>(uint16_t{1} << (14 - j));
    } else if (j <= 45) {
      mask_word1 |= (uint32_t{1} << (45 - j));
    } else {
      mask_word2 |= (uint64_t{1} << (109 - j));
    }
  }
  if (need_word1) {
    mask_word0 |= 0x8000u;
  }
  if (need_word2) {
    mask_word1 |= 0x80000000u;
  }

  const size_t mask_bytes = 2 + (need_word1 ? 4 : 0) + (need_word2 ? 8 : 0);
  const size_t fec_hdr_size = kFlexfecCommonHeaderSize + 2 + mask_bytes;
  std::vector<uint8_t> fec_payload(fec_hdr_size + repair_payload.size(), 0);

  // R=0, F=0 写入首字节高 2 位。
  fec_payload[0] = static_cast<uint8_t>(hdr0_xor & 0x3Fu);
  fec_payload[1] = hdr1_xor;
  WriteBigEndian16(fec_payload.data() + 2, len_recovery);
  WriteBigEndian32(fec_payload.data() + 4, ts_recovery);
  WriteBigEndian16(fec_payload.data() + 8, base_seq);
  WriteBigEndian16(fec_payload.data() + 10, mask_word0);

  size_t hdr_off = 12;
  if (need_word1) {
    WriteBigEndian32(fec_payload.data() + hdr_off, mask_word1);
    hdr_off += 4;
  }
  if (need_word2) {
    WriteBigEndian64(fec_payload.data() + hdr_off, mask_word2);
    hdr_off += 8;
  }
  if (!repair_payload.empty()) {
    std::memcpy(fec_payload.data() + hdr_off, repair_payload.data(),
                repair_payload.size());
  }

  RtpPacket fec_pkt;
  fec_pkt.set_payload_type(flexfec_pt_);
  fec_pkt.set_ssrc(flexfec_ssrc_);
  // RFC 8627 第 4.2.1 节：Marker 位必须设为 0，且由 RTP 头 CSRC 列表声明受保护源 SSRC。
  fec_pkt.set_marker(false);
  fec_pkt.set_csrcs({protected_media_ssrc_});
  fec_pkt.set_sequence_number(seq_num_++);
  fec_pkt.set_timestamp(valid_group.back()->timestamp());
  if (!mid_.empty()) {
    fec_pkt.SetMid(mid_);
  }
  *fec_pkt.mutable_payload() = std::move(fec_payload);
  return fec_pkt;
}

std::optional<RtpPacket> FlexfecSender::BuildFixedMatrixParityPacket(
    const std::vector<const RtpPacket*>& group,
    uint16_t sn_base,
    uint8_t columns_l,
    uint8_t rows_d) {
  // RFC 8627 图 14：L=0（含 L=0,D=0）属于保留/非法配置，禁止发送。
  if (group.empty() || columns_l == 0) {
    return std::nullopt;
  }

  uint8_t hdr0_xor = 0;
  uint8_t hdr1_xor = 0;
  uint16_t len_recovery = 0;
  uint32_t ts_recovery = 0;
  std::vector<uint8_t> repair_payload;
  if (!ComputeXorParityFields(group, &hdr0_xor, &hdr1_xor, &len_recovery,
                              &ts_recovery, &repair_payload)) {
    return std::nullopt;
  }

  constexpr size_t kFixedF1HeaderSize = kFlexfecCommonHeaderSize + 4;  // 12 字节
  std::vector<uint8_t> fec_payload(kFixedF1HeaderSize + repair_payload.size(),
                                   0);
  // R=0, F=1（0x40）
  fec_payload[0] = static_cast<uint8_t>(0x40u | (hdr0_xor & 0x3Fu));
  fec_payload[1] = hdr1_xor;
  WriteBigEndian16(fec_payload.data() + 2, len_recovery);
  WriteBigEndian32(fec_payload.data() + 4, ts_recovery);
  WriteBigEndian16(fec_payload.data() + 8, sn_base);
  fec_payload[10] = columns_l;
  fec_payload[11] = rows_d;
  if (!repair_payload.empty()) {
    std::memcpy(fec_payload.data() + kFixedF1HeaderSize, repair_payload.data(),
                repair_payload.size());
  }

  RtpPacket fec_pkt;
  fec_pkt.set_payload_type(flexfec_pt_);
  fec_pkt.set_ssrc(flexfec_ssrc_);
  fec_pkt.set_marker(false);
  fec_pkt.set_csrcs({protected_media_ssrc_});
  fec_pkt.set_sequence_number(seq_num_++);
  fec_pkt.set_timestamp(group.back()->timestamp());
  if (!mid_.empty()) {
    fec_pkt.SetMid(mid_);
  }
  *fec_pkt.mutable_payload() = std::move(fec_payload);
  return fec_pkt;
}

std::optional<RtpPacket> FlexfecSender::BuildRetransmissionPacket(
    const RtpPacket& media_packet) {
  if (media_packet.ssrc() != protected_media_ssrc_) {
    return std::nullopt;
  }
  std::vector<uint8_t> src_wire = media_packet.WireBytes();
  if (src_wire.size() < kRtpFixedHeaderSize) {
    return std::nullopt;
  }

  // RFC 8627 第 4.2.2.3 节图 15：R=1, F=0，FEC 头与源 RTP 头同构，外层 RTP 头不携带 CSRC。
  src_wire[0] = static_cast<uint8_t>(0x80u | (src_wire[0] & 0x3Fu));

  RtpPacket rtx_fec;
  rtx_fec.set_payload_type(flexfec_pt_);
  rtx_fec.set_ssrc(flexfec_ssrc_);
  rtx_fec.set_marker(false);
  rtx_fec.set_sequence_number(seq_num_++);
  rtx_fec.set_timestamp(media_packet.timestamp());
  if (!mid_.empty()) {
    rtx_fec.SetMid(mid_);
  }
  *rtx_fec.mutable_payload() = std::move(src_wire);
  return rtx_fec;
}

std::vector<RtpPacket> FlexfecSender::GetFecPackets() {
  std::vector<RtpPacket> out = std::move(ready_fec_packets_);
  ready_fec_packets_.clear();
  return out;
}

FlexfecReceiver::FlexfecReceiver(uint32_t flexfec_ssrc,
                                 uint32_t protected_media_ssrc,
                                 uint32_t repair_window_us)
    : flexfec_ssrc_(flexfec_ssrc),
      protected_media_ssrc_(protected_media_ssrc),
      repair_window_us_(repair_window_us > 0 ? repair_window_us : 10'000'000) {}

void FlexfecReceiver::PruneBuffers() {
  // received_media_wire_ 以单调递增的 int64_t 展开序列号为键，begin() 恒为最老报文，跨 65535->0 回绕零误删。
  while (received_media_wire_.size() > kMaxCachedMediaPackets) {
    received_media_wire_.erase(received_media_wire_.begin());
  }
  if (newest_unwrapped_seq_ >= 0) {
    const int64_t min_keep_seq = newest_unwrapped_seq_ -
                                 static_cast<int64_t>(kMaxCachedMediaPackets);
    while (!received_media_wire_.empty() &&
           received_media_wire_.begin()->first < min_keep_seq) {
      received_media_wire_.erase(received_media_wire_.begin());
    }
    const int64_t min_fec_seq = newest_unwrapped_seq_ - 256;
    for (auto it = pending_fecs_.begin(); it != pending_fecs_.end();) {
      if (it->unwrapped_base_seq < min_fec_seq) {
        it = pending_fecs_.erase(it);
      } else {
        ++it;
      }
    }
  }
  while (pending_fecs_.size() > kMaxPendingFecPackets) {
    pending_fecs_.pop_front();
  }
}

void FlexfecReceiver::DrainPendingFecs(
    std::vector<RtpPacket>* out_recovered_list) {
  // 支持 2-D 行列 FEC 迭代剥离（Peeling Decoder）：任一报文恢复后立即触发其余挂起校验块继续求解。
  bool made_progress = true;
  while (made_progress && !pending_fecs_.empty()) {
    made_progress = false;
    for (auto it = pending_fecs_.begin(); it != pending_fecs_.end();) {
      RtpPacket rec_pkt;
      const RecoverStatus st = TryRecover(*it, &rec_pkt);
      if (st == RecoverStatus::kRecovered) {
        const int64_t uw = seq_unwrapper_.Unwrap(rec_pkt.sequence_number());
        newest_unwrapped_seq_ = std::max(newest_unwrapped_seq_, uw);
        received_media_wire_[uw] = rec_pkt.WireBytes();
        out_recovered_list->push_back(std::move(rec_pkt));
        it = pending_fecs_.erase(it);
        made_progress = true;
      } else if (st == RecoverStatus::kAlreadyComplete) {
        // 所有受保护源包均已齐备，立即擦除该冗余校验记录，杜绝无效滞留。
        it = pending_fecs_.erase(it);
      } else {
        ++it;
      }
    }
  }
}

std::vector<RtpPacket> FlexfecReceiver::OnRtpPacket(const RtpPacket& packet) {
  std::vector<RtpPacket> recovered_list;

  if (packet.ssrc() == protected_media_ssrc_) {
    const int64_t uw = seq_unwrapper_.Unwrap(packet.sequence_number());
    newest_unwrapped_seq_ = std::max(newest_unwrapped_seq_, uw);
    received_media_wire_[uw] = packet.WireBytes();
    DrainPendingFecs(&recovered_list);
    PruneBuffers();
    return recovered_list;
  }

  if ((flexfec_ssrc_ != 0 && packet.ssrc() != flexfec_ssrc_) ||
      packet.ssrc() == protected_media_ssrc_ ||
      packet.payload_size() < kFlexfecCommonHeaderSize) {
    return recovered_list;
  }

  const uint8_t* p = packet.payload().data();
  const size_t sz = packet.payload_size();
  const bool r_bit = (p[0] & 0x80u) != 0;
  const bool f_bit = (p[0] & 0x40u) != 0;

  // RFC 8627 图 11：R=1, F=1 为未来保留格式，接收端必须直接忽略。
  if (r_bit && f_bit) {
    return recovered_list;
  }

  // RFC 8627 第 4.2.2.3 节（R=1, F=0）：单源包重传格式。
  if (r_bit && !f_bit) {
    if (sz < kFlexfecRetransmitHeaderSize) {
      return recovered_list;
    }
    const uint32_t orig_ssrc = ReadBigEndian32(p + 8);
    if (orig_ssrc != protected_media_ssrc_) {
      return recovered_list;
    }
    const uint16_t orig_seq = ReadBigEndian16(p + 2);
    const int64_t uw = seq_unwrapper_.PeekUnwrap(orig_seq);
    if (received_media_wire_.find(uw) != received_media_wire_.end()) {
      return recovered_list;
    }

    std::vector<uint8_t> recovered_wire(p, p + sz);
    recovered_wire[0] = static_cast<uint8_t>(0x80u | (p[0] & 0x3Fu));
    RtpPacket rec_pkt;
    if (!rec_pkt.Parse(recovered_wire, ext_map_)) {
      return recovered_list;
    }
    const int64_t committed_uw = seq_unwrapper_.Unwrap(orig_seq);
    newest_unwrapped_seq_ = std::max(newest_unwrapped_seq_, committed_uw);
    received_media_wire_[committed_uw] = std::move(recovered_wire);
    recovered_list.push_back(std::move(rec_pkt));
    DrainPendingFecs(&recovered_list);
    PruneBuffers();
    return recovered_list;
  }

  ParityRecord rec;
  if (!ParseRepairPacket(packet, &rec)) {
    return recovered_list;
  }

  RtpPacket immediate_pkt;
  const RecoverStatus st = TryRecover(rec, &immediate_pkt);
  if (st == RecoverStatus::kRecovered) {
    RTC_LOG(kVerbose) << "FlexFEC (RFC 8627) immediately recovered seq="
                      << immediate_pkt.sequence_number();
    const int64_t uw = seq_unwrapper_.Unwrap(immediate_pkt.sequence_number());
    newest_unwrapped_seq_ = std::max(newest_unwrapped_seq_, uw);
    received_media_wire_[uw] = immediate_pkt.WireBytes();
    recovered_list.push_back(std::move(immediate_pkt));
    DrainPendingFecs(&recovered_list);
  } else if (st == RecoverStatus::kNeedMorePackets) {
    pending_fecs_.push_back(std::move(rec));
  }
  PruneBuffers();
  return recovered_list;
}

bool FlexfecReceiver::ParseRepairPacket(const RtpPacket& packet,
                                        ParityRecord* out_record) {
  const uint8_t* p = packet.payload().data();
  const size_t sz = packet.payload_size();
  if (sz < kFlexfecCommonHeaderSize) {
    return false;
  }

  const bool f_bit = (p[0] & 0x40u) != 0;
  const auto& csrcs = packet.csrcs();

  ParityRecord rec;
  rec.outer_rtp_ts = packet.timestamp();
  rec.hdr0_recovery = static_cast<uint8_t>(p[0] & 0x3Fu);
  rec.hdr1_recovery = p[1];
  rec.length_recovery = ReadBigEndian16(p + 2);
  rec.ts_recovery = ReadBigEndian32(p + 4);

  size_t off = kFlexfecCommonHeaderSize;
  if (csrcs.empty()) {
    return false;
  }

  // RFC 8627 第 4.2.2 节：RTP 头部的 CSRC 列表按序声明每个被保护的源 SSRC 块。
  bool matched_single_stream = (csrcs.size() == 1 &&
                                csrcs[0] == protected_media_ssrc_);
  for (size_t i = 0; i < csrcs.size(); ++i) {
    if (!f_bit) {
      // R=0, F=0：SN base_i (16b) + 级联 k-bit 位掩码（15 / 46 / 110 位）。
      if (off + 4 > sz) {
        return false;
      }
      const uint16_t sn_base = ReadBigEndian16(p + off);
      const uint16_t word0 = ReadBigEndian16(p + off + 2);
      off += 4;

      const bool k0 = (word0 & 0x8000u) != 0;
      uint32_t word1 = 0;
      bool k1 = false;
      if (k0) {
        if (off + 4 > sz) {
          return false;
        }
        word1 = ReadBigEndian32(p + off);
        off += 4;
        k1 = (word1 & 0x80000000u) != 0;
      }
      uint64_t word2 = 0;
      if (k1) {
        if (off + 8 > sz) {
          return false;
        }
        word2 = ReadBigEndian64(p + off);
        off += 8;
      }

      if (matched_single_stream) {
        for (uint16_t j = 0; j <= 14; ++j) {
          if ((word0 & (uint16_t{1} << (14 - j))) != 0) {
            rec.protected_seqs.push_back(static_cast<uint16_t>(sn_base + j));
          }
        }
        if (k0) {
          for (uint16_t j = 15; j <= 45; ++j) {
            if ((word1 & (uint32_t{1} << (45 - j))) != 0) {
              rec.protected_seqs.push_back(static_cast<uint16_t>(sn_base + j));
            }
          }
        }
        if (k1) {
          for (uint16_t j = 46; j <= 109; ++j) {
            if ((word2 & (uint64_t{1} << (109 - j))) != 0) {
              rec.protected_seqs.push_back(static_cast<uint16_t>(sn_base + j));
            }
          }
        }
      }
    } else {
      // R=0, F=1 固定行列矩阵模式：SN base_i (16b) | L (8b) | D (8b)。
      if (off + 4 > sz) {
        return false;
      }
      const uint16_t sn_base = ReadBigEndian16(p + off);
      const uint8_t cols_l = p[off + 2];
      const uint8_t rows_d = p[off + 3];
      off += 4;

      // RFC 8627 图 14：L=0（含 L=0,D=0）必须忽略；跨度过大超出合理窗口亦忽略。
      if (cols_l == 0) {
        return false;
      }
      if (matched_single_stream) {
        if (rows_d == 0 || rows_d == 1) {
          for (uint16_t c = 0; c < cols_l; ++c) {
            rec.protected_seqs.push_back(static_cast<uint16_t>(sn_base + c));
          }
        } else {
          const uint32_t max_span =
              static_cast<uint32_t>(rows_d - 1) * static_cast<uint32_t>(cols_l);
          if (max_span >= kMaxCachedMediaPackets) {
            return false;
          }
          for (uint16_t r = 0; r < rows_d; ++r) {
            rec.protected_seqs.push_back(
                static_cast<uint16_t>(sn_base + r * cols_l));
          }
        }
      }
    }
  }

  if (!matched_single_stream || rec.protected_seqs.empty()) {
    return false;
  }

  rec.unwrapped_base_seq =
      seq_unwrapper_.PeekUnwrap(rec.protected_seqs.front());
  rec.repair_payload.assign(p + off, p + sz);
  *out_record = std::move(rec);
  return true;
}

FlexfecReceiver::RecoverStatus FlexfecReceiver::TryRecover(
    const ParityRecord& fec,
    RtpPacket* out_recovered) {
  int missing_count = 0;
  uint16_t missing_seq = 0;

  for (uint16_t seq : fec.protected_seqs) {
    const int64_t uw = seq_unwrapper_.PeekUnwrap(seq);
    if (received_media_wire_.find(uw) == received_media_wire_.end()) {
      ++missing_count;
      missing_seq = seq;
      if (missing_count > 1) {
        return RecoverStatus::kNeedMorePackets;
      }
    }
  }
  if (missing_count == 0) {
    return RecoverStatus::kAlreadyComplete;
  }

  uint8_t rec_hdr0 = fec.hdr0_recovery;
  uint8_t rec_hdr1 = fec.hdr1_recovery;
  uint16_t rec_post_hdr_len = fec.length_recovery;
  uint32_t rec_ts = fec.ts_recovery;
  std::vector<uint8_t> rec_post_hdr = fec.repair_payload;

  const uint64_t max_ts_span_90k =
      (static_cast<uint64_t>(repair_window_us_) * 90ULL) / 1000ULL;

  for (uint16_t seq : fec.protected_seqs) {
    if (seq == missing_seq) {
      continue;
    }
    const int64_t uw = seq_unwrapper_.PeekUnwrap(seq);
    const auto it = received_media_wire_.find(uw);
    if (it == received_media_wire_.end() ||
        it->second.size() < kRtpFixedHeaderSize) {
      return RecoverStatus::kAlreadyComplete;
    }
    const auto& known_wire = it->second;
    rec_hdr0 ^= static_cast<uint8_t>(known_wire[0] & 0x3Fu);
    rec_hdr1 ^= known_wire[1];
    const size_t known_post_len = known_wire.size() - kRtpFixedHeaderSize;
    rec_post_hdr_len ^= static_cast<uint16_t>(known_post_len);
    rec_ts ^= ReadBigEndian32(known_wire.data() + 4);

    if (rec_post_hdr.size() < known_post_len) {
      rec_post_hdr.resize(known_post_len, 0);
    }
    for (size_t b = 0; b < known_post_len; ++b) {
      rec_post_hdr[b] ^= known_wire[kRtpFixedHeaderSize + b];
    }
  }

  if (rec_post_hdr_len > rec_post_hdr.size()) {
    return RecoverStatus::kAlreadyComplete;
  }
  if (AbsRtpTimestampDiff(fec.outer_rtp_ts, rec_ts) > max_ts_span_90k) {
    return RecoverStatus::kAlreadyComplete;
  }

  std::vector<uint8_t> full_wire(kRtpFixedHeaderSize + rec_post_hdr_len, 0);
  full_wire[0] = static_cast<uint8_t>(0x80u | (rec_hdr0 & 0x3Fu));
  full_wire[1] = rec_hdr1;
  WriteBigEndian16(full_wire.data() + 2, missing_seq);
  WriteBigEndian32(full_wire.data() + 4, rec_ts);
  WriteBigEndian32(full_wire.data() + 8, protected_media_ssrc_);
  if (rec_post_hdr_len > 0) {
    std::memcpy(full_wire.data() + kRtpFixedHeaderSize, rec_post_hdr.data(),
                rec_post_hdr_len);
  }

  if (!out_recovered->Parse(full_wire, ext_map_)) {
    return RecoverStatus::kAlreadyComplete;
  }
  return RecoverStatus::kRecovered;
}

}  // namespace rtc
