#include "modules/rtp_rtcp/flexfec_codec.h"

#include <algorithm>
#include <cmath>
#include <cstring>

#include "modules/rtp_rtcp/byte_io.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {
constexpr size_t kFlexfecHeaderSize = 20;
}  // namespace

void FecControllerDefault::UpdateNetworkMetrics(DataRate estimated_bitrate,
                                                TimeDelta rtt,
                                                double loss_rate_ratio) {
  loss_rate_ratio = std::clamp(loss_rate_ratio, 0.0, 0.5);
  if ((estimated_bitrate < DataRate::KilobitsPerSec(110) &&
       loss_rate_ratio < 0.12) ||
      (loss_rate_ratio < 0.02 && rtt < TimeDelta::Millis(70))) {
    keyframe_params_ = FecProtectionParams{25, 1, false};
    delta_params_ = FecProtectionParams{0, 1, false};
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

  keyframe_params_.fec_rate =
      static_cast<uint8_t>(std::lround(key_ratio * 255.0));
  keyframe_params_.max_fec_frames = 1;
  keyframe_params_.use_burst_interleaving = (loss_rate_ratio >= 0.08);
}

FlexfecSender::FlexfecSender(uint8_t flexfec_payload_type,
                             uint32_t flexfec_ssrc,
                             uint32_t protected_media_ssrc,
                             std::string mid)
    : flexfec_pt_(flexfec_payload_type),
      flexfec_ssrc_(flexfec_ssrc),
      protected_media_ssrc_(protected_media_ssrc),
      mid_(std::move(mid)) {}

void FlexfecSender::SetProtectionParameters(const FecProtectionParams& params) {
  params_ = params;
}

void FlexfecSender::AddRtpPacketAndGenerateFec(const RtpPacket& media_packet) {
  if (params_.fec_rate == 0 || media_packet.ssrc() != protected_media_ssrc_) {
    return;
  }
  pending_media_.push_back(media_packet);

  const size_t group_size =
      std::clamp<size_t>((255 + params_.fec_rate / 2) / params_.fec_rate, 2, 12);

  if (params_.use_burst_interleaving &&
      pending_media_.size() >= group_size * 2) {
    std::vector<const RtpPacket*> even_group;
    std::vector<const RtpPacket*> odd_group;
    for (size_t i = 0; i < group_size * 2; ++i) {
      if ((i % 2) == 0) {
        even_group.push_back(&pending_media_[i]);
      } else {
        odd_group.push_back(&pending_media_[i]);
      }
    }
    ready_fec_packets_.push_back(BuildParityPacket(even_group));
    ready_fec_packets_.push_back(BuildParityPacket(odd_group));
    pending_media_.erase(
        pending_media_.begin(),
        pending_media_.begin() + static_cast<ptrdiff_t>(group_size * 2));
  } else if (!params_.use_burst_interleaving &&
             pending_media_.size() >= group_size) {
    std::vector<const RtpPacket*> group;
    group.reserve(group_size);
    for (size_t i = 0; i < group_size; ++i) {
      group.push_back(&pending_media_[i]);
    }
    ready_fec_packets_.push_back(BuildParityPacket(group));
    pending_media_.erase(
        pending_media_.begin(),
        pending_media_.begin() + static_cast<ptrdiff_t>(group_size));
  } else if (media_packet.marker() && pending_media_.size() >= 3 &&
             params_.fec_rate >= 45) {
    std::vector<const RtpPacket*> group;
    group.reserve(pending_media_.size());
    for (const auto& p : pending_media_) {
      group.push_back(&p);
    }
    ready_fec_packets_.push_back(BuildParityPacket(group));
    pending_media_.clear();
  }
}

RtpPacket FlexfecSender::BuildParityPacket(
    const std::vector<const RtpPacket*>& group) {
  const uint16_t base_seq = group.front()->sequence_number();
  uint16_t bitmask = 0;

  std::vector<std::vector<uint8_t>> serialized;
  serialized.reserve(group.size());
  size_t max_wire_len = 0;

  for (const RtpPacket* pkt : group) {
    const uint16_t offset =
        static_cast<uint16_t>(pkt->sequence_number() - base_seq);
    if (offset < 16) {
      bitmask |= static_cast<uint16_t>(1u << offset);
      auto wire = pkt->Serialize();
      max_wire_len = std::max(max_wire_len, wire.size());
      serialized.push_back(std::move(wire));
    }
  }

  std::vector<uint8_t> fec_payload(kFlexfecHeaderSize + max_wire_len, 0);
  uint16_t len_recovery = 0;

  for (const auto& wire : serialized) {
    len_recovery ^= static_cast<uint16_t>(wire.size());
    for (size_t b = 0; b < wire.size(); ++b) {
      fec_payload[kFlexfecHeaderSize + b] ^= wire[b];
    }
  }

  fec_payload[0] = fec_payload[kFlexfecHeaderSize + 0] & 0x3F;
  fec_payload[1] = fec_payload[kFlexfecHeaderSize + 1];
  WriteBigEndian16(fec_payload.data() + 2, len_recovery);
  std::memcpy(fec_payload.data() + 4,
              fec_payload.data() + kFlexfecHeaderSize + 4, 4);
  fec_payload[8] = 1;
  WriteBigEndian32(fec_payload.data() + 12, protected_media_ssrc_);
  WriteBigEndian16(fec_payload.data() + 16, base_seq);
  WriteBigEndian16(fec_payload.data() + 18, bitmask);

  RtpPacket fec_pkt;
  fec_pkt.set_payload_type(flexfec_pt_);
  fec_pkt.set_ssrc(flexfec_ssrc_);
  fec_pkt.set_sequence_number(seq_num_++);
  fec_pkt.set_timestamp(group.back()->timestamp());
  fec_pkt.set_marker(true);
  if (!mid_.empty()) {
    fec_pkt.SetMid(mid_);
  }
  *fec_pkt.mutable_payload() = std::move(fec_payload);
  return fec_pkt;
}

std::vector<RtpPacket> FlexfecSender::GetFecPackets() {
  std::vector<RtpPacket> out = std::move(ready_fec_packets_);
  ready_fec_packets_.clear();
  return out;
}

FlexfecReceiver::FlexfecReceiver(uint32_t flexfec_ssrc,
                                 uint32_t protected_media_ssrc)
    : flexfec_ssrc_(flexfec_ssrc),
      protected_media_ssrc_(protected_media_ssrc) {}

std::vector<RtpPacket> FlexfecReceiver::OnRtpPacket(const RtpPacket& packet) {
  std::vector<RtpPacket> recovered_list;

  if (packet.ssrc() == protected_media_ssrc_) {
    received_media_wire_[packet.sequence_number()] = packet.Serialize();
    while (received_media_wire_.size() > 512) {
      received_media_wire_.erase(received_media_wire_.begin());
    }

    for (auto it = pending_fecs_.begin(); it != pending_fecs_.end();) {
      auto rec = TryRecover(*it);
      if (rec.has_value()) {
        RTC_LOG(kVerbose) << "FlexFEC recovered lost packet seq="
                          << rec->sequence_number();
        received_media_wire_[rec->sequence_number()] = rec->Serialize();
        recovered_list.push_back(std::move(*rec));
        it = pending_fecs_.erase(it);
      } else {
        ++it;
      }
    }
    return recovered_list;
  }

  // 支持动态通配 flexfec_ssrc_ == 0（接收端尚未预先获知对端冗余流 SSRC 时，凭载荷内 protected_media_ssrc 精确校验）。
  if ((flexfec_ssrc_ == 0 || packet.ssrc() == flexfec_ssrc_) &&
      packet.ssrc() != protected_media_ssrc_ &&
      packet.payload_size() > kFlexfecHeaderSize) {
    const uint8_t* p = packet.payload().data();
    const uint32_t prot_ssrc = ReadBigEndian32(p + 12);
    if (prot_ssrc != protected_media_ssrc_) {
      return recovered_list;
    }
    ParityRecord rec;
    rec.base_seq = ReadBigEndian16(p + 16);
    rec.bitmask = ReadBigEndian16(p + 18);
    rec.xor_header_recovery.assign(p, p + kFlexfecHeaderSize);
    rec.xor_wire_bytes.assign(p + kFlexfecHeaderSize,
                              p + packet.payload_size());

    auto recovered = TryRecover(rec);
    if (recovered.has_value()) {
      RTC_LOG(kVerbose) << "FlexFEC immediately recovered packet seq="
                        << recovered->sequence_number();
      received_media_wire_[recovered->sequence_number()] =
          recovered->Serialize();
      recovered_list.push_back(std::move(*recovered));
    } else {
      pending_fecs_.push_back(std::move(rec));
      while (pending_fecs_.size() > 64) {
        pending_fecs_.pop_front();
      }
    }
  }
  return recovered_list;
}

std::optional<RtpPacket> FlexfecReceiver::TryRecover(const ParityRecord& fec) {
  int missing_count = 0;
  uint16_t missing_seq = 0;

  for (uint16_t i = 0; i < 16; ++i) {
    if ((fec.bitmask & (1u << i)) == 0) {
      continue;
    }
    const uint16_t seq = static_cast<uint16_t>(fec.base_seq + i);
    if (received_media_wire_.find(seq) == received_media_wire_.end()) {
      ++missing_count;
      missing_seq = seq;
      if (missing_count > 1) {
        return std::nullopt;
      }
    }
  }
  if (missing_count != 1) {
    return std::nullopt;
  }

  uint16_t recovered_len = ReadBigEndian16(fec.xor_header_recovery.data() + 2);
  std::vector<uint8_t> recovered_wire = fec.xor_wire_bytes;

  for (uint16_t i = 0; i < 16; ++i) {
    if ((fec.bitmask & (1u << i)) == 0) {
      continue;
    }
    const uint16_t seq = static_cast<uint16_t>(fec.base_seq + i);
    if (seq == missing_seq) {
      continue;
    }

    const auto& known_wire = received_media_wire_[seq];
    recovered_len ^= static_cast<uint16_t>(known_wire.size());
    if (recovered_wire.size() < known_wire.size()) {
      recovered_wire.resize(known_wire.size(), 0);
    }
    for (size_t b = 0; b < known_wire.size(); ++b) {
      recovered_wire[b] ^= known_wire[b];
    }
  }

  if (recovered_len < RtpPacket::kFixedHeaderSize ||
      recovered_len > recovered_wire.size()) {
    return std::nullopt;
  }
  recovered_wire.resize(recovered_len);
  recovered_wire[0] = (recovered_wire[0] & 0x3F) | 0x80;
  WriteBigEndian16(recovered_wire.data() + 2, missing_seq);
  WriteBigEndian32(recovered_wire.data() + 8, protected_media_ssrc_);

  RtpPacket pkt;
  if (!pkt.Parse(recovered_wire)) {
    return std::nullopt;
  }
  return pkt;
}

}  // namespace rtc
