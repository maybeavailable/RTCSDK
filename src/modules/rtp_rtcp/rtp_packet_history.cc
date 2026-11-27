#include "modules/rtp_rtcp/rtp_packet_history.h"

#include <algorithm>
#include <cstring>

#include "modules/rtp_rtcp/byte_io.h"

namespace rtc {

RtpPacketHistory::RtpPacketHistory(size_t number_to_store)
    : max_to_store_(std::clamp<size_t>(number_to_store, 64, kMaxCapacity)) {}

void RtpPacketHistory::SetRtt(TimeDelta rtt) {
  if (rtt > TimeDelta::Zero()) {
    rtt_ = std::clamp(rtt, TimeDelta::Millis(20), TimeDelta::Seconds(2));
  }
}

void RtpPacketHistory::PutRtpPacket(const RtpPacket& packet,
                                    Timestamp send_time) {
  if (packet.payload_size() == 0) {
    return;
  }
  CullOldPackets(send_time);

  const int64_t unwrapped = unwrapper_.Unwrap(packet.sequence_number());
  StoredPacket entry;
  entry.packet = packet;
  entry.unwrapped_seq = unwrapped;
  entry.insert_time = send_time;
  entry.last_send_time = send_time;
  entry.times_retransmitted = 0;

  if (packets_.empty() || unwrapped > packets_.back().unwrapped_seq) {
    packets_.push_back(std::move(entry));
  } else {
    auto it = std::lower_bound(packets_.begin(), packets_.end(), unwrapped,
                               [](const StoredPacket& sp, int64_t seq) {
                                 return sp.unwrapped_seq < seq;
                               });
    if (it != packets_.end() && it->unwrapped_seq == unwrapped) {
      *it = std::move(entry);
    } else {
      packets_.insert(it, std::move(entry));
    }
  }

  while (packets_.size() > max_to_store_) {
    packets_.pop_front();
  }
}

std::optional<RtpPacket> RtpPacketHistory::GetPacketAndMarkAsSent(
    uint16_t sequence_number,
    Timestamp now) {
  CullOldPackets(now);
  for (auto& sp : packets_) {
    if (sp.packet.sequence_number() == sequence_number) {
      if (sp.times_retransmitted >= 5) {
        return std::nullopt;
      }
      if (sp.times_retransmitted > 0 && (now - sp.last_send_time) < rtt_) {
        return std::nullopt;
      }
      sp.last_send_time = now;
      ++sp.times_retransmitted;
      return sp.packet;
    }
  }
  return std::nullopt;
}

std::optional<RtpPacket> RtpPacketHistory::GetPayloadPaddingPacket(
    Timestamp now) {
  CullOldPackets(now);
  if (packets_.empty()) {
    return std::nullopt;
  }
  return packets_.back().packet;
}

void RtpPacketHistory::CullOldPackets(Timestamp now) {
  const TimeDelta max_age = std::max(rtt_ * 3, TimeDelta::Millis(1000));
  while (!packets_.empty() && (now - packets_.front().insert_time) > max_age) {
    packets_.pop_front();
  }
}

void RtpPacketHistory::Clear() {
  packets_.clear();
  unwrapper_.Reset();
}

RtpPacket RtxCodec::BuildRtxPacket(const RtpPacket& original,
                                   uint32_t rtx_ssrc,
                                   uint8_t rtx_payload_type,
                                   uint16_t rtx_sequence_number) {
  RtpPacket rtx;
  rtx.CopyHeaderAndExtensionsFrom(original);
  rtx.set_ssrc(rtx_ssrc);
  rtx.set_payload_type(rtx_payload_type);
  rtx.set_sequence_number(rtx_sequence_number);

  if (original.rid().has_value()) {
    rtx.SetRepairedRid(*original.rid());
    rtx.ClearRid();
  }

  std::vector<uint8_t>* dst_payload = rtx.mutable_payload();
  dst_payload->resize(2 + original.payload_size());
  WriteBigEndian16(dst_payload->data(), original.sequence_number());
  if (original.payload_size() > 0) {
    std::memcpy(dst_payload->data() + 2, original.payload().data(),
                original.payload_size());
  }
  return rtx;
}

std::optional<RtpPacket> RtxCodec::ParseRtxPacket(
    const RtpPacket& rtx_packet,
    uint32_t original_media_ssrc,
    uint8_t original_media_payload_type) {
  if (rtx_packet.payload_size() <= 2) {
    return std::nullopt;
  }
  RtpPacket media;
  media.CopyHeaderAndExtensionsFrom(rtx_packet);
  media.set_ssrc(original_media_ssrc);
  media.set_payload_type(original_media_payload_type);

  const uint16_t osn = ReadBigEndian16(rtx_packet.payload().data());
  media.set_sequence_number(osn);
  if (rtx_packet.repaired_rid().has_value()) {
    media.SetRid(*rtx_packet.repaired_rid());
    media.ClearRepairedRid();
  }
  media.SetPayload(MakeArrayView(rtx_packet.payload().data() + 2,
                                 rtx_packet.payload_size() - 2));
  return media;
}

}  // namespace rtc
