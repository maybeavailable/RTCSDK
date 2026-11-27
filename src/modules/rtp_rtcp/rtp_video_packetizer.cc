#include "modules/rtp_rtcp/rtp_video_packetizer.h"

#include <algorithm>
#include <cstring>

#include "modules/rtp_rtcp/byte_io.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {
constexpr uint8_t kAnnexBStartCode[4] = {0x00, 0x00, 0x00, 0x01};

// H.264 NALU 类型定义（RFC 6184）
constexpr uint8_t kH264NaluIdr = 5;
constexpr uint8_t kH264NaluSps = 7;
constexpr uint8_t kH264NaluPps = 8;
constexpr uint8_t kH264StapA = 24;
constexpr uint8_t kH264FuA = 28;

// H.265 NALU 类型定义（RFC 7798）
constexpr uint8_t kH265BlaWLp = 16;
constexpr uint8_t kH265BlaWRadl = 17;
constexpr uint8_t kH265BlaNLp = 18;
constexpr uint8_t kH265IdrWRadl = 19;
constexpr uint8_t kH265IdrNLp = 20;
constexpr uint8_t kH265Cra = 21;
constexpr uint8_t kH265Vps = 32;
constexpr uint8_t kH265Sps = 33;
constexpr uint8_t kH265Pps = 34;
constexpr uint8_t kH265Ap = 48;
constexpr uint8_t kH265Fu = 49;

constexpr bool IsH265IrapSlice(uint8_t type) {
  return type >= kH265BlaWLp && type <= kH265Cra;
}

void AppendAnnexBNalu(ArrayView<const uint8_t> nalu,
                      std::vector<uint8_t>* dst) {
  dst->insert(dst->end(), kAnnexBStartCode, kAnnexBStartCode + 4);
  dst->insert(dst->end(), nalu.begin(), nalu.end());
}
}  // namespace

std::vector<ArrayView<const uint8_t>> ParseAnnexBNalus(
    ArrayView<const uint8_t> bitstream) {
  std::vector<ArrayView<const uint8_t>> nalus;
  const uint8_t* data = bitstream.data();
  const size_t size = bitstream.size();
  if (data == nullptr || size < 4) {
    return nalus;
  }

  auto find_start_code = [data, size](size_t pos, size_t* sc_len) -> size_t {
    while (pos + 3 <= size) {
      if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
        if (data[pos + 2] == 0x01) {
          *sc_len = 3;
          return pos;
        }
        if (pos + 4 <= size && data[pos + 2] == 0x00 && data[pos + 3] == 0x01) {
          *sc_len = 4;
          return pos;
        }
      }
      ++pos;
    }
    return size;
  };

  size_t sc_len = 0;
  size_t sc_pos = find_start_code(0, &sc_len);
  if (sc_pos == size) {
    nalus.emplace_back(data, size);
    return nalus;
  }

  while (sc_pos < size) {
    const size_t nalu_start = sc_pos + sc_len;
    size_t next_sc_len = 0;
    const size_t next_sc_pos = find_start_code(nalu_start, &next_sc_len);
    if (next_sc_pos > nalu_start) {
      nalus.emplace_back(data + nalu_start, next_sc_pos - nalu_start);
    }
    sc_pos = next_sc_pos;
    sc_len = next_sc_len;
  }
  return nalus;
}

// ======================= H.264 RTP 打包与解包（RFC 6184） =======================

H264Packetizer::H264Packetizer(size_t max_payload_len)
    : max_payload_len_(std::max<size_t>(max_payload_len, 256)) {}

std::vector<PacketizedPayload> H264Packetizer::PacketizeAnnexB(
    ArrayView<const uint8_t> bitstream,
    bool* out_is_keyframe) {
  const auto raw_nalus = ParseAnnexBNalus(bitstream);
  std::vector<ArrayView<const uint8_t>> effective_nalus;
  effective_nalus.reserve(raw_nalus.size() + 2);

  bool has_sps = false;
  bool has_pps = false;
  bool has_idr = false;

  for (const auto& nalu : raw_nalus) {
    if (nalu.empty()) {
      continue;
    }
    const uint8_t type = nalu[0] & 0x1F;
    if (type == kH264NaluSps) {
      cached_sps_.assign(nalu.begin(), nalu.end());
      has_sps = true;
    } else if (type == kH264NaluPps) {
      cached_pps_.assign(nalu.begin(), nalu.end());
      has_pps = true;
    } else if (type == kH264NaluIdr) {
      has_idr = true;
    }
  }

  if (has_idr) {
    if (!has_sps && !cached_sps_.empty()) {
      effective_nalus.emplace_back(cached_sps_);
    }
    if (!has_pps && !cached_pps_.empty()) {
      effective_nalus.emplace_back(cached_pps_);
    }
  }
  for (const auto& nalu : raw_nalus) {
    if (!nalu.empty()) {
      effective_nalus.push_back(nalu);
    }
  }
  if (out_is_keyframe != nullptr) {
    *out_is_keyframe = has_idr;
  }

  std::vector<PacketizedPayload> packets;
  size_t i = 0;
  while (i < effective_nalus.size()) {
    const auto& cur = effective_nalus[i];
    if (cur.size() <= max_payload_len_) {
      size_t agg_count = 1;
      size_t stap_bytes = 1 + 2 + cur.size();
      uint8_t max_nri = cur[0] & 0x60;
      while (i + agg_count < effective_nalus.size()) {
        const auto& next = effective_nalus[i + agg_count];
        if (stap_bytes + 2 + next.size() > max_payload_len_) {
          break;
        }
        stap_bytes += 2 + next.size();
        max_nri = std::max<uint8_t>(max_nri, next[0] & 0x60);
        ++agg_count;
      }

      if (agg_count > 1) {
        PacketizedPayload pkt;
        pkt.bytes.resize(stap_bytes);
        pkt.bytes[0] = static_cast<uint8_t>(max_nri | kH264StapA);
        size_t offset = 1;
        for (size_t k = 0; k < agg_count; ++k) {
          const auto& item = effective_nalus[i + k];
          WriteBigEndian16(pkt.bytes.data() + offset,
                           static_cast<uint16_t>(item.size()));
          offset += 2;
          std::memcpy(pkt.bytes.data() + offset, item.data(), item.size());
          offset += item.size();
        }
        packets.push_back(std::move(pkt));
        i += agg_count;
      } else {
        PacketizedPayload pkt;
        pkt.bytes.assign(cur.begin(), cur.end());
        packets.push_back(std::move(pkt));
        ++i;
      }
    } else {
      const uint8_t nalu_hdr = cur[0];
      const uint8_t fu_indicator = (nalu_hdr & 0xE0) | kH264FuA;
      const uint8_t nalu_type = nalu_hdr & 0x1F;

      const uint8_t* payload_ptr = cur.data() + 1;
      const size_t total_payload = cur.size() - 1;
      const size_t max_frag_payload = max_payload_len_ - 2;
      const size_t num_frags =
          (total_payload + max_frag_payload - 1) / max_frag_payload;
      const size_t base_frag_size = total_payload / num_frags;
      size_t remainder = total_payload % num_frags;

      size_t offset = 0;
      for (size_t f = 0; f < num_frags; ++f) {
        const size_t chunk = base_frag_size + (remainder > 0 ? 1 : 0);
        if (remainder > 0) {
          --remainder;
        }

        PacketizedPayload pkt;
        pkt.bytes.resize(2 + chunk);
        pkt.bytes[0] = fu_indicator;
        uint8_t fu_hdr = nalu_type;
        if (f == 0) {
          fu_hdr |= 0x80;
        }
        if (f + 1 == num_frags) {
          fu_hdr |= 0x40;
        }
        pkt.bytes[1] = fu_hdr;
        std::memcpy(pkt.bytes.data() + 2, payload_ptr + offset, chunk);
        packets.push_back(std::move(pkt));
        offset += chunk;
      }
      ++i;
    }
  }

  if (!packets.empty()) {
    packets.front().is_first_in_frame = true;
    packets.back().is_last_in_frame = true;
  }
  return packets;
}

std::optional<DepacketizedUnit> H264Depacketizer::ParsePayload(
    ArrayView<const uint8_t> payload) {
  if (payload.empty() || (payload[0] & 0x80u) != 0) {
    return std::nullopt;
  }
  DepacketizedUnit out;
  const uint8_t nal_type = payload[0] & 0x1F;

  if (nal_type >= 1 && nal_type <= 23) {
    out.is_first_in_frame = true;
    out.nalu_type = nal_type;
    out.has_sps = (nal_type == kH264NaluSps);
    out.has_pps = (nal_type == kH264NaluPps);
    out.is_keyframe = (nal_type == kH264NaluIdr);
    AppendAnnexBNalu(payload, &out.annexb_bytes);
    return out;
  }
  if (nal_type == kH264StapA) {
    if (payload.size() <= 3) {
      RTC_LOG(kWarning) << "Truncated H.264 STAP-A packet";
      return std::nullopt;
    }
    out.is_first_in_frame = true;
    out.nalu_type = kH264StapA;
    size_t offset = 1;
    while (offset + 2 <= payload.size()) {
      const uint16_t nalu_len = ReadBigEndian16(payload.data() + offset);
      offset += 2;
      if (nalu_len == 0 || offset + nalu_len > payload.size()) {
        RTC_LOG(kWarning) << "Malformed H.264 STAP-A NALU length=" << nalu_len;
        return std::nullopt;
      }
      if ((payload[offset] & 0x80u) != 0) {
        return std::nullopt;
      }
      const uint8_t inner_type = payload[offset] & 0x1F;
      if (inner_type == 0 || inner_type >= 24) {
        return std::nullopt;
      }
      if (inner_type == kH264NaluSps) {
        out.has_sps = true;
      } else if (inner_type == kH264NaluPps) {
        out.has_pps = true;
      } else if (inner_type == kH264NaluIdr) {
        out.is_keyframe = true;
      }
      AppendAnnexBNalu(payload.subview(offset, nalu_len), &out.annexb_bytes);
      offset += nalu_len;
    }
    if (offset != payload.size()) {
      return std::nullopt;
    }
    return out;
  }
  if (nal_type == kH264FuA) {
    if (payload.size() <= 2) {
      return std::nullopt;
    }
    const bool start_bit = (payload[1] & 0x80) != 0;
    const bool end_bit = (payload[1] & 0x40) != 0;
    const uint8_t orig_type = payload[1] & 0x1F;
    if ((start_bit && end_bit) || orig_type == 0 || orig_type >= 24) {
      return std::nullopt;
    }
    out.is_fu = true;
    out.is_fu_start = start_bit;
    out.is_fu_end = end_bit;
    out.nalu_type = orig_type;
    out.has_sps = (orig_type == kH264NaluSps);
    out.has_pps = (orig_type == kH264NaluPps);
    const uint8_t reconstructed_hdr = (payload[0] & 0x60) | orig_type;

    if (start_bit) {
      out.is_first_in_frame = true;
      out.is_keyframe = (orig_type == kH264NaluIdr);
      out.annexb_bytes.insert(out.annexb_bytes.end(), kAnnexBStartCode,
                              kAnnexBStartCode + 4);
      out.annexb_bytes.push_back(reconstructed_hdr);
    }
    out.annexb_bytes.insert(out.annexb_bytes.end(), payload.data() + 2,
                            payload.data() + payload.size());
    return out;
  }
  return std::nullopt;
}

// ======================= H.265 RTP 打包与解包（RFC 7798） =======================

H265Packetizer::H265Packetizer(size_t max_payload_len)
    : max_payload_len_(std::max<size_t>(max_payload_len, 256)) {}

std::vector<PacketizedPayload> H265Packetizer::PacketizeAnnexB(
    ArrayView<const uint8_t> bitstream,
    bool* out_is_keyframe) {
  const auto raw_nalus = ParseAnnexBNalus(bitstream);
  std::vector<ArrayView<const uint8_t>> effective_nalus;
  effective_nalus.reserve(raw_nalus.size() + 3);

  bool has_vps = false;
  bool has_sps = false;
  bool has_pps = false;
  bool has_irap = false;

  for (const auto& nalu : raw_nalus) {
    if (nalu.size() < 2) {
      continue;
    }
    const uint8_t type = (nalu[0] >> 1) & 0x3F;
    if (type == kH265Vps) {
      cached_vps_.assign(nalu.begin(), nalu.end());
      has_vps = true;
    } else if (type == kH265Sps) {
      cached_sps_.assign(nalu.begin(), nalu.end());
      has_sps = true;
    } else if (type == kH265Pps) {
      cached_pps_.assign(nalu.begin(), nalu.end());
      has_pps = true;
    } else if (IsH265IrapSlice(type)) {
      has_irap = true;
    }
  }

  if (has_irap) {
    if (!has_vps && !cached_vps_.empty()) {
      effective_nalus.emplace_back(cached_vps_);
    }
    if (!has_sps && !cached_sps_.empty()) {
      effective_nalus.emplace_back(cached_sps_);
    }
    if (!has_pps && !cached_pps_.empty()) {
      effective_nalus.emplace_back(cached_pps_);
    }
  }
  for (const auto& nalu : raw_nalus) {
    if (nalu.size() >= 2) {
      effective_nalus.push_back(nalu);
    }
  }
  if (out_is_keyframe != nullptr) {
    *out_is_keyframe = has_irap;
  }

  std::vector<PacketizedPayload> packets;
  size_t i = 0;
  while (i < effective_nalus.size()) {
    const auto& cur = effective_nalus[i];
    if (cur.size() <= max_payload_len_) {
      size_t agg_count = 1;
      size_t ap_bytes = 2 + 2 + cur.size();
      uint8_t min_layer_id =
          static_cast<uint8_t>(((cur[0] & 0x01) << 5) | ((cur[1] >> 3) & 0x1F));
      uint8_t min_tid = cur[1] & 0x07;

      while (i + agg_count < effective_nalus.size()) {
        const auto& next = effective_nalus[i + agg_count];
        if (ap_bytes + 2 + next.size() > max_payload_len_) {
          break;
        }
        ap_bytes += 2 + next.size();
        const uint8_t lid = static_cast<uint8_t>(((next[0] & 0x01) << 5) |
                                                 ((next[1] >> 3) & 0x1F));
        const uint8_t tid = next[1] & 0x07;
        min_layer_id = std::min(min_layer_id, lid);
        min_tid = std::min(min_tid, tid);
        ++agg_count;
      }

      if (agg_count > 1) {
        PacketizedPayload pkt;
        pkt.bytes.resize(ap_bytes);
        pkt.bytes[0] =
            static_cast<uint8_t>((kH265Ap << 1) | ((min_layer_id >> 5) & 0x01));
        pkt.bytes[1] =
            static_cast<uint8_t>(((min_layer_id & 0x1F) << 3) | (min_tid & 0x07));
        size_t offset = 2;
        for (size_t k = 0; k < agg_count; ++k) {
          const auto& item = effective_nalus[i + k];
          WriteBigEndian16(pkt.bytes.data() + offset,
                           static_cast<uint16_t>(item.size()));
          offset += 2;
          std::memcpy(pkt.bytes.data() + offset, item.data(), item.size());
          offset += item.size();
        }
        packets.push_back(std::move(pkt));
        i += agg_count;
      } else {
        PacketizedPayload pkt;
        pkt.bytes.assign(cur.begin(), cur.end());
        packets.push_back(std::move(pkt));
        ++i;
      }
    } else {
      const uint8_t orig_type = (cur[0] >> 1) & 0x3F;
      const uint8_t hdr0 =
          static_cast<uint8_t>((cur[0] & 0x81) | (kH265Fu << 1));
      const uint8_t hdr1 = cur[1];

      const uint8_t* payload_ptr = cur.data() + 2;
      const size_t total_payload = cur.size() - 2;
      const size_t max_frag_payload = max_payload_len_ - 3;
      const size_t num_frags =
          (total_payload + max_frag_payload - 1) / max_frag_payload;
      const size_t base_frag_size = total_payload / num_frags;
      size_t remainder = total_payload % num_frags;

      size_t offset = 0;
      for (size_t f = 0; f < num_frags; ++f) {
        const size_t chunk = base_frag_size + (remainder > 0 ? 1 : 0);
        if (remainder > 0) {
          --remainder;
        }

        PacketizedPayload pkt;
        pkt.bytes.resize(3 + chunk);
        pkt.bytes[0] = hdr0;
        pkt.bytes[1] = hdr1;
        uint8_t fu_hdr = orig_type;
        if (f == 0) {
          fu_hdr |= 0x80;
        }
        if (f + 1 == num_frags) {
          fu_hdr |= 0x40;
        }
        pkt.bytes[2] = fu_hdr;
        std::memcpy(pkt.bytes.data() + 3, payload_ptr + offset, chunk);
        packets.push_back(std::move(pkt));
        offset += chunk;
      }
      ++i;
    }
  }

  if (!packets.empty()) {
    packets.front().is_first_in_frame = true;
    packets.back().is_last_in_frame = true;
  }
  return packets;
}

std::optional<DepacketizedUnit> H265Depacketizer::ParsePayload(
    ArrayView<const uint8_t> payload) {
  if (payload.size() < 2 || (payload[0] & 0x80u) != 0 ||
      (payload[1] & 0x07u) == 0) {
    return std::nullopt;
  }
  DepacketizedUnit out;
  const uint8_t nal_type = (payload[0] >> 1) & 0x3F;

  if (nal_type < 48) {
    out.is_first_in_frame = true;
    out.nalu_type = nal_type;
    out.has_vps = (nal_type == kH265Vps);
    out.has_sps = (nal_type == kH265Sps);
    out.has_pps = (nal_type == kH265Pps);
    out.is_keyframe = IsH265IrapSlice(nal_type);
    AppendAnnexBNalu(payload, &out.annexb_bytes);
    return out;
  }
  if (nal_type == kH265Ap) {
    if (payload.size() <= 4) {
      RTC_LOG(kWarning) << "Truncated H.265 AP packet";
      return std::nullopt;
    }
    out.is_first_in_frame = true;
    out.nalu_type = kH265Ap;
    size_t offset = 2;
    while (offset + 2 <= payload.size()) {
      const uint16_t nalu_len = ReadBigEndian16(payload.data() + offset);
      offset += 2;
      if (nalu_len < 2 || offset + nalu_len > payload.size()) {
        RTC_LOG(kWarning) << "Malformed H.265 AP NALU length=" << nalu_len;
        return std::nullopt;
      }
      if ((payload[offset] & 0x80u) != 0 ||
          (payload[offset + 1] & 0x07u) == 0) {
        return std::nullopt;
      }
      const uint8_t inner_type = (payload[offset] >> 1) & 0x3F;
      if (inner_type >= 48) {
        return std::nullopt;
      }
      if (inner_type == kH265Vps) {
        out.has_vps = true;
      } else if (inner_type == kH265Sps) {
        out.has_sps = true;
      } else if (inner_type == kH265Pps) {
        out.has_pps = true;
      } else if (IsH265IrapSlice(inner_type)) {
        out.is_keyframe = true;
      }
      AppendAnnexBNalu(payload.subview(offset, nalu_len), &out.annexb_bytes);
      offset += nalu_len;
    }
    if (offset != payload.size()) {
      return std::nullopt;
    }
    return out;
  }
  if (nal_type == kH265Fu) {
    if (payload.size() <= 3) {
      return std::nullopt;
    }
    const bool start_bit = (payload[2] & 0x80) != 0;
    const bool end_bit = (payload[2] & 0x40) != 0;
    const uint8_t orig_type = payload[2] & 0x3F;
    if ((start_bit && end_bit) || orig_type >= 48) {
      return std::nullopt;
    }
    out.is_fu = true;
    out.is_fu_start = start_bit;
    out.is_fu_end = end_bit;
    out.nalu_type = orig_type;
    out.has_vps = (orig_type == kH265Vps);
    out.has_sps = (orig_type == kH265Sps);
    out.has_pps = (orig_type == kH265Pps);
    if (start_bit) {
      out.is_first_in_frame = true;
      out.is_keyframe = IsH265IrapSlice(orig_type);
      const uint8_t rec_hdr0 =
          static_cast<uint8_t>((payload[0] & 0x01) | (orig_type << 1));
      const uint8_t rec_hdr1 = payload[1];
      out.annexb_bytes.insert(out.annexb_bytes.end(), kAnnexBStartCode,
                              kAnnexBStartCode + 4);
      out.annexb_bytes.push_back(rec_hdr0);
      out.annexb_bytes.push_back(rec_hdr1);
    }
    out.annexb_bytes.insert(out.annexb_bytes.end(), payload.data() + 3,
                            payload.data() + payload.size());
    return out;
  }
  return std::nullopt;
}

}  // namespace rtc
