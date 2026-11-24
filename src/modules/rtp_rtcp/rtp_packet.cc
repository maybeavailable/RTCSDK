#include "modules/rtp_rtcp/rtp_packet.h"

#include <algorithm>
#include <cstring>

#include "modules/rtp_rtcp/byte_io.h"
#include "rtc_base/logging.h"

namespace rtc {

void RtpPacket::set_csrcs(std::vector<uint32_t> list) {
  if (list.size() > 15) {
    list.resize(15);
  }
  csrcs_ = std::move(list);
  raw_wire_.clear();
}

void RtpPacket::add_csrc(uint32_t csrc) {
  if (csrcs_.size() < 15) {
    csrcs_.push_back(csrc);
    raw_wire_.clear();
  }
}

void RtpPacket::SetMid(std::string_view mid_value) {
  if (!mid_value.empty() && mid_value.size() <= 16) {
    mid_.emplace(mid_value);
    raw_wire_.clear();
  }
}

void RtpPacket::SetRid(std::string_view rid_value) {
  if (!rid_value.empty() && rid_value.size() <= 16) {
    rid_.emplace(rid_value);
    raw_wire_.clear();
  }
}

void RtpPacket::SetRepairedRid(std::string_view rrid_value) {
  if (!rrid_value.empty() && rrid_value.size() <= 16) {
    rrid_.emplace(rrid_value);
    raw_wire_.clear();
  }
}

void RtpPacket::SetPayload(ArrayView<const uint8_t> payload_bytes) {
  if (!payload_bytes.empty()) {
    payload_.assign(payload_bytes.begin(), payload_bytes.end());
  } else {
    payload_.clear();
  }
  raw_wire_.clear();
}

void RtpPacket::CopyHeaderAndExtensionsFrom(const RtpPacket& other) {
  ext_map_ = other.ext_map_;
  marker_ = other.marker_;
  payload_type_ = other.payload_type_;
  sequence_number_ = other.sequence_number_;
  timestamp_ = other.timestamp_;
  ssrc_ = other.ssrc_;
  csrcs_ = other.csrcs_;
  transport_seq_ = other.transport_seq_;
  abs_send_time_ = other.abs_send_time_;
  mid_ = other.mid_;
  rid_ = other.rid_;
  rrid_ = other.rrid_;
  playout_delay_ = other.playout_delay_;
  dep_ext_ = other.dep_ext_;
  raw_wire_.clear();
}

bool RtpPacket::UsesTwoByteExtensionHeader() const {
  return (transport_seq_.has_value() &&
          ext_map_.transport_sequence_number_id > 14) ||
         (abs_send_time_.has_value() && ext_map_.absolute_send_time_id > 14) ||
         (mid_.has_value() && !mid_->empty() && ext_map_.mid_id > 14) ||
         (rid_.has_value() && !rid_->empty() && ext_map_.rid_id > 14) ||
         (rrid_.has_value() && !rrid_->empty() &&
          ext_map_.repaired_rid_id > 14) ||
         (playout_delay_.has_value() && ext_map_.playout_delay_id > 14) ||
         (dep_ext_.has_value() && ext_map_.dependency_descriptor_id > 14);
}

size_t RtpPacket::ExtensionsContentBytes() const {
  const size_t hdr_bytes = UsesTwoByteExtensionHeader() ? 2 : 1;
  size_t content = 0;
  if (transport_seq_.has_value() &&
      ext_map_.transport_sequence_number_id != 0) {
    content += hdr_bytes + 2;
  }
  if (abs_send_time_.has_value() && ext_map_.absolute_send_time_id != 0) {
    content += hdr_bytes + 3;
  }
  if (mid_.has_value() && !mid_->empty() && ext_map_.mid_id != 0) {
    content += hdr_bytes + mid_->size();
  }
  if (rid_.has_value() && !rid_->empty() && ext_map_.rid_id != 0) {
    content += hdr_bytes + rid_->size();
  }
  if (rrid_.has_value() && !rrid_->empty() && ext_map_.repaired_rid_id != 0) {
    content += hdr_bytes + rrid_->size();
  }
  if (playout_delay_.has_value() && ext_map_.playout_delay_id != 0) {
    content += hdr_bytes + 3;
  }
  if (dep_ext_.has_value() && ext_map_.dependency_descriptor_id != 0) {
    const uint8_t refs = std::min<uint8_t>(dep_ext_->num_fdiffs, 4);
    content += hdr_bytes + (4 + refs);
  }
  return content;
}

size_t RtpPacket::SerializedSize() const {
  if (!raw_wire_.empty()) {
    return raw_wire_.size();
  }
  const size_t cc = std::min<size_t>(csrcs_.size(), 15);
  size_t total = kFixedHeaderSize + cc * 4;
  const size_t ext_content = ExtensionsContentBytes();
  if (ext_content > 0) {
    const size_t padded_ext = (ext_content + 3) & ~size_t{3};
    total += 4 + padded_ext;
  }
  total += payload_.size();
  total += padding_size_;
  return total;
}

std::vector<uint8_t> RtpPacket::WireBytes() const {
  if (!raw_wire_.empty()) {
    return raw_wire_;
  }
  return Serialize();
}

size_t RtpPacket::WriteExtensions(uint8_t* dst) const {
  const size_t ext_content = ExtensionsContentBytes();
  if (ext_content == 0) {
    return 0;
  }
  const bool two_byte = UsesTwoByteExtensionHeader();
  const size_t padded_ext = (ext_content + 3) & ~size_t{3};
  WriteBigEndian16(dst,
                   two_byte ? kTwoByteExtensionProfile : kOneByteExtensionProfile);
  WriteBigEndian16(dst + 2, static_cast<uint16_t>(padded_ext / 4));

  uint8_t* p = dst + 4;
  auto write_elem_hdr = [&p, two_byte](uint8_t id, size_t len) {
    if (two_byte) {
      *p++ = id;
      *p++ = static_cast<uint8_t>(len);
    } else {
      *p++ = static_cast<uint8_t>((id << 4) | (len - 1));
    }
  };

  if (transport_seq_.has_value() &&
      ext_map_.transport_sequence_number_id != 0) {
    write_elem_hdr(ext_map_.transport_sequence_number_id, 2);
    WriteBigEndian16(p, *transport_seq_);
    p += 2;
  }
  if (abs_send_time_.has_value() && ext_map_.absolute_send_time_id != 0) {
    write_elem_hdr(ext_map_.absolute_send_time_id, 3);
    WriteBigEndian24(p, *abs_send_time_);
    p += 3;
  }
  auto write_str_ext = [&p, &write_elem_hdr](
                           uint8_t id,
                           const std::optional<std::string>& str) {
    if (id != 0 && str.has_value() && !str->empty() && str->size() <= 16) {
      write_elem_hdr(id, str->size());
      std::memcpy(p, str->data(), str->size());
      p += str->size();
    }
  };
  write_str_ext(ext_map_.mid_id, mid_);
  write_str_ext(ext_map_.rid_id, rid_);
  write_str_ext(ext_map_.repaired_rid_id, rrid_);

  if (playout_delay_.has_value() && ext_map_.playout_delay_id != 0) {
    write_elem_hdr(ext_map_.playout_delay_id, 3);
    const uint32_t min_10ms =
        std::min<uint32_t>(playout_delay_->min_ms / 10, 0x0FFF);
    const uint32_t max_10ms =
        std::min<uint32_t>(playout_delay_->max_ms / 10, 0x0FFF);
    const uint32_t packed = (min_10ms << 12) | max_10ms;
    WriteBigEndian24(p, packed);
    p += 3;
  }
  if (dep_ext_.has_value() && ext_map_.dependency_descriptor_id != 0) {
    const auto& d = *dep_ext_;
    const uint8_t refs = std::min<uint8_t>(d.num_fdiffs, 4);
    const size_t len = 4 + refs;
    write_elem_hdr(ext_map_.dependency_descriptor_id, len);
    uint8_t flags = 0;
    if (d.is_first_in_frame) {
      flags |= 0x80;
    }
    if (d.is_last_in_frame) {
      flags |= 0x40;
    }
    if (d.is_keyframe) {
      flags |= 0x20;
    }
    if (d.discardable) {
      flags |= 0x10;
    }
    flags |= static_cast<uint8_t>((d.spatial_id & 0x03) << 2);
    flags |= static_cast<uint8_t>(d.temporal_id & 0x03);
    *p++ = flags;
    WriteBigEndian16(p, d.frame_number);
    p += 2;
    *p++ = refs;
    for (uint8_t i = 0; i < refs; ++i) {
      *p++ = d.fdiffs[i];
    }
  }

  const size_t written_content = static_cast<size_t>(p - (dst + 4));
  if (padded_ext > written_content) {
    std::memset(p, 0, padded_ext - written_content);
  }
  return 4 + padded_ext;
}

size_t RtpPacket::SerializeTo(uint8_t* dst, size_t capacity) const {
  const size_t needed = SerializedSize();
  if (dst == nullptr || capacity < needed) {
    return 0;
  }
  if (!raw_wire_.empty()) {
    std::memcpy(dst, raw_wire_.data(), raw_wire_.size());
    return raw_wire_.size();
  }
  const bool has_ext = ExtensionsContentBytes() > 0;
  const bool has_pad = padding_size_ > 0;
  const uint8_t cc = static_cast<uint8_t>(std::min<size_t>(csrcs_.size(), 15));

  uint8_t b0 = static_cast<uint8_t>(0x80 | (cc & 0x0F));
  if (has_pad) {
    b0 |= 0x20;
  }
  if (has_ext) {
    b0 |= 0x10;
  }
  dst[0] = b0;
  dst[1] =
      static_cast<uint8_t>((marker_ ? 0x80 : 0x00) | (payload_type_ & 0x7F));
  WriteBigEndian16(dst + 2, sequence_number_);
  WriteBigEndian32(dst + 4, timestamp_);
  WriteBigEndian32(dst + 8, ssrc_);

  size_t offset = kFixedHeaderSize;
  for (uint8_t i = 0; i < cc; ++i) {
    WriteBigEndian32(dst + offset, csrcs_[i]);
    offset += 4;
  }
  if (has_ext) {
    offset += WriteExtensions(dst + offset);
  }
  if (!payload_.empty()) {
    std::memcpy(dst + offset, payload_.data(), payload_.size());
    offset += payload_.size();
  }
  if (has_pad) {
    if (padding_size_ > 1) {
      std::memset(dst + offset, 0, padding_size_ - 1);
    }
    dst[offset + padding_size_ - 1] = static_cast<uint8_t>(padding_size_);
    offset += padding_size_;
  }
  return offset;
}

std::vector<uint8_t> RtpPacket::Serialize() const {
  std::vector<uint8_t> out(SerializedSize());
  SerializeTo(out.data(), out.size());
  return out;
}

void RtpPacket::ParseSingleExtensionElement(
    uint8_t id,
    const uint8_t* p,
    size_t len,
    const RtpHeaderExtensionMap& ext_map) {
  if (id == 0) {
    return;
  }
  if (id == ext_map.transport_sequence_number_id && len == 2) {
    transport_seq_ = ReadBigEndian16(p);
  } else if (id == ext_map.absolute_send_time_id && len == 3) {
    abs_send_time_ = ReadBigEndian24(p);
  } else if (id == ext_map.mid_id && len > 0) {
    mid_.emplace(reinterpret_cast<const char*>(p), len);
  } else if (id == ext_map.rid_id && len > 0) {
    rid_.emplace(reinterpret_cast<const char*>(p), len);
  } else if (id == ext_map.repaired_rid_id && len > 0) {
    rrid_.emplace(reinterpret_cast<const char*>(p), len);
  } else if (id == ext_map.playout_delay_id && len == 3) {
    const uint32_t v = ReadBigEndian24(p);
    PlayoutDelayLimits lim;
    lim.min_ms = static_cast<uint16_t>(((v >> 12) & 0x0FFF) * 10);
    lim.max_ms = static_cast<uint16_t>((v & 0x0FFF) * 10);
    playout_delay_ = lim;
  } else if (id == ext_map.dependency_descriptor_id && len >= 4) {
    CompactDependencyExtension d;
    const uint8_t flags = p[0];
    d.is_first_in_frame = (flags & 0x80) != 0;
    d.is_last_in_frame = (flags & 0x40) != 0;
    d.is_keyframe = (flags & 0x20) != 0;
    d.discardable = (flags & 0x10) != 0;
    d.spatial_id = (flags >> 2) & 0x03;
    d.temporal_id = flags & 0x03;
    d.frame_number = ReadBigEndian16(p + 1);
    const uint8_t refs = std::min<uint8_t>(p[3], 4);
    if (len >= static_cast<size_t>(4 + refs)) {
      d.num_fdiffs = refs;
      for (uint8_t i = 0; i < refs; ++i) {
        d.fdiffs[i] = p[4 + i];
      }
      dep_ext_ = d;
    }
  }
}

bool RtpPacket::Parse(ArrayView<const uint8_t> buffer) {
  return Parse(buffer, ext_map_);
}

bool RtpPacket::Parse(ArrayView<const uint8_t> buffer,
                      const RtpHeaderExtensionMap& ext_map) {
  if (buffer.size() < kFixedHeaderSize) {
    return false;
  }
  const uint8_t* raw = buffer.data();
  const size_t size = buffer.size();

  const uint8_t version = (raw[0] >> 6) & 0x03;
  if (version != 2) {
    RTC_LOG(kVerbose) << "Dropped RTP packet with invalid version="
                      << static_cast<int>(version);
    return false;
  }
  const bool has_padding = (raw[0] & 0x20) != 0;
  const bool has_extension = (raw[0] & 0x10) != 0;
  const uint8_t csrc_count = raw[0] & 0x0F;

  ext_map_ = ext_map;
  marker_ = (raw[1] & 0x80) != 0;
  payload_type_ = raw[1] & 0x7F;
  sequence_number_ = ReadBigEndian16(raw + 2);
  timestamp_ = ReadBigEndian32(raw + 4);
  ssrc_ = ReadBigEndian32(raw + 8);

  size_t offset = kFixedHeaderSize + static_cast<size_t>(csrc_count) * 4;
  if (offset > size) {
    return false;
  }
  csrcs_.resize(csrc_count);
  for (uint8_t i = 0; i < csrc_count; ++i) {
    csrcs_[i] = ReadBigEndian32(raw + kFixedHeaderSize + static_cast<size_t>(i) * 4);
  }

  transport_seq_.reset();
  abs_send_time_.reset();
  mid_.reset();
  rid_.reset();
  rrid_.reset();
  playout_delay_.reset();
  dep_ext_.reset();

  if (has_extension) {
    if (offset + 4 > size) {
      return false;
    }
    const uint16_t profile = ReadBigEndian16(raw + offset);
    const size_t ext_len_bytes =
        static_cast<size_t>(ReadBigEndian16(raw + offset + 2)) * 4;
    offset += 4;
    if (offset + ext_len_bytes > size) {
      return false;
    }
    const uint8_t* p = raw + offset;
    const uint8_t* end = p + ext_len_bytes;
    if (profile == kOneByteExtensionProfile) {
      while (p < end) {
        if (*p == 0) {
          ++p;
          continue;
        }
        const uint8_t id = (*p >> 4) & 0x0F;
        const size_t len = static_cast<size_t>(*p & 0x0F) + 1;
        ++p;
        if (id == 15 || p + len > end) {
          break;
        }
        ParseSingleExtensionElement(id, p, len, ext_map);
        p += len;
      }
    } else if ((profile & kTwoByteExtensionProfileMask) ==
               kTwoByteExtensionProfile) {
      while (p < end) {
        if (*p == 0) {
          ++p;
          continue;
        }
        if (p + 2 > end) {
          break;
        }
        const uint8_t id = p[0];
        const size_t len = p[1];
        p += 2;
        if (p + len > end) {
          break;
        }
        ParseSingleExtensionElement(id, p, len, ext_map);
        p += len;
      }
    }
    offset += ext_len_bytes;
  }

  padding_size_ = 0;
  size_t payload_end = size;
  if (has_padding) {
    if (offset >= size) {
      return false;
    }
    const uint8_t pad_len = raw[size - 1];
    if (pad_len == 0 || offset + pad_len > size) {
      return false;
    }
    padding_size_ = pad_len;
    payload_end -= pad_len;
  }

  if (payload_end > offset) {
    payload_.assign(raw + offset, raw + payload_end);
  } else {
    payload_.clear();
  }
  raw_wire_.assign(raw, raw + size);
  return true;
}

}  // namespace rtc