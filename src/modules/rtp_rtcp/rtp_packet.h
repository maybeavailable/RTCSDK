#ifndef SRC_MODULES_RTP_RTCP_RTP_PACKET_H_
#define SRC_MODULES_RTP_RTCP_RTP_PACKET_H_

// 对标 libwebrtc/modules/rtp_rtcp/source/rtp_packet.h 与
// rtp_header_extension_map.h（支持 RFC 3550 与 RFC 8285 单字节/双字节头部扩展）。

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "api/array_view.h"
#include "api/units.h"
#include "api/video_types.h"

namespace rtc {

namespace rtp_ext_id {
constexpr uint8_t kTransportSequenceNumber = 1;
constexpr uint8_t kAbsoluteSendTime = 2;
constexpr uint8_t kRtpMid = 3;
constexpr uint8_t kRtpStreamId = 4;
constexpr uint8_t kRepairedRtpStreamId = 5;
constexpr uint8_t kPlayoutDelay = 6;
constexpr uint8_t kDependencyDescriptor = 7;
}  // namespace rtp_ext_id

// 协商后的 SDP `a=extmap:` 扩展映射表（0 表示未协商或不在报文中携带）。
struct RtpHeaderExtensionMap {
  uint8_t transport_sequence_number_id = rtp_ext_id::kTransportSequenceNumber;
  uint8_t absolute_send_time_id = rtp_ext_id::kAbsoluteSendTime;
  uint8_t mid_id = rtp_ext_id::kRtpMid;
  uint8_t rid_id = rtp_ext_id::kRtpStreamId;
  uint8_t repaired_rid_id = rtp_ext_id::kRepairedRtpStreamId;
  uint8_t playout_delay_id = rtp_ext_id::kPlayoutDelay;
  uint8_t dependency_descriptor_id = rtp_ext_id::kDependencyDescriptor;

  static RtpHeaderExtensionMap BrowserDefault() {
    RtpHeaderExtensionMap m;
    m.rid_id = 0;
    m.repaired_rid_id = 0;
    m.dependency_descriptor_id = 0;
    return m;
  }
};

struct PlayoutDelayLimits {
  uint16_t min_ms = 0;
  uint16_t max_ms = 0;
};

struct CompactDependencyExtension {
  bool is_first_in_frame = false;
  bool is_last_in_frame = false;
  bool is_keyframe = false;
  bool discardable = false;
  uint8_t spatial_id = 0;
  uint8_t temporal_id = 0;
  uint16_t frame_number = 0;
  uint8_t num_fdiffs = 0;
  uint8_t fdiffs[4]{};
};

class RtpPacket {
 public:
  static constexpr size_t kFixedHeaderSize = 12;
  static constexpr uint16_t kOneByteExtensionProfile = 0xBEDE;
  static constexpr uint16_t kTwoByteExtensionProfileMask = 0xFFF0;
  static constexpr uint16_t kTwoByteExtensionProfile = 0x1000;
  static constexpr size_t kDefaultMaxPacketSize = 1200;

  RtpPacket() = default;

  bool Parse(ArrayView<const uint8_t> buffer);
  bool Parse(ArrayView<const uint8_t> buffer,
             const RtpHeaderExtensionMap& ext_map);
  bool Parse(const uint8_t* buffer, size_t size) {
    return Parse(MakeArrayView(buffer, size));
  }

  std::vector<uint8_t> Serialize() const;
  size_t SerializeTo(uint8_t* dst, size_t capacity) const;

  void set_extension_map(const RtpHeaderExtensionMap& ext_map) {
    ext_map_ = ext_map;
  }
  const RtpHeaderExtensionMap& extension_map() const { return ext_map_; }

  bool marker() const { return marker_; }
  void set_marker(bool m) { marker_ = m; }

  uint8_t payload_type() const { return payload_type_; }
  void set_payload_type(uint8_t pt) { payload_type_ = pt & 0x7F; }

  uint16_t sequence_number() const { return sequence_number_; }
  void set_sequence_number(uint16_t seq) { sequence_number_ = seq; }

  uint32_t timestamp() const { return timestamp_; }
  void set_timestamp(uint32_t ts) { timestamp_ = ts; }

  uint32_t ssrc() const { return ssrc_; }
  void set_ssrc(uint32_t ssrc) { ssrc_ = ssrc; }

  std::optional<uint16_t> transport_sequence_number() const {
    return transport_seq_;
  }
  void set_transport_sequence_number(uint16_t seq) { transport_seq_ = seq; }

  std::optional<uint32_t> absolute_send_time() const { return abs_send_time_; }
  void SetAbsoluteSendTime(Timestamp t) {
    abs_send_time_ = ToAbsoluteSendTime24(t);
  }

  const std::optional<std::string>& mid() const { return mid_; }
  void SetMid(std::string_view mid_value);

  const std::optional<std::string>& rid() const { return rid_; }
  void SetRid(std::string_view rid_value);

  const std::optional<std::string>& repaired_rid() const { return rrid_; }
  void SetRepairedRid(std::string_view rrid_value);

  std::optional<PlayoutDelayLimits> playout_delay() const {
    return playout_delay_;
  }
  void set_playout_delay(PlayoutDelayLimits limits) { playout_delay_ = limits; }

  std::optional<CompactDependencyExtension> dependency_descriptor() const {
    return dep_ext_;
  }
  void set_dependency_descriptor(const CompactDependencyExtension& dep) {
    dep_ext_ = dep;
  }

  void CopyHeaderAndExtensionsFrom(const RtpPacket& other);

  const std::vector<uint8_t>& payload() const { return payload_; }
  std::vector<uint8_t>* mutable_payload() { return &payload_; }
  void SetPayload(ArrayView<const uint8_t> payload_bytes);
  size_t payload_size() const { return payload_.size(); }

  size_t padding_size() const { return padding_size_; }
  void set_padding_size(size_t pad_bytes) {
    padding_size_ = (pad_bytes > 255) ? 255 : pad_bytes;
  }

  size_t SerializedSize() const;

  static constexpr uint32_t ToAbsoluteSendTime24(Timestamp t) {
    const uint64_t us = static_cast<uint64_t>(t.us() >= 0 ? t.us() : 0);
    return static_cast<uint32_t>(((us << 18) / 1'000'000ULL) & 0x00FFFFFFULL);
  }

 private:
  void ParseSingleExtensionElement(uint8_t id,
                                   const uint8_t* ptr,
                                   size_t len,
                                   const RtpHeaderExtensionMap& ext_map);
  bool UsesTwoByteExtensionHeader() const;
  size_t WriteExtensions(uint8_t* dst) const;
  size_t ExtensionsContentBytes() const;

  RtpHeaderExtensionMap ext_map_{};
  bool marker_ = false;
  uint8_t payload_type_ = 96;
  uint16_t sequence_number_ = 0;
  uint32_t timestamp_ = 0;
  uint32_t ssrc_ = 0;

  std::optional<uint16_t> transport_seq_;
  std::optional<uint32_t> abs_send_time_;
  std::optional<std::string> mid_;
  std::optional<std::string> rid_;
  std::optional<std::string> rrid_;
  std::optional<PlayoutDelayLimits> playout_delay_;
  std::optional<CompactDependencyExtension> dep_ext_;

  std::vector<uint8_t> payload_;
  size_t padding_size_ = 0;
};

constexpr bool IsRtcpPacketWire(ArrayView<const uint8_t> packet) {
  if (packet.size() < 8) {
    return false;
  }
  const uint8_t version = (packet[0] >> 6) & 0x03;
  if (version != 2) {
    return false;
  }
  const uint8_t pt = packet[1];
  return pt >= 192 && pt <= 223;
}

}  // namespace rtc

#endif  // SRC_MODULES_RTP_RTCP_RTP_PACKET_H_