#ifndef SRC_MODULES_RTP_RTCP_RTP_VIDEO_PACKETIZER_H_
#define SRC_MODULES_RTP_RTCP_RTP_VIDEO_PACKETIZER_H_

// 对标 libwebrtc/modules/rtp_rtcp/source/rtp_format_h264.h 与
// rtp_format_h265.h（遵循 RFC 6184 H.264 与 RFC 7798 H.265/HEVC 打包规范）。

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "api/array_view.h"
#include "api/video_types.h"

namespace rtc {

std::vector<ArrayView<const uint8_t>> ParseAnnexBNalus(
    ArrayView<const uint8_t> bitstream);

struct PacketizedPayload {
  std::vector<uint8_t> bytes;
  bool is_first_in_frame = false;
  bool is_last_in_frame = false;
};

struct DepacketizedUnit {
  std::vector<uint8_t> annexb_bytes;
  bool is_first_in_frame = false;
  bool is_keyframe = false;
  bool is_fu = false;
  bool is_fu_start = false;
  bool is_fu_end = false;
  uint8_t nalu_type = 0;
  bool has_sps = false;
  bool has_pps = false;
  bool has_vps = false;
};

class H264Packetizer {
 public:
  explicit H264Packetizer(size_t max_payload_len = 1160);

  std::vector<PacketizedPayload> PacketizeAnnexB(
      ArrayView<const uint8_t> bitstream,
      bool* out_is_keyframe = nullptr);

 private:
  size_t max_payload_len_;
  std::vector<uint8_t> cached_sps_;
  std::vector<uint8_t> cached_pps_;
};

class H264Depacketizer {
 public:
  static std::optional<DepacketizedUnit> ParsePayload(
      ArrayView<const uint8_t> payload);
};

class H265Packetizer {
 public:
  explicit H265Packetizer(size_t max_payload_len = 1160);

  std::vector<PacketizedPayload> PacketizeAnnexB(
      ArrayView<const uint8_t> bitstream,
      bool* out_is_keyframe = nullptr);

 private:
  size_t max_payload_len_;
  std::vector<uint8_t> cached_vps_;
  std::vector<uint8_t> cached_sps_;
  std::vector<uint8_t> cached_pps_;
};

class H265Depacketizer {
 public:
  static std::optional<DepacketizedUnit> ParsePayload(
      ArrayView<const uint8_t> payload);
};

}  // namespace rtc

#endif  // SRC_MODULES_RTP_RTCP_RTP_VIDEO_PACKETIZER_H_
