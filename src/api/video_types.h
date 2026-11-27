#ifndef SRC_API_VIDEO_TYPES_H_
#define SRC_API_VIDEO_TYPES_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "api/units.h"
#include "rtc_video_types.hpp"

namespace rtc {

constexpr size_t kMaxFrameReferences = 5;
constexpr uint32_t kVideoPayloadClockHz = 90'000;

enum class VideoCodec {
  kH264 = RTC_CODEC_H264,
  kH265 = RTC_CODEC_H265,
};

enum class SpatialLayer : uint8_t {
  kLow = RTC_STREAM_LAYER_LOW,
  kHigh = RTC_STREAM_LAYER_HIGH,
};

// 对标 libwebrtc GenericFrameInfo / DependencyDescriptor 的紧凑帧依赖元数据，
// 在 WebRTC RTP 与 MoQ 两种传输模式间采用完全一致的结构共享。
struct FrameDependencyMetadata {
  int64_t frame_id = -1;
  uint16_t picture_id = 0;
  uint8_t spatial_id = 0;
  uint8_t temporal_id = 0;
  bool is_keyframe = false;
  bool discardable = false;
  size_t num_references = 0;
  std::array<int64_t, kMaxFrameReferences> references{};
};

struct EncodedVideoFrame {
  std::vector<uint8_t> data;
  Timestamp capture_time = Timestamp::MinusInfinity();
  uint32_t rtp_timestamp = 0;
  VideoCodec codec = VideoCodec::kH264;
  SpatialLayer layer = SpatialLayer::kHigh;
  FrameDependencyMetadata dep;
};

struct LayerAllocation {
  bool active = false;
  uint32_t target_bitrate_bps = 0;
  uint32_t target_fps = 30;
};

struct VideoBitrateAllocation {
  LayerAllocation layers[2];  // 空间层码率分配：[0] 为 kLow 低清层，[1] 为 kHigh 高清层

  uint32_t TotalBitrateBps() const {
    uint32_t sum = 0;
    for (const auto& layer_alloc : layers) {
      if (layer_alloc.active) {
        sum += layer_alloc.target_bitrate_bps;
      }
    }
    return sum;
  }
};

constexpr uint32_t MicrosToRtp90kHzU64(uint64_t ts_us) {
  return static_cast<uint32_t>(
      ((ts_us / 1000ULL) * 90ULL + ((ts_us % 1000ULL) * 90ULL) / 1000ULL) &
      0xFFFFFFFFULL);
}

constexpr uint32_t MicrosToRtp90kHz(int64_t ts_us) {
  return ts_us <= 0 ? 0u : MicrosToRtp90kHzU64(static_cast<uint64_t>(ts_us));
}

}  // namespace rtc

#endif  // SRC_API_VIDEO_TYPES_H_
