#ifndef SRC_MODULES_VIDEO_CODING_VIDEO_CODING_MODULE_H_
#define SRC_MODULES_VIDEO_CODING_VIDEO_CODING_MODULE_H_

// 1:1 对标 libwebrtc/modules/video_coding/ 实现：
//   1. PacketBuffer（RTP 视频包重组缓冲区）
//   2. NackModule2（NACK 丢包检测与重传调度模块）
//   3. RtpFrameReferenceFinder（RTP 视频帧参考关系解析器）
//   4. DecodedFramesHistory（已解码帧历史记录）+ FrameBuffer3（可解码帧调度缓冲区）
//   5. VCMJitterEstimator（卡尔曼滤波抖动估计器）+ VCMTiming（视频渲染时序控制器）
//   6. SimulcastRateAllocator（Simulcast 多流空间层码率分配器）

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <vector>

#include "api/units.h"
#include "api/video_types.h"
#include "modules/rtp_rtcp/rtp_packet.h"
#include "modules/rtp_rtcp/rtp_video_packetizer.h"
#include "rtc_base/seq_num_unwrapper.h"
#include "rtc_base/timestamp_extrapolator.h"

namespace rtc {

struct AssembledRtpFrame {
  uint16_t first_seq_num = 0;
  uint16_t last_seq_num = 0;
  uint32_t rtp_timestamp = 0;
  Timestamp received_time = Timestamp::MinusInfinity();
  VideoCodec codec = VideoCodec::kH264;
  bool is_keyframe = false;
  std::optional<PlayoutDelayLimits> playout_delay;
  std::optional<CompactDependencyExtension> dependency_ext;
  FrameDependencyMetadata dep;
  std::vector<uint8_t> annexb_bitstream;
};

class PacketBuffer {
 public:
  explicit PacketBuffer(VideoCodec codec,
                        size_t start_size = 512,
                        size_t max_size = 2048);

  PacketBuffer(const PacketBuffer&) = delete;
  PacketBuffer& operator=(const PacketBuffer&) = delete;

  std::vector<AssembledRtpFrame> InsertPacket(const RtpPacket& packet,
                                              Timestamp receive_time);
  void ClearTo(uint16_t seq_num);
  void Clear();

 private:
  struct Slot {
    bool used = false;
    bool continuous = false;
    uint16_t seq_num = 0;
    uint32_t rtp_ts = 0;
    bool is_first_in_frame = false;
    bool is_last_in_frame = false;
    bool is_keyframe = false;
    bool is_fu = false;
    bool is_fu_start = false;
    bool is_fu_end = false;
    uint8_t nalu_type = 0;
    bool has_sps = false;
    bool has_pps = false;
    bool has_vps = false;
    Timestamp receive_time = Timestamp::MinusInfinity();
    std::optional<PlayoutDelayLimits> playout_delay;
    std::optional<CompactDependencyExtension> dep_ext;
    std::vector<uint8_t> annexb_chunk;
  };

  struct AssembledSpan {
    uint16_t first_seq = 0;
    uint16_t last_seq = 0;
    uint32_t rtp_ts = 0;
  };

  static bool AreAdjacentSlotsCompatible(const Slot& prev, const Slot& cur);
  bool PotentialNewFrame(uint16_t seq_num) const;
  std::vector<AssembledRtpFrame> FindFrames(uint16_t seq_num);
  void ExpandBufferSize();

  const VideoCodec codec_;
  const size_t max_size_;
  std::vector<Slot> buffer_;
  bool first_packet_received_ = false;
  bool is_cleared_to_first_seq_num_ = false;
  uint16_t first_seq_num_ = 0;
  std::optional<uint16_t> last_assembled_end_seq_;
  std::deque<AssembledSpan> recently_assembled_;
};

class NackModule2 {
 public:
  static constexpr size_t kMaxNackPackets = 512;
  static constexpr int kMaxNackRetries = 10;

  NackModule2();

  NackModule2(const NackModule2&) = delete;
  NackModule2& operator=(const NackModule2&) = delete;

  void UpdateRtt(TimeDelta rtt);
  std::vector<uint16_t> OnReceivedPacket(uint16_t seq_num,
                                         bool is_keyframe,
                                         bool is_recovered,
                                         Timestamp now,
                                         bool* out_keyframe_requested);
  std::vector<uint16_t> ProcessNacks(Timestamp now,
                                     bool* out_keyframe_requested);
  void ClearUpTo(uint16_t seq_num);
  size_t PendingNackCount() const { return nack_list_.size(); }

 private:
  struct NackInfo {
    uint16_t seq_num = 0;
    uint16_t send_at_seq_num = 0;
    Timestamp created_time = Timestamp::MinusInfinity();
    Timestamp sent_time = Timestamp::MinusInfinity();
    int retries = 0;
  };

  void RecordReorderingDistance(uint16_t distance);
  uint16_t WaitNumberOfPackets(double probability) const;
  void ClearUpToUnwrapped(int64_t target_unwrapped_seq);

  bool initialized_ = false;
  uint16_t newest_seq_num_ = 0;
  int64_t newest_unwrapped_seq_ = 0;
  RtpSeqUnwrapper seq_unwrapper_;
  TimeDelta rtt_ = TimeDelta::Millis(60);
  std::map<int64_t, NackInfo> nack_list_;
  std::deque<int64_t> keyframe_list_;
  std::vector<int> reordering_histogram_;
  size_t total_reordered_samples_ = 0;
};

class RtpFrameReferenceFinder {
 public:
  RtpFrameReferenceFinder() = default;

  RtpFrameReferenceFinder(const RtpFrameReferenceFinder&) = delete;
  RtpFrameReferenceFinder& operator=(const RtpFrameReferenceFinder&) = delete;

  std::vector<AssembledRtpFrame> ManageFrame(AssembledRtpFrame frame);
  bool HasStalledFrames(Timestamp now, TimeDelta max_wait) const;
  void ClearTo(uint16_t seq_num);

 private:
  enum class Decision { kStash, kHandOff, kDrop };
  Decision ResolveFrame(AssembledRtpFrame* frame);

  RtpSeqUnwrapper frame_num_unwrapper_;
  int64_t synthetic_frame_id_ = 0;
  std::optional<int64_t> first_keyframe_id_;
  std::optional<int64_t> last_keyframe_id_;
  std::optional<int64_t> last_base_layer_frame_id_;
  std::optional<uint16_t> last_unwrapped_seq_end_;
  std::deque<int64_t> recent_dd_frame_ids_;
  std::deque<AssembledRtpFrame> stashed_frames_;
};

class DecodedFramesHistory {
 public:
  explicit DecodedFramesHistory(size_t window_size = 1024);

  void InsertDecoded(int64_t frame_id, uint32_t rtp_timestamp);
  bool WasDecoded(int64_t frame_id) const;
  void Clear();

 private:
  const size_t window_size_;
  std::vector<bool> buffer_;
  std::optional<int64_t> last_frame_id_;
  std::optional<uint32_t> last_decoded_timestamp_;
};

class VCMJitterEstimator {
 public:
  VCMJitterEstimator();

  void Reset();
  void UpdateEstimate(TimeDelta frame_delay_delta,
                      DataSize frame_size_delta,
                      DataSize current_frame_size,
                      bool incomplete_frame = false);
  void FrameNacked() { nack_count_ = std::min(nack_count_ + 1, 5); }
  TimeDelta GetJitterEstimate(double rtt_multiplier, TimeDelta rtt) const;

 private:
  double theta_[2];
  double theta_cov_[2][2];
  double q_cov_[2][2];
  double avg_frame_size_bytes_ = 500.0;
  double var_frame_size_bytes2_ = 100.0;
  double max_frame_size_bytes_ = 500.0;
  double avg_noise_ms_ = 0.0;
  double var_noise_ms2_ = 4.0;
  uint32_t startup_count_ = 0;
  int nack_count_ = 0;
};

class VCMTiming {
 public:
  explicit VCMTiming(Timestamp start_time, bool zero_playout_delay = false);

  void Reset(Timestamp now);
  void SetJitterDelay(TimeDelta jitter_delay);
  void SetPlayoutDelay(PlayoutDelayLimits limits);
  void IncomingTimestamp(uint32_t rtp_timestamp, Timestamp now);

  Timestamp RenderTime(uint32_t frame_timestamp, Timestamp now) const;
  TimeDelta MaxWaitingTime(Timestamp render_time, Timestamp now) const;
  TimeDelta TargetVideoDelay() const;

 private:
  TimestampExtrapolator ts_extrapolator_;
  bool zero_playout_delay_ = false;
  TimeDelta jitter_delay_ = TimeDelta::Millis(20);
  TimeDelta min_playout_delay_ = TimeDelta::Zero();
  TimeDelta max_playout_delay_ = TimeDelta::Millis(1000);
  TimeDelta estimated_decode_time_ = TimeDelta::Millis(5);
};

class FrameBuffer3 {
 public:
  explicit FrameBuffer3(size_t max_size = 256);

  FrameBuffer3(const FrameBuffer3&) = delete;
  FrameBuffer3& operator=(const FrameBuffer3&) = delete;

  void InsertFrame(AssembledRtpFrame frame);

  std::optional<AssembledRtpFrame> ExtractNextDecodableFrame();
  std::optional<uint32_t> NextDecodableRtpTimestamp() const;
  bool HasContinuousKeyframe() const;
  bool IsCorruptedOrStalled(Timestamp now, TimeDelta max_wait) const;
  size_t Size() const { return frames_.size(); }
  void Clear();

 private:
  bool AllReferencesDecoded(const AssembledRtpFrame& f) const;

  const size_t max_size_;
  std::map<int64_t, AssembledRtpFrame> frames_;
  DecodedFramesHistory decoded_history_;
  std::optional<int64_t> last_decoded_frame_id_;
  Timestamp oldest_undecodable_since_ = Timestamp::MinusInfinity();
};

struct SimulcastAllocatorConfig {
  bool enable_simulcast = true;
  uint32_t min_total_bps = 150'000;
  uint32_t low_min_bps = 120'000;
  uint32_t low_max_bps = 450'000;
  uint32_t high_min_bps = 400'000;
  uint32_t high_hysteresis_bps = 80'000;
  uint32_t max_total_bps = 6'000'000;
};

class SimulcastRateAllocator {
 public:
  explicit SimulcastRateAllocator(const SimulcastAllocatorConfig& cfg);

  VideoBitrateAllocation Allocate(DataRate total_target_rate,
                                  double protection_overhead_ratio);

 private:
  SimulcastAllocatorConfig cfg_;
  bool high_was_active_ = false;
};

}  // namespace rtc

#endif  // SRC_MODULES_VIDEO_CODING_VIDEO_CODING_MODULE_H_
