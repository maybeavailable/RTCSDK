#ifndef SRC_MODULES_PACING_PACING_MODULE_H_
#define SRC_MODULES_PACING_PACING_MODULE_H_

// 1:1 对标 libwebrtc/modules/pacing/ 实现：
//   - IntervalBudget（时间区间发送预算）
//   - BitrateProber（带宽码率探测器）
//   - RoundRobinPacketQueue（按流优先级轮询发包队列）
//   - PacingController（平滑发送控制器）
//   - TaskQueuePacedSender（运行于独立 PacerQueue 上的平滑发送器）

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <queue>
#include <set>
#include <utility>
#include <vector>

#include "api/network_types.h"
#include "api/units.h"
#include "modules/rtp_rtcp/rtp_packet.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"
#include "rtc_base/time_utils.h"

namespace rtc {

class IntervalBudget {
 public:
  explicit IntervalBudget(int initial_target_rate_kbps,
                          bool can_build_up_underuse = false);

  void set_target_rate_kbps(int target_rate_kbps);
  void IncreaseBudget(int64_t delta_time_ms);
  void IncreaseBudgetUs(int64_t delta_time_us);
  void UseBudget(size_t bytes);

  size_t bytes_remaining() const;
  double budget_ratio() const;
  int target_rate_kbps() const { return target_rate_kbps_; }

 private:
  int target_rate_kbps_ = 0;
  int64_t max_bytes_in_budget_ = 0;
  int64_t bytes_remaining_ = 0;
  int64_t sub_byte_kbps_us_rem_ = 0;
  bool can_build_up_underuse_ = false;
};

class BitrateProber {
 public:
  BitrateProber() = default;

  BitrateProber(const BitrateProber&) = delete;
  BitrateProber& operator=(const BitrateProber&) = delete;

  void SetEnabled(bool enable);
  bool is_probing() const { return probing_state_ == ProbingState::kActive; }

  void OnIncomingPacket(DataSize packet_size);
  void CreateProbeCluster(const ProbeClusterConfig& cluster_config);

  Timestamp NextProbeTime(Timestamp now) const;
  std::optional<PacedPacketInfo> CurrentCluster(Timestamp now);
  size_t RecommendedMinProbeSize() const;
  void ProbeSent(Timestamp now, DataSize size);
  void PauseUntilIncomingPacket();

 private:
  enum class ProbingState {
    kDisabled,
    kInactive,
    kActive,
  };

  struct ProbeCluster {
    PacedPacketInfo pace_info;
    int sent_probes = 0;
    int sent_bytes = 0;
    Timestamp requested_at = Timestamp::MinusInfinity();
    Timestamp started_at = Timestamp::MinusInfinity();
  };

  Timestamp CalculateNextProbeTime(const ProbeCluster& cluster) const;

  ProbingState probing_state_ = ProbingState::kInactive;
  std::queue<ProbeCluster> clusters_;
  Timestamp next_probe_time_ = Timestamp::PlusInfinity();
};

class RoundRobinPacketQueue {
 public:
  struct QueuedPacket {
    RtpPacketMediaType type = RtpPacketMediaType::kVideoDelta;
    Timestamp enqueue_time = Timestamp::MinusInfinity();
    uint64_t enqueue_order = 0;
    std::unique_ptr<RtpPacket> packet;
  };

  explicit RoundRobinPacketQueue(Timestamp start_time);

  RoundRobinPacketQueue(const RoundRobinPacketQueue&) = delete;
  RoundRobinPacketQueue& operator=(const RoundRobinPacketQueue&) = delete;

  void Push(RtpPacketMediaType type,
            Timestamp enqueue_time,
            std::unique_ptr<RtpPacket> packet);
  QueuedPacket Pop();

  bool Empty() const { return size_packets_ == 0; }
  size_t SizeInPackets() const { return size_packets_; }
  DataSize SizeData() const { return size_data_; }

  Timestamp OldestEnqueueTime() const;
  TimeDelta AverageQueueTime() const;
  void UpdateQueueTime(Timestamp now);
  void Clear(Timestamp now);
  void PurgeStalePacketsForKeyframe(Timestamp now,
                                    uint32_t keyframe_ssrc,
                                    uint32_t keyframe_rtp_ts);

 private:
  struct StreamPrioKey {
    RtpPacketMediaType priority;
    DataSize accumulated_size;
    uint32_t ssrc;

    bool operator<(const StreamPrioKey& other) const {
      if (priority != other.priority) {
        return static_cast<int>(priority) > static_cast<int>(other.priority);
      }
      if (accumulated_size != other.accumulated_size) {
        return accumulated_size > other.accumulated_size;
      }
      return ssrc > other.ssrc;
    }
  };

  struct Stream {
    DataSize size = DataSize::Zero();
    uint32_t ssrc = 0;
    std::priority_queue<QueuedPacket,
                        std::vector<QueuedPacket>,
                        bool (*)(const QueuedPacket&, const QueuedPacket&)>
        packet_queue;
    bool in_prio_queue = false;

    Stream();
  };

  uint64_t enqueue_count_ = 0;
  size_t size_packets_ = 0;
  DataSize size_data_ = DataSize::Zero();
  DataSize max_size_ = DataSize::Zero();

  Timestamp time_last_updated_;
  TimeDelta queue_time_sum_ = TimeDelta::Zero();

  std::multiset<Timestamp> enqueue_times_;
  std::map<uint32_t, Stream> streams_;
  std::priority_queue<StreamPrioKey> stream_priorities_;
};

class PacingPacketSender {
 public:
  virtual ~PacingPacketSender() = default;

  virtual void SendPacedPacket(std::unique_ptr<RtpPacket> packet,
                               const PacedPacketInfo& cluster_info) = 0;
  virtual std::vector<std::unique_ptr<RtpPacket>> GeneratePadding(
      DataSize target_size) = 0;
};

class PacingController {
 public:
  static constexpr TimeDelta kMaxEarlyProbeProcessing = TimeDelta::Millis(1);
  static constexpr TimeDelta kMinSleepTime = TimeDelta::Millis(1);
  static constexpr TimeDelta kMaxElapsedTime = TimeDelta::Seconds(2);

  PacingController(Clock* clock, PacingPacketSender* packet_sender);

  PacingController(const PacingController&) = delete;
  PacingController& operator=(const PacingController&) = delete;

  void CreateProbeClusters(
      const std::vector<ProbeClusterConfig>& probe_cluster_configs);
  void SetPacingRates(DataRate pacing_rate, DataRate padding_rate);
  void SetCongestionWindow(DataSize congestion_window_size);
  void UpdateOutstandingData(DataSize outstanding_data);
  void set_queue_time_limit(TimeDelta limit) { queue_time_limit_ = limit; }

  void EnqueuePacket(std::unique_ptr<RtpPacket> packet,
                     RtpPacketMediaType type);

  Timestamp NextSendTime() const;
  void ProcessPackets();

  size_t QueueSizePackets() const { return packet_queue_.SizeInPackets(); }
  DataSize QueueSizeData() const { return packet_queue_.SizeData(); }
  TimeDelta ExpectedQueueTime() const;

 private:
  TimeDelta UpdateTimeAndGetElapsed(Timestamp now);
  void UpdateBudgetWithElapsedTime(TimeDelta delta);
  void UpdateBudgetWithSentData(DataSize size);
  bool Congested() const;
  std::unique_ptr<RtpPacket> GetPendingPacket(
      const PacedPacketInfo& pacing_info);

  Clock* const clock_;
  PacingPacketSender* const packet_sender_;

  Timestamp last_process_time_;
  Timestamp last_send_time_ = Timestamp::MinusInfinity();
  mutable RoundRobinPacketQueue packet_queue_;
  // 有符号字节债务：> 0 表示等待排空发送债务；< 0 仅在队列有待发包时保留受限的定时器抖动结余（队列为空时截断为 >= 0）。
  int64_t media_debt_bytes_ = 0;
  DataSize padding_debt_ = DataSize::Zero();
  int64_t media_debt_subbyte_rem_ = 0;
  int64_t padding_debt_subbyte_rem_ = 0;
  BitrateProber prober_;

  DataRate pacing_rate_ = DataRate::KilobitsPerSec(1500);
  DataRate adjusted_media_rate_ = DataRate::KilobitsPerSec(1500);
  DataRate padding_rate_ = DataRate::Zero();

  DataSize congestion_window_size_ = DataSize::Infinity();
  DataSize outstanding_data_ = DataSize::Zero();
  TimeDelta queue_time_limit_ = TimeDelta::Millis(500);
  bool drain_large_queues_ = true;
};

class TaskQueuePacedSender {
 public:
  TaskQueuePacedSender(Clock* clock,
                       PacingPacketSender* packet_sender,
                       TaskQueueBoost* pacer_queue);
  ~TaskQueuePacedSender();

  TaskQueuePacedSender(const TaskQueuePacedSender&) = delete;
  TaskQueuePacedSender& operator=(const TaskQueuePacedSender&) = delete;

  void EnsureStarted();
  void SetPacingRates(DataRate pacing_rate, DataRate padding_rate);
  void CreateProbeClusters(std::vector<ProbeClusterConfig> clusters);
  void SetCongestionWindow(DataSize cwnd);
  void UpdateOutstandingData(DataSize in_flight);

  void EnqueuePackets(
      std::vector<std::pair<RtpPacketMediaType, std::unique_ptr<RtpPacket>>>
          packets);

 private:
  void MaybeProcessPackets(Timestamp scheduled_process_time);

  Clock* const clock_;
  TaskQueueBoost* const pacer_queue_;
  SequenceChecker pacer_checker_;
  PacingController pacing_controller_;
  boost::asio::steady_timer process_timer_;
  Timestamp next_process_time_ = Timestamp::MinusInfinity();
  ScopedTaskSafety safety_;
};

}  // namespace rtc

#endif  // SRC_MODULES_PACING_PACING_MODULE_H_
