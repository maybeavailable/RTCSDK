#ifndef SRC_MOQ_QUIC_CONGESTION_CONTROL_H_
#define SRC_MOQ_QUIC_CONGESTION_CONTROL_H_

// 支持热插拔的主流 QUIC 拥塞控制模块：
//   1. BbrQuicCongestionController     （Google BBRv1 拥塞控制）
//   2. Bbr2QuicCongestionController    （IETF 草案 BBRv2，支持丢包率感知与在途余量控制）
//   3. CubicQuicCongestionController   （RFC 9438 CUBIC + RFC 9406 HyStart++ 慢启动优化）
//   4. CopaQuicCongestionController    （MIT / Meta mvfst Copa 时延目标型拥塞控制）
//   5. NewRenoQuicCongestionController （RFC 9002 第 7 节 NewReno AIMD 拥塞控制）

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string_view>
#include <vector>

#include "rtc_quic_congestion_control.hpp"

namespace rtc {

// 基于单调递增虚拟轮次/时间计数器的 O(1) 三槽位（Kathleen Nichols / Van Jacobson）滑动窗口最大值滤波器。
class QuicWindowedMaxFilter {
 public:
  explicit QuicWindowedMaxFilter(uint64_t window_length)
      : window_length_(window_length) {}

  void Reset(int64_t new_sample, uint64_t new_time) {
    Sample s{new_sample, new_time};
    estimates_[0] = s;
    estimates_[1] = s;
    estimates_[2] = s;
  }

  void Update(int64_t new_sample, uint64_t new_time);

  int64_t GetBest() const { return estimates_[0].sample; }
  int64_t GetSecondBest() const { return estimates_[1].sample; }
  int64_t GetThirdBest() const { return estimates_[2].sample; }

 private:
  struct Sample {
    int64_t sample = 0;
    uint64_t time = 0;
  };

  uint64_t window_length_ = 10;
  Sample estimates_[3]{};
};

// 1. Google BBRv1（基于瓶颈带宽与往返传播时延的拥塞控制算法）。
class BbrQuicCongestionController final : public IQuicCongestionController {
 public:
  explicit BbrQuicCongestionController(size_t max_datagram_size = 1200);
  ~BbrQuicCongestionController() override = default;

  std::string_view Name() const override { return "BBRv1"; }

  void OnPacketSent(int64_t now_us,
                    uint64_t packet_number,
                    size_t bytes,
                    bool in_flight,
                    size_t prior_in_flight_bytes) override;

  void OnCongestionEvent(
      int64_t now_us,
      size_t prior_in_flight_bytes,
      size_t bytes_in_flight,
      const QuicRttSample& rtt,
      const std::vector<QuicAckedPacket>& acked_packets,
      const std::vector<QuicLostPacket>& lost_packets) override;

  void OnPersistentCongestion(int64_t now_us) override;

  size_t GetCongestionWindowBytes() const override;
  int64_t GetPacingRateBps(int64_t smoothed_rtt_us) const override;
  int64_t GetBandwidthEstimateBps() const override;
  size_t GetSlowStartThresholdBytes() const override { return ssthresh_bytes_; }

  QuicCcMigrationState ExportMigrationState() const override;
  void ImportMigrationState(const QuicCcMigrationState& state,
                            int64_t now_us) override;

 private:
  enum class Mode : uint8_t {
    kStartup = 0,
    kDrain = 1,
    kProbeBw = 2,
    kProbeRtt = 3,
  };

  size_t TargetBdpBytes(double gain) const;
  void UpdateBandwidthAndRound(const std::vector<QuicAckedPacket>& acked,
                               int64_t now_us);
  void UpdateMinRttAndProbeRtt(int64_t now_us,
                               size_t bytes_in_flight,
                               const QuicRttSample& rtt);
  void CheckStartupFullBandwidth();
  void UpdateProbeBwCycle(int64_t now_us, size_t bytes_in_flight);
  void RecalculateCwndAndPacing(size_t newly_acked_bytes,
                                size_t bytes_in_flight);

  const size_t mss_;
  Mode mode_ = Mode::kStartup;
  QuicWindowedMaxFilter max_bw_filter_{10};

  uint64_t delivered_bytes_ = 0;
  int64_t delivered_time_us_ = 0;
  uint64_t next_round_delivered_ = 0;
  uint64_t round_count_ = 0;
  bool round_start_ = false;
  bool last_sample_app_limited_ = false;

  int64_t min_rtt_us_ = 0;
  int64_t min_rtt_timestamp_us_ = 0;
  int64_t probe_rtt_done_timestamp_us_ = 0;
  bool probe_rtt_round_done_ = false;
  bool idle_restart_ = false;

  bool full_bw_reached_ = false;
  int64_t full_bw_baseline_bps_ = 0;
  uint32_t rounds_without_bw_growth_ = 0;

  size_t cycle_idx_ = 0;
  int64_t cycle_stamp_us_ = 0;
  double pacing_gain_ = 2.885;
  double cwnd_gain_ = 2.0;

  size_t cwnd_bytes_ = 0;
  size_t ssthresh_bytes_ = 8 * 1024 * 1024;
  int64_t pacing_rate_bps_ = 0;
};

// 2. IETF BBRv2（融合丢包率约束与在途字节余量模型的拥塞控制算法）。
class Bbr2QuicCongestionController final : public IQuicCongestionController {
 public:
  explicit Bbr2QuicCongestionController(size_t max_datagram_size = 1200);
  ~Bbr2QuicCongestionController() override = default;

  std::string_view Name() const override { return "BBRv2"; }

  void OnPacketSent(int64_t now_us,
                    uint64_t packet_number,
                    size_t bytes,
                    bool in_flight,
                    size_t prior_in_flight_bytes) override;

  void OnCongestionEvent(
      int64_t now_us,
      size_t prior_in_flight_bytes,
      size_t bytes_in_flight,
      const QuicRttSample& rtt,
      const std::vector<QuicAckedPacket>& acked_packets,
      const std::vector<QuicLostPacket>& lost_packets) override;

  void OnPersistentCongestion(int64_t now_us) override;

  size_t GetCongestionWindowBytes() const override;
  int64_t GetPacingRateBps(int64_t smoothed_rtt_us) const override;
  int64_t GetBandwidthEstimateBps() const override;
  size_t GetSlowStartThresholdBytes() const override { return inflight_hi_; }

  QuicCcMigrationState ExportMigrationState() const override;
  void ImportMigrationState(const QuicCcMigrationState& state,
                            int64_t now_us) override;

 private:
  enum class State : uint8_t {
    kStartup = 0,
    kDrain = 1,
    kProbeBwDown = 2,
    kProbeBwCruise = 3,
    kProbeBwRefill = 4,
    kProbeBwUp = 5,
    kProbeRtt = 6,
  };

  size_t TargetBdpBytes(double gain) const;
  size_t InflightWithHeadroom() const;
  bool IsLossTooHighInRound() const;
  void EnterProbeBwDown(int64_t now_us);
  void EnterProbeBwCruise(int64_t now_us);
  void EnterProbeBwRefill(int64_t now_us);
  void EnterProbeBwUp(int64_t now_us);

  const size_t mss_;
  State state_ = State::kStartup;
  QuicWindowedMaxFilter max_bw_filter_{10};

  uint64_t delivered_bytes_ = 0;
  int64_t delivered_time_us_ = 0;
  uint64_t next_round_delivered_ = 0;
  uint64_t round_count_ = 0;
  bool round_start_ = false;
  bool last_sample_app_limited_ = false;

  size_t round_acked_bytes_ = 0;
  size_t round_lost_bytes_ = 0;
  uint32_t round_lost_pkts_ = 0;
  size_t max_inflight_in_round_ = 0;

  int64_t bw_lo_bps_ = INT64_MAX;
  size_t inflight_hi_ = 8 * 1024 * 1024;
  size_t inflight_lo_ = 8 * 1024 * 1024;
  size_t probe_up_cnt_ = 4;
  size_t probe_up_acked_ = 0;

  bool full_bw_reached_ = false;
  int64_t full_bw_baseline_bps_ = 0;
  uint32_t rounds_without_bw_growth_ = 0;

  int64_t min_rtt_us_ = 0;
  int64_t min_rtt_stamp_us_ = 0;
  int64_t cycle_stamp_us_ = 0;
  int64_t probe_rtt_done_us_ = 0;

  double pacing_gain_ = 2.885;
  double cwnd_gain_ = 2.0;
  size_t cwnd_bytes_ = 0;
  int64_t pacing_rate_bps_ = 0;
};

// 3. RFC 9438 CUBIC + RFC 9406 HyStart++ 拥塞控制算法。
class CubicQuicCongestionController final : public IQuicCongestionController {
 public:
  explicit CubicQuicCongestionController(size_t max_datagram_size = 1200);
  ~CubicQuicCongestionController() override = default;

  std::string_view Name() const override { return "CUBIC"; }

  void OnPacketSent(int64_t now_us,
                    uint64_t packet_number,
                    size_t bytes,
                    bool in_flight,
                    size_t prior_in_flight_bytes) override;

  void OnCongestionEvent(
      int64_t now_us,
      size_t prior_in_flight_bytes,
      size_t bytes_in_flight,
      const QuicRttSample& rtt,
      const std::vector<QuicAckedPacket>& acked_packets,
      const std::vector<QuicLostPacket>& lost_packets) override;

  void OnPersistentCongestion(int64_t now_us) override;

  size_t GetCongestionWindowBytes() const override { return cwnd_bytes_; }
  int64_t GetPacingRateBps(int64_t smoothed_rtt_us) const override;
  int64_t GetBandwidthEstimateBps() const override;
  size_t GetSlowStartThresholdBytes() const override { return ssthresh_bytes_; }

  QuicCcMigrationState ExportMigrationState() const override;
  void ImportMigrationState(const QuicCcMigrationState& state,
                            int64_t now_us) override;

 private:
  bool IsCwndLimited(size_t prior_in_flight_bytes) const;
  void MaybeExitSlowStartHyStart(int64_t now_us, const QuicRttSample& rtt);
  void UpdateCubicCongestionAvoidance(size_t acked_bytes,
                                      int64_t now_us,
                                      int64_t rtt_us);

  const size_t mss_;
  size_t cwnd_bytes_ = 0;
  size_t ssthresh_bytes_ = 8 * 1024 * 1024;
  int64_t recovery_start_time_us_ = -1;

  // RFC 9438 CUBIC 状态变量（以字节和秒为单位）。
  int64_t epoch_start_us_ = -1;
  double w_max_segments_ = 0.0;
  double k_sec_ = 0.0;
  double w_est_segments_ = 0.0;
  double cwnd_frac_accum_ = 0.0;

  // RFC 9406 HyStart++ 慢启动退出检测状态变量。
  uint64_t highest_sent_pn_ = 0;
  uint64_t round_end_pn_ = 0;
  int64_t last_round_min_rtt_us_ = 0;
  int64_t curr_round_min_rtt_us_ = 0;
  uint32_t rtt_sample_count_ = 0;

  int64_t last_smoothed_rtt_us_ = 30'000;
};

// 4. MIT / Meta mvfst Copa 时延目标型拥塞控制算法。
class CopaQuicCongestionController final : public IQuicCongestionController {
 public:
  explicit CopaQuicCongestionController(size_t max_datagram_size = 1200);
  ~CopaQuicCongestionController() override = default;

  std::string_view Name() const override { return "Copa"; }

  void OnPacketSent(int64_t now_us,
                    uint64_t packet_number,
                    size_t bytes,
                    bool in_flight,
                    size_t prior_in_flight_bytes) override;

  void OnCongestionEvent(
      int64_t now_us,
      size_t prior_in_flight_bytes,
      size_t bytes_in_flight,
      const QuicRttSample& rtt,
      const std::vector<QuicAckedPacket>& acked_packets,
      const std::vector<QuicLostPacket>& lost_packets) override;

  void OnPersistentCongestion(int64_t now_us) override;

  size_t GetCongestionWindowBytes() const override { return cwnd_bytes_; }
  int64_t GetPacingRateBps(int64_t smoothed_rtt_us) const override;
  int64_t GetBandwidthEstimateBps() const override;
  size_t GetSlowStartThresholdBytes() const override {
    return in_slow_start_ ? (8 * 1024 * 1024) : cwnd_bytes_;
  }

  QuicCcMigrationState ExportMigrationState() const override;
  void ImportMigrationState(const QuicCcMigrationState& state,
                            int64_t now_us) override;

 private:
  struct TimedRtt {
    int64_t time_us = 0;
    int64_t rtt_us = 0;
  };

  int64_t ComputeStandingRttUs(int64_t now_us, int64_t window_us);

  const size_t mss_;
  size_t cwnd_bytes_ = 0;
  double cwnd_bytes_fp_ = 0.0;
  bool in_slow_start_ = true;

  int64_t base_min_rtt_us_ = 0;
  int64_t base_min_rtt_stamp_us_ = 0;
  int64_t standing_rtt_us_ = 30'000;
  std::deque<TimedRtt> rtt_samples_;

  double delta_ = 0.5;  // 均衡驻留队列长度 = 1 / delta = 2 个数据包
  int direction_ = 0;   // 窗口调整方向：+1 表示递增，-1 表示递减
  uint32_t same_direction_rounds_ = 0;
  double velocity_ = 1.0;
  uint64_t highest_sent_pn_ = 0;
  uint64_t round_end_pn_ = 0;
  size_t cwnd_at_round_start_ = 0;
  uint32_t unemptied_queue_rounds_ = 0;
};

// 5. RFC 9002 第 7 节 NewReno AIMD（加性增乘性减）拥塞控制算法。
class NewRenoQuicCongestionController final : public IQuicCongestionController {
 public:
  explicit NewRenoQuicCongestionController(size_t max_datagram_size = 1200);
  ~NewRenoQuicCongestionController() override = default;

  std::string_view Name() const override { return "NewReno"; }

  void OnPacketSent(int64_t now_us,
                    uint64_t packet_number,
                    size_t bytes,
                    bool in_flight,
                    size_t prior_in_flight_bytes) override;

  void OnCongestionEvent(
      int64_t now_us,
      size_t prior_in_flight_bytes,
      size_t bytes_in_flight,
      const QuicRttSample& rtt,
      const std::vector<QuicAckedPacket>& acked_packets,
      const std::vector<QuicLostPacket>& lost_packets) override;

  void OnPersistentCongestion(int64_t now_us) override;

  size_t GetCongestionWindowBytes() const override { return cwnd_bytes_; }
  int64_t GetPacingRateBps(int64_t smoothed_rtt_us) const override;
  int64_t GetBandwidthEstimateBps() const override;
  size_t GetSlowStartThresholdBytes() const override { return ssthresh_bytes_; }

  QuicCcMigrationState ExportMigrationState() const override;
  void ImportMigrationState(const QuicCcMigrationState& state,
                            int64_t now_us) override;

 private:
  bool IsCwndLimited(size_t prior_in_flight_bytes) const;

  const size_t mss_;
  size_t cwnd_bytes_ = 0;
  size_t ssthresh_bytes_ = 8 * 1024 * 1024;
  size_t ca_byte_accum_ = 0;
  int64_t recovery_start_time_us_ = -1;
  int64_t last_smoothed_rtt_us_ = 30'000;
};

}  // namespace rtc

#endif  // SRC_MOQ_QUIC_CONGESTION_CONTROL_H_
