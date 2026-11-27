#include "moq/quic_congestion_control.h"

#include <algorithm>
#include <cmath>
#include <limits>

#include "rtc_base/logging.h"

namespace rtc {

namespace {

constexpr size_t kMaxCwndBytes = 8 * 1024 * 1024;
constexpr int64_t kRtpropExpiryUs = 10'000'000;
constexpr int64_t kProbeRttDurationUs = 200'000;
constexpr double kBbrHighGain = 2.88539008178;  // 高增益系数 2 / ln(2)
constexpr double kBbrDrainGain = 1.0 / kBbrHighGain;
constexpr double kBbrPacingGainCycle[8] = {1.25, 0.75, 1.0, 1.0,
                                           1.0,  1.0,  1.0, 1.0};

int64_t ComputeRateBpsFromCwnd(size_t cwnd_bytes,
                               int64_t rtt_us,
                               double gain = 1.0) {
  const int64_t safe_rtt_us = std::max<int64_t>(1000, rtt_us);
  const double bps =
      (static_cast<double>(cwnd_bytes) * 8'000'000.0 * gain) /
      static_cast<double>(safe_rtt_us);
  return std::max<int64_t>(100'000, static_cast<int64_t>(bps));
}

class BuiltinQuicCcFactory final : public IQuicCongestionControllerFactory {
 public:
  explicit BuiltinQuicCcFactory(rtc_quic_cc_algo_e algo) : algo_(algo) {}

  std::unique_ptr<IQuicCongestionController> Create(
      size_t max_datagram_size) override {
    return CreateBuiltinQuicCongestionController(algo_, max_datagram_size);
  }

 private:
  rtc_quic_cc_algo_e algo_;
};

}  // namespace

// ======================= QuicWindowedMaxFilter 滑动窗口最大值滤波器 =======================

void QuicWindowedMaxFilter::Update(int64_t new_sample, uint64_t new_time) {
  if (estimates_[0].sample == 0 || new_sample >= estimates_[0].sample ||
      new_time - estimates_[2].time > window_length_) {
    Reset(new_sample, new_time);
    return;
  }

  if (new_sample >= estimates_[1].sample) {
    estimates_[1] = Sample{new_sample, new_time};
    estimates_[2] = estimates_[1];
  } else if (new_sample >= estimates_[2].sample) {
    estimates_[2] = Sample{new_sample, new_time};
  }

  if (new_time - estimates_[0].time > window_length_) {
    estimates_[0] = estimates_[1];
    estimates_[1] = estimates_[2];
    estimates_[2] = Sample{new_sample, new_time};
    if (new_time - estimates_[0].time > window_length_) {
      estimates_[0] = estimates_[1];
      estimates_[1] = estimates_[2];
    }
    return;
  }

  if (estimates_[1].sample == estimates_[0].sample &&
      new_time - estimates_[1].time > window_length_ / 4) {
    estimates_[2] = Sample{new_sample, new_time};
    estimates_[1] = estimates_[2];
    return;
  }

  if (estimates_[2].sample == estimates_[1].sample &&
      new_time - estimates_[2].time > window_length_ / 2) {
    estimates_[2] = Sample{new_sample, new_time};
  }
}

// ======================= 1. BBRv1 拥塞控制算法 =======================

BbrQuicCongestionController::BbrQuicCongestionController(
    size_t max_datagram_size)
    : mss_(std::max<size_t>(512, max_datagram_size)),
      cwnd_bytes_(10 * mss_) {}

void BbrQuicCongestionController::OnPacketSent(int64_t /*now_us*/,
                                               uint64_t /*packet_number*/,
                                               size_t /*bytes*/,
                                               bool in_flight,
                                               size_t prior_in_flight_bytes) {
  if (!in_flight) {
    return;
  }
  if (prior_in_flight_bytes == 0 && mode_ == Mode::kProbeBw) {
    idle_restart_ = true;
    pacing_gain_ = 1.0;
  }
}

size_t BbrQuicCongestionController::TargetBdpBytes(double gain) const {
  const int64_t bw_bps = max_bw_filter_.GetBest();
  if (bw_bps <= 0 || min_rtt_us_ <= 0) {
    return static_cast<size_t>(10.0 * static_cast<double>(mss_) *
                               std::max(1.0, gain * 0.5));
  }
  const double bytes =
      (static_cast<double>(bw_bps) * static_cast<double>(min_rtt_us_) * gain) /
      8'000'000.0;
  const size_t min_bdp = (bw_bps < 250'000) ? (2 * mss_) : (4 * mss_);
  return std::clamp<size_t>(static_cast<size_t>(bytes), min_bdp,
                            kMaxCwndBytes);
}

void BbrQuicCongestionController::UpdateBandwidthAndRound(
    const std::vector<QuicAckedPacket>& acked,
    int64_t now_us) {
  round_start_ = false;
  for (const auto& pkt : acked) {
    if (delivered_bytes_ < pkt.delivered_bytes_at_send) {
      delivered_bytes_ = pkt.delivered_bytes_at_send;
      next_round_delivered_ = delivered_bytes_;
    }
    delivered_bytes_ += pkt.bytes;
    delivered_time_us_ = now_us;

    if (pkt.delivered_bytes_at_send >= next_round_delivered_) {
      next_round_delivered_ = delivered_bytes_;
      ++round_count_;
      round_start_ = true;
    }

    const int64_t send_elapsed_us =
        pkt.sent_time_us - pkt.first_sent_time_us_at_send;
    const int64_t ack_elapsed_us = now_us - pkt.delivered_time_us_at_send;
    const int64_t interval_us = std::max(send_elapsed_us, ack_elapsed_us);
    if (interval_us <= 0 || delivered_bytes_ <= pkt.delivered_bytes_at_send) {
      continue;
    }

    const uint64_t bytes_delivered =
        delivered_bytes_ - pkt.delivered_bytes_at_send;
    const int64_t sample_bps = static_cast<int64_t>(
        (static_cast<double>(bytes_delivered) * 8'000'000.0) /
        static_cast<double>(interval_us));
    last_sample_app_limited_ = pkt.is_app_limited;

    if (!pkt.is_app_limited || sample_bps > max_bw_filter_.GetBest()) {
      max_bw_filter_.Update(sample_bps, round_count_);
    }
  }
}

void BbrQuicCongestionController::CheckStartupFullBandwidth() {
  if (full_bw_reached_ || !round_start_ || last_sample_app_limited_) {
    return;
  }
  const int64_t bw = max_bw_filter_.GetBest();
  if (bw <= 0) {
    return;
  }
  if (static_cast<double>(bw) >=
      static_cast<double>(full_bw_baseline_bps_) * 1.25) {
    full_bw_baseline_bps_ = bw;
    rounds_without_bw_growth_ = 0;
    return;
  }
  ++rounds_without_bw_growth_;
  if (rounds_without_bw_growth_ >= 3) {
    full_bw_reached_ = true;
    ssthresh_bytes_ = TargetBdpBytes(2.0);
  }
}

void BbrQuicCongestionController::UpdateProbeBwCycle(int64_t now_us,
                                                     size_t bytes_in_flight) {
  if (mode_ != Mode::kProbeBw || idle_restart_) {
    idle_restart_ = false;
    return;
  }
  const int64_t phase_elapsed_us = now_us - cycle_stamp_us_;
  const int64_t rtt_ref_us = std::max<int64_t>(4000, min_rtt_us_);
  bool should_advance = (phase_elapsed_us > rtt_ref_us);
  if (pacing_gain_ > 1.0) {
    should_advance =
        (phase_elapsed_us > rtt_ref_us) &&
        (bytes_in_flight >= TargetBdpBytes(pacing_gain_) ||
         phase_elapsed_us > 2 * rtt_ref_us);
  } else if (pacing_gain_ < 1.0 && bytes_in_flight <= TargetBdpBytes(1.0)) {
    should_advance = true;
  }

  if (should_advance) {
    cycle_idx_ = (cycle_idx_ + 1) % 8;
    cycle_stamp_us_ = now_us;
    pacing_gain_ = kBbrPacingGainCycle[cycle_idx_];
  }
}

void BbrQuicCongestionController::UpdateMinRttAndProbeRtt(
    int64_t now_us,
    size_t bytes_in_flight,
    const QuicRttSample& rtt) {
  const int64_t sample_rtt =
      (rtt.latest_rtt_us > 0) ? rtt.latest_rtt_us : rtt.smoothed_rtt_us;
  const bool expired =
      (min_rtt_us_ > 0) && (now_us > min_rtt_timestamp_us_ + kRtpropExpiryUs);
  if (sample_rtt > 0 && (min_rtt_us_ == 0 || sample_rtt <= min_rtt_us_ ||
                         expired)) {
    min_rtt_us_ = sample_rtt;
    min_rtt_timestamp_us_ = now_us;
  } else if (!full_bw_reached_ && min_rtt_us_ > 0 &&
             delivered_bytes_ >= 4 * mss_ &&
             sample_rtt > min_rtt_us_ * 2 + 30'000) {
    // 遵循 IETF BBR 延迟膨胀早退准则：在超窄带链路上若排队 RTT 翻倍则提前退出 Startup 进入 Drain，防止冲爆浅缓冲。
    full_bw_reached_ = true;
    ssthresh_bytes_ = TargetBdpBytes(1.5);
  }

  if (mode_ != Mode::kProbeRtt && expired && full_bw_reached_) {
    mode_ = Mode::kProbeRtt;
    pacing_gain_ = 1.0;
    probe_rtt_done_timestamp_us_ = 0;
    probe_rtt_round_done_ = false;
  }

  if (mode_ == Mode::kProbeRtt) {
    if (probe_rtt_done_timestamp_us_ == 0 &&
        bytes_in_flight <= 4 * mss_ + mss_) {
      probe_rtt_done_timestamp_us_ =
          now_us + std::max(kProbeRttDurationUs, sample_rtt);
      probe_rtt_round_done_ = false;
      next_round_delivered_ = delivered_bytes_;
    } else if (probe_rtt_done_timestamp_us_ != 0) {
      if (round_start_) {
        probe_rtt_round_done_ = true;
      }
      if (probe_rtt_round_done_ && now_us >= probe_rtt_done_timestamp_us_) {
        min_rtt_timestamp_us_ = now_us;
        if (full_bw_reached_) {
          mode_ = Mode::kProbeBw;
          cycle_idx_ = 2;
          cycle_stamp_us_ = now_us;
          pacing_gain_ = 1.0;
          cwnd_gain_ = 2.0;
        } else {
          mode_ = Mode::kStartup;
          pacing_gain_ = kBbrHighGain;
          cwnd_gain_ = 2.0;
        }
      }
    }
  }
}

void BbrQuicCongestionController::RecalculateCwndAndPacing(
    size_t newly_acked_bytes,
    size_t /*bytes_in_flight*/) {
  const int64_t bw_bps = max_bw_filter_.GetBest();
  const int64_t init_pacing_bps = ComputeRateBpsFromCwnd(
      10 * mss_, min_rtt_us_ > 0 ? min_rtt_us_ : 30'000, kBbrHighGain);
  if (bw_bps > 0) {
    const double scaled = std::clamp(
        static_cast<double>(bw_bps) * pacing_gain_, 0.0, 1.0e12);
    const int64_t candidate_bps = static_cast<int64_t>(scaled);
    if (full_bw_reached_) {
      pacing_rate_bps_ = std::max<int64_t>(100'000, candidate_bps);
    } else {
      // 在 Startup 填满瓶颈前，防止微小的应用受限控制帧将初始平滑发送速率拉低。
      pacing_rate_bps_ =
          std::max({pacing_rate_bps_, init_pacing_bps, candidate_bps});
    }
  }

  if (mode_ == Mode::kProbeRtt) {
    cwnd_bytes_ = 4 * mss_;
    return;
  }

  const size_t min_cwnd = (bw_bps > 0 && bw_bps < 250'000) ? (2 * mss_) : (4 * mss_);
  const size_t target_cwnd =
      TargetBdpBytes(cwnd_gain_) + ((bw_bps > 0 && bw_bps < 250'000) ? mss_ : 3 * mss_);
  if (full_bw_reached_) {
    cwnd_bytes_ = std::clamp(target_cwnd, min_cwnd, kMaxCwndBytes);
  } else if (cwnd_bytes_ < target_cwnd || delivered_bytes_ < 10 * mss_) {
    cwnd_bytes_ =
        std::min(kMaxCwndBytes, cwnd_bytes_ + newly_acked_bytes);
  }
  cwnd_bytes_ = std::max(cwnd_bytes_, min_cwnd);
}

void BbrQuicCongestionController::OnCongestionEvent(
    int64_t now_us,
    size_t /*prior_in_flight_bytes*/,
    size_t bytes_in_flight,
    const QuicRttSample& rtt,
    const std::vector<QuicAckedPacket>& acked_packets,
    const std::vector<QuicLostPacket>& /*lost_packets*/) {
  size_t newly_acked = 0;
  for (const auto& p : acked_packets) {
    newly_acked += p.bytes;
  }

  if (!acked_packets.empty()) {
    UpdateBandwidthAndRound(acked_packets, now_us);
  }

  CheckStartupFullBandwidth();

  if (mode_ == Mode::kStartup && full_bw_reached_) {
    mode_ = Mode::kDrain;
    pacing_gain_ = kBbrDrainGain;
    cwnd_gain_ = 2.0;
  }
  if (mode_ == Mode::kDrain && bytes_in_flight <= TargetBdpBytes(1.0)) {
    mode_ = Mode::kProbeBw;
    cycle_idx_ = 0;
    cycle_stamp_us_ = now_us;
    pacing_gain_ = kBbrPacingGainCycle[0];
    cwnd_gain_ = 2.0;
  }

  UpdateProbeBwCycle(now_us, bytes_in_flight);
  UpdateMinRttAndProbeRtt(now_us, bytes_in_flight, rtt);
  RecalculateCwndAndPacing(newly_acked, bytes_in_flight);
}

void BbrQuicCongestionController::OnPersistentCongestion(int64_t /*now_us*/) {
  cwnd_bytes_ = 4 * mss_;
  full_bw_reached_ = false;
  rounds_without_bw_growth_ = 0;
  full_bw_baseline_bps_ = 0;
  mode_ = Mode::kStartup;
  pacing_gain_ = kBbrHighGain;
  cwnd_gain_ = 2.0;
}

size_t BbrQuicCongestionController::GetCongestionWindowBytes() const {
  return (mode_ == Mode::kProbeRtt) ? (4 * mss_) : cwnd_bytes_;
}

int64_t BbrQuicCongestionController::GetPacingRateBps(
    int64_t smoothed_rtt_us) const {
  if (pacing_rate_bps_ > 0) {
    return pacing_rate_bps_;
  }
  return ComputeRateBpsFromCwnd(cwnd_bytes_, smoothed_rtt_us, kBbrHighGain);
}

int64_t BbrQuicCongestionController::GetBandwidthEstimateBps() const {
  const int64_t bw = max_bw_filter_.GetBest();
  const int64_t cwnd_bps = ComputeRateBpsFromCwnd(
      cwnd_bytes_, min_rtt_us_ > 0 ? min_rtt_us_ : 30'000, 1.0);
  if (!full_bw_reached_) {
    return std::max(bw, cwnd_bps);
  }
  if (bw > 0) {
    return bw;
  }
  return cwnd_bps;
}

QuicCcMigrationState BbrQuicCongestionController::ExportMigrationState() const {
  QuicCcMigrationState st;
  st.cwnd_bytes = GetCongestionWindowBytes();
  st.ssthresh_bytes = ssthresh_bytes_;
  st.pacing_rate_bps = pacing_rate_bps_;
  st.bandwidth_estimate_bps = GetBandwidthEstimateBps();
  st.min_rtt_us = min_rtt_us_;
  st.smoothed_rtt_us = min_rtt_us_;
  st.delivered_bytes = delivered_bytes_;
  return st;
}

void BbrQuicCongestionController::ImportMigrationState(
    const QuicCcMigrationState& state,
    int64_t now_us) {
  cwnd_bytes_ = std::clamp(state.cwnd_bytes, 4 * mss_, kMaxCwndBytes);
  ssthresh_bytes_ = std::max(4 * mss_, state.ssthresh_bytes);
  delivered_bytes_ = state.delivered_bytes;
  next_round_delivered_ = delivered_bytes_;
  delivered_time_us_ = now_us;
  if (state.min_rtt_us > 0) {
    min_rtt_us_ = state.min_rtt_us;
    min_rtt_timestamp_us_ = now_us;
  } else if (state.smoothed_rtt_us > 0) {
    min_rtt_us_ = state.smoothed_rtt_us;
    min_rtt_timestamp_us_ = now_us;
  }
  if (state.bandwidth_estimate_bps > 0) {
    max_bw_filter_.Reset(state.bandwidth_estimate_bps, round_count_);
    full_bw_baseline_bps_ = state.bandwidth_estimate_bps;
    full_bw_reached_ = true;
    mode_ = Mode::kProbeBw;
    cycle_idx_ = 2;
    cycle_stamp_us_ = now_us;
    pacing_gain_ = 1.0;
    cwnd_gain_ = 2.0;
    pacing_rate_bps_ = state.bandwidth_estimate_bps;
  }
}

// ======================= 2. BBRv2 拥塞控制算法 =======================

Bbr2QuicCongestionController::Bbr2QuicCongestionController(
    size_t max_datagram_size)
    : mss_(std::max<size_t>(512, max_datagram_size)),
      inflight_hi_(kMaxCwndBytes),
      inflight_lo_(kMaxCwndBytes),
      cwnd_bytes_(10 * mss_) {}

void Bbr2QuicCongestionController::OnPacketSent(int64_t /*now_us*/,
                                                uint64_t /*packet_number*/,
                                                size_t bytes,
                                                bool in_flight,
                                                size_t prior_in_flight_bytes) {
  if (in_flight) {
    max_inflight_in_round_ =
        std::max(max_inflight_in_round_, prior_in_flight_bytes + bytes);
  }
}

size_t Bbr2QuicCongestionController::TargetBdpBytes(double gain) const {
  const int64_t bw_hi = max_bw_filter_.GetBest();
  const int64_t eff_bw = std::min(bw_hi, bw_lo_bps_);
  if (eff_bw <= 0 || min_rtt_us_ <= 0) {
    return 10 * mss_;
  }
  const double bdp =
      (static_cast<double>(eff_bw) * static_cast<double>(min_rtt_us_) * gain) /
      8'000'000.0;
  const size_t min_bdp = (eff_bw < 250'000) ? (2 * mss_) : (4 * mss_);
  return std::clamp<size_t>(static_cast<size_t>(bdp), min_bdp, kMaxCwndBytes);
}

size_t Bbr2QuicCongestionController::InflightWithHeadroom() const {
  if (inflight_hi_ >= kMaxCwndBytes) {
    return kMaxCwndBytes;
  }
  const size_t headroom =
      std::max(mss_, static_cast<size_t>(static_cast<double>(inflight_hi_) * 0.15));
  return (inflight_hi_ > headroom + 4 * mss_) ? (inflight_hi_ - headroom)
                                              : (4 * mss_);
}

bool Bbr2QuicCongestionController::IsLossTooHighInRound() const {
  const size_t total = round_acked_bytes_ + round_lost_bytes_;
  if (total < 8 * mss_) {
    return false;
  }
  // BBRv2 单轮丢包率阈值 kLossThresh = 2%
  return (round_lost_bytes_ * 100 > total * 2);
}

void Bbr2QuicCongestionController::EnterProbeBwDown(int64_t now_us) {
  state_ = State::kProbeBwDown;
  pacing_gain_ = 0.90;
  cwnd_gain_ = 2.0;
  cycle_stamp_us_ = now_us;
}

void Bbr2QuicCongestionController::EnterProbeBwCruise(int64_t now_us) {
  state_ = State::kProbeBwCruise;
  pacing_gain_ = 1.0;
  cwnd_gain_ = 2.0;
  cycle_stamp_us_ = now_us;
}

void Bbr2QuicCongestionController::EnterProbeBwRefill(int64_t now_us) {
  state_ = State::kProbeBwRefill;
  bw_lo_bps_ = INT64_MAX;
  inflight_lo_ = kMaxCwndBytes;
  probe_up_cnt_ = 4;
  probe_up_acked_ = 0;
  pacing_gain_ = 1.0;
  cwnd_gain_ = 2.0;
  cycle_stamp_us_ = now_us;
}

void Bbr2QuicCongestionController::EnterProbeBwUp(int64_t now_us) {
  state_ = State::kProbeBwUp;
  pacing_gain_ = 1.25;
  cwnd_gain_ = 2.25;
  probe_up_rounds_ = 0;
  cycle_stamp_us_ = now_us;
  if (inflight_hi_ >= kMaxCwndBytes) {
    inflight_hi_ = std::max(TargetBdpBytes(1.25), cwnd_bytes_);
  }
}

void Bbr2QuicCongestionController::OnCongestionEvent(
    int64_t now_us,
    size_t /*prior_in_flight_bytes*/,
    size_t bytes_in_flight,
    const QuicRttSample& rtt,
    const std::vector<QuicAckedPacket>& acked_packets,
    const std::vector<QuicLostPacket>& lost_packets) {
  round_start_ = false;
  size_t newly_acked = 0;
  for (const auto& pkt : acked_packets) {
    if (delivered_bytes_ < pkt.delivered_bytes_at_send) {
      delivered_bytes_ = pkt.delivered_bytes_at_send;
      next_round_delivered_ = delivered_bytes_;
    }
    newly_acked += pkt.bytes;
    round_acked_bytes_ += pkt.bytes;
    delivered_bytes_ += pkt.bytes;
    delivered_time_us_ = now_us;

    if (pkt.delivered_bytes_at_send >= next_round_delivered_) {
      next_round_delivered_ = delivered_bytes_;
      ++round_count_;
      round_start_ = true;
    }

    const int64_t send_elapsed =
        pkt.sent_time_us - pkt.first_sent_time_us_at_send;
    const int64_t ack_elapsed = now_us - pkt.delivered_time_us_at_send;
    const int64_t interval_us = std::max(send_elapsed, ack_elapsed);
    if (interval_us > 0 && delivered_bytes_ > pkt.delivered_bytes_at_send) {
      const uint64_t dbytes = delivered_bytes_ - pkt.delivered_bytes_at_send;
      const int64_t sample_bps = static_cast<int64_t>(
          (static_cast<double>(dbytes) * 8'000'000.0) /
          static_cast<double>(interval_us));
      last_sample_app_limited_ = pkt.is_app_limited;
      if (!pkt.is_app_limited || sample_bps > max_bw_filter_.GetBest()) {
        max_bw_filter_.Update(sample_bps, round_count_);
      }
    }
  }

  for (const auto& lost : lost_packets) {
    round_lost_bytes_ += lost.bytes;
    ++round_lost_pkts_;
  }

  const int64_t sample_rtt =
      (rtt.latest_rtt_us > 0) ? rtt.latest_rtt_us : rtt.smoothed_rtt_us;
  const bool rtt_expired =
      (min_rtt_us_ > 0) && (now_us > min_rtt_stamp_us_ + kRtpropExpiryUs);
  if (sample_rtt > 0 &&
      (min_rtt_us_ == 0 || sample_rtt <= min_rtt_us_ || rtt_expired)) {
    min_rtt_us_ = sample_rtt;
    min_rtt_stamp_us_ = now_us;
  } else if (!full_bw_reached_ && min_rtt_us_ > 0 &&
             delivered_bytes_ >= 4 * mss_ &&
             sample_rtt > min_rtt_us_ * 2 + 30'000) {
    // 超窄带链路 Startup 排队延迟翻倍早退保护：转入 Drain 排空积压队列，但不伪造丢包上限 inflight_hi_。
    full_bw_reached_ = true;
  }

  // BBRv2 单轮次门控的短期丢包响应（同一轮次内多次 ACK 检测到丢包仅执行一次折减）。
  if (!lost_packets.empty() && !loss_round_handled_ && IsLossTooHighInRound()) {
    if (state_ == State::kStartup) {
      if (round_lost_pkts_ >= 4) {
        full_bw_reached_ = true;
        inflight_hi_ = std::max(TargetBdpBytes(1.0), max_inflight_in_round_);
        state_ = State::kDrain;
        pacing_gain_ = kBbrDrainGain;
        loss_round_handled_ = true;
      }
    } else if (state_ == State::kProbeBwUp) {
      inflight_hi_ = std::max(TargetBdpBytes(1.0), bytes_in_flight);
      EnterProbeBwDown(now_us);
      loss_round_handled_ = true;
    } else {
      const int64_t cur_bw = GetBandwidthEstimateBps();
      bw_lo_bps_ = std::max<int64_t>(
          100'000,
          static_cast<int64_t>(static_cast<double>(std::min(cur_bw, bw_lo_bps_)) *
                               0.80));
      inflight_lo_ = std::max(
          4 * mss_,
          static_cast<size_t>(static_cast<double>(std::min(cwnd_bytes_, inflight_lo_)) *
                              0.80));
      loss_round_handled_ = true;
    }
  }

  if (round_start_) {
    if (!full_bw_reached_ && !last_sample_app_limited_) {
      const int64_t bw = max_bw_filter_.GetBest();
      if (static_cast<double>(bw) >=
          static_cast<double>(full_bw_baseline_bps_) * 1.25) {
        full_bw_baseline_bps_ = bw;
        rounds_without_bw_growth_ = 0;
      } else if (++rounds_without_bw_growth_ >= 3) {
        full_bw_reached_ = true;
      }
    }
    if (state_ == State::kProbeBwUp) {
      ++probe_up_rounds_;
    }
    round_acked_bytes_ = 0;
    round_lost_bytes_ = 0;
    round_lost_pkts_ = 0;
    max_inflight_in_round_ = bytes_in_flight;
    loss_round_handled_ = false;
  }

  if (state_ == State::kStartup && full_bw_reached_) {
    state_ = State::kDrain;
    pacing_gain_ = kBbrDrainGain;
    cwnd_gain_ = 2.0;
  }
  if (state_ == State::kDrain && bytes_in_flight <= TargetBdpBytes(1.0)) {
    EnterProbeBwCruise(now_us);
  }

  const int64_t ref_rtt_us = std::max<int64_t>(4000, min_rtt_us_);
  switch (state_) {
    case State::kProbeBwDown:
      if (bytes_in_flight <= std::min(TargetBdpBytes(1.0), InflightWithHeadroom()) ||
          (now_us - cycle_stamp_us_) > 2 * ref_rtt_us) {
        EnterProbeBwCruise(now_us);
      }
      break;
    case State::kProbeBwCruise:
      if ((now_us - cycle_stamp_us_) >= std::max<int64_t>(320'000, 8 * ref_rtt_us)) {
        EnterProbeBwRefill(now_us);
      }
      break;
    case State::kProbeBwRefill:
      if (round_start_ && (now_us - cycle_stamp_us_) >= ref_rtt_us) {
        EnterProbeBwUp(now_us);
      }
      break;
    case State::kProbeBwUp: {
      if (newly_acked > 0 && bytes_in_flight + mss_ >= inflight_hi_) {
        probe_up_acked_ += newly_acked;
        if (probe_up_acked_ >= probe_up_cnt_ * mss_) {
          const size_t delta = (probe_up_acked_ / (probe_up_cnt_ * mss_)) * mss_;
          probe_up_acked_ %= (probe_up_cnt_ * mss_);
          inflight_hi_ = std::min(kMaxCwndBytes, inflight_hi_ + delta);
          probe_up_cnt_ = std::min<size_t>(64, probe_up_cnt_ * 2);
        }
      }
      const bool app_limited_exit =
          last_sample_app_limited_ &&
          (probe_up_rounds_ >= 2 ||
           (now_us - cycle_stamp_us_) >= 2 * ref_rtt_us);
      if (app_limited_exit ||
          ((now_us - cycle_stamp_us_) >= 2 * ref_rtt_us &&
           bytes_in_flight > TargetBdpBytes(1.25) + 2 * mss_)) {
        EnterProbeBwDown(now_us);
      }
      break;
    }
    default:
      break;
  }

  if (state_ != State::kProbeRtt && rtt_expired && full_bw_reached_) {
    state_ = State::kProbeRtt;
    pacing_gain_ = 1.0;
    probe_rtt_done_us_ = 0;
    probe_rtt_round_done_ = false;
  }
  if (state_ == State::kProbeRtt) {
    if (probe_rtt_done_us_ == 0 && bytes_in_flight <= 4 * mss_) {
      probe_rtt_done_us_ = now_us + std::max(kProbeRttDurationUs, ref_rtt_us);
      probe_rtt_round_done_ = false;
      next_round_delivered_ = delivered_bytes_;
    } else if (probe_rtt_done_us_ != 0) {
      if (round_start_) {
        probe_rtt_round_done_ = true;
      }
      if ((probe_rtt_round_done_ || bytes_in_flight == 0) &&
          now_us >= probe_rtt_done_us_) {
        min_rtt_stamp_us_ = now_us;
        EnterProbeBwCruise(now_us);
      }
    }
  }

  const int64_t eff_bw = std::min(max_bw_filter_.GetBest(), bw_lo_bps_);
  const int64_t init_pacing_bps = ComputeRateBpsFromCwnd(
      10 * mss_, min_rtt_us_ > 0 ? min_rtt_us_ : 30'000, kBbrHighGain);
  if (eff_bw > 0) {
    const double scaled = std::clamp(
        static_cast<double>(eff_bw) * pacing_gain_, 0.0, 1.0e12);
    const int64_t candidate_bps =
        std::max<int64_t>(100'000, static_cast<int64_t>(scaled));
    pacing_rate_bps_ = full_bw_reached_
                           ? candidate_bps
                           : std::max({pacing_rate_bps_, init_pacing_bps,
                                       candidate_bps});
  }

  if (state_ == State::kProbeRtt) {
    cwnd_bytes_ = 4 * mss_;
    return;
  }

  const size_t min_cwnd =
      (eff_bw > 0 && eff_bw < 250'000) ? (2 * mss_) : (4 * mss_);
  size_t target = TargetBdpBytes(cwnd_gain_) +
                  ((eff_bw > 0 && eff_bw < 250'000) ? mss_ : (2 * mss_));
  if (state_ == State::kProbeBwCruise || state_ == State::kProbeBwDown) {
    target = std::min(target, InflightWithHeadroom());
  } else if (state_ == State::kProbeBwUp || state_ == State::kProbeBwRefill) {
    target = std::min(target, inflight_hi_);
  }
  target = std::min(target, inflight_lo_);
  if (full_bw_reached_) {
    cwnd_bytes_ = std::clamp(target, min_cwnd, kMaxCwndBytes);
  } else {
    cwnd_bytes_ =
        std::clamp(std::max(cwnd_bytes_ + newly_acked, target), min_cwnd, kMaxCwndBytes);
  }
}

void Bbr2QuicCongestionController::OnPersistentCongestion(int64_t /*now_us*/) {
  cwnd_bytes_ = 4 * mss_;
  inflight_lo_ = kMaxCwndBytes;
  inflight_hi_ = kMaxCwndBytes;
  bw_lo_bps_ = INT64_MAX;
  full_bw_baseline_bps_ = 0;
  full_bw_reached_ = false;
  rounds_without_bw_growth_ = 0;
  loss_round_handled_ = false;
  probe_rtt_done_us_ = 0;
  probe_rtt_round_done_ = false;
  state_ = State::kStartup;
  pacing_gain_ = kBbrHighGain;
  cwnd_gain_ = 2.0;
}

size_t Bbr2QuicCongestionController::GetCongestionWindowBytes() const {
  return (state_ == State::kProbeRtt) ? (4 * mss_) : cwnd_bytes_;
}

int64_t Bbr2QuicCongestionController::GetPacingRateBps(
    int64_t smoothed_rtt_us) const {
  if (pacing_rate_bps_ > 0) {
    return pacing_rate_bps_;
  }
  return ComputeRateBpsFromCwnd(cwnd_bytes_, smoothed_rtt_us, kBbrHighGain);
}

int64_t Bbr2QuicCongestionController::GetBandwidthEstimateBps() const {
  const int64_t bw = std::min(max_bw_filter_.GetBest(), bw_lo_bps_);
  const int64_t cwnd_bps = ComputeRateBpsFromCwnd(
      cwnd_bytes_, min_rtt_us_ > 0 ? min_rtt_us_ : 30'000, 1.0);
  if (!full_bw_reached_) {
    return (bw > 0 && bw < INT64_MAX) ? std::max(bw, cwnd_bps) : cwnd_bps;
  }
  if (bw > 0 && bw < INT64_MAX) {
    return bw;
  }
  return cwnd_bps;
}

QuicCcMigrationState Bbr2QuicCongestionController::ExportMigrationState() const {
  QuicCcMigrationState st;
  st.cwnd_bytes = GetCongestionWindowBytes();
  st.ssthresh_bytes = inflight_hi_;
  st.pacing_rate_bps = pacing_rate_bps_;
  st.bandwidth_estimate_bps = GetBandwidthEstimateBps();
  st.min_rtt_us = min_rtt_us_;
  st.smoothed_rtt_us = min_rtt_us_;
  st.delivered_bytes = delivered_bytes_;
  return st;
}

void Bbr2QuicCongestionController::ImportMigrationState(
    const QuicCcMigrationState& state,
    int64_t now_us) {
  cwnd_bytes_ = std::clamp(state.cwnd_bytes, 4 * mss_, kMaxCwndBytes);
  if (state.ssthresh_bytes > 4 * mss_ && state.ssthresh_bytes < kMaxCwndBytes) {
    inflight_hi_ = state.ssthresh_bytes;
  }
  delivered_bytes_ = state.delivered_bytes;
  next_round_delivered_ = delivered_bytes_;
  delivered_time_us_ = now_us;
  loss_round_handled_ = false;
  probe_rtt_done_us_ = 0;
  probe_rtt_round_done_ = false;
  if (state.min_rtt_us > 0) {
    min_rtt_us_ = state.min_rtt_us;
    min_rtt_stamp_us_ = now_us;
  } else if (state.smoothed_rtt_us > 0) {
    min_rtt_us_ = state.smoothed_rtt_us;
    min_rtt_stamp_us_ = now_us;
  }
  if (state.bandwidth_estimate_bps > 0) {
    max_bw_filter_.Reset(state.bandwidth_estimate_bps, round_count_);
    full_bw_baseline_bps_ = state.bandwidth_estimate_bps;
    full_bw_reached_ = true;
    pacing_rate_bps_ = state.bandwidth_estimate_bps;
    EnterProbeBwCruise(now_us);
  }
}

// ======================= 3. CUBIC + HyStart++ 拥塞控制算法 =======================

CubicQuicCongestionController::CubicQuicCongestionController(
    size_t max_datagram_size)
    : mss_(std::max<size_t>(512, max_datagram_size)),
      cwnd_bytes_(10 * mss_) {}

void CubicQuicCongestionController::OnPacketSent(int64_t now_us,
                                                 uint64_t packet_number,
                                                 size_t /*bytes*/,
                                                 bool in_flight,
                                                 size_t prior_in_flight) {
  if (in_flight) {
    highest_sent_pn_ = std::max(highest_sent_pn_, packet_number);
    // RFC 9438 第 5.8 节：从在途字节为空的静默暂停恢复发送时记录受限起点，
    // 以便在重返 cwnd 受限状态时平移 epoch_start_us_，防止 (dt)^3 爆炸。
    if (prior_in_flight == 0 && epoch_start_us_ >= 0 &&
        app_limited_start_us_ < 0 && last_cwnd_limited_us_ > 0 &&
        now_us > last_cwnd_limited_us_ + last_smoothed_rtt_us_) {
      app_limited_start_us_ = last_cwnd_limited_us_;
    }
  }
}

bool CubicQuicCongestionController::IsCwndLimited(
    size_t prior_in_flight_bytes) const {
  return (prior_in_flight_bytes >= cwnd_bytes_) ||
         (cwnd_bytes_ - prior_in_flight_bytes <= 3 * mss_) ||
         (prior_in_flight_bytes * 2 >= cwnd_bytes_);
}

void CubicQuicCongestionController::MaybeExitSlowStartHyStart(
    int64_t /*now_us*/,
    const QuicRttSample& rtt) {
  if (cwnd_bytes_ >= ssthresh_bytes_ || rtt.latest_rtt_us <= 0) {
    return;
  }
  if (curr_round_min_rtt_us_ == 0 || rtt.latest_rtt_us < curr_round_min_rtt_us_) {
    curr_round_min_rtt_us_ = rtt.latest_rtt_us;
  }
  ++rtt_sample_count_;

  if (rtt_sample_count_ >= 8 && last_round_min_rtt_us_ > 0) {
    const int64_t thresh_us =
        std::clamp<int64_t>(last_round_min_rtt_us_ / 8, 4000, 16'000);
    if (curr_round_min_rtt_us_ >= last_round_min_rtt_us_ + thresh_us) {
      // RFC 9406 HyStart++ 检测到排队时延增长：平滑退出慢启动阶段。
      ssthresh_bytes_ = cwnd_bytes_;
    }
  }
}

void CubicQuicCongestionController::UpdateCubicCongestionAvoidance(
    size_t acked_bytes,
    int64_t now_us,
    int64_t rtt_us) {
  constexpr double kCubicC = 0.4;
  constexpr double kCubicBeta = 0.7;

  const double cwnd_segs =
      static_cast<double>(cwnd_bytes_) / static_cast<double>(mss_);
  const double acked_segs =
      static_cast<double>(acked_bytes) / static_cast<double>(mss_);

  if (epoch_start_us_ < 0) {
    epoch_start_us_ = now_us;
    w_est_segments_ = cwnd_segs;
    if (w_max_segments_ <= cwnd_segs) {
      k_sec_ = 0.0;
      w_max_segments_ = cwnd_segs;
    } else {
      k_sec_ = std::cbrt((w_max_segments_ - cwnd_segs) / kCubicC);
    }
  }

  const double t_sec =
      static_cast<double>(std::max<int64_t>(0, now_us - epoch_start_us_ + rtt_us)) /
      1'000'000.0;
  const double dt = t_sec - k_sec_;
  const double w_cubic_segs = kCubicC * (dt * dt * dt) + w_max_segments_;

  // RFC 9438 第 4.3 节 Reno 友好型影子窗口：alpha = 3*(1-beta)/(1+beta)
  constexpr double kAlphaReno =
      (3.0 * (1.0 - kCubicBeta)) / (1.0 + kCubicBeta);
  w_est_segments_ += kAlphaReno * (acked_segs / std::max(1.0, cwnd_segs));

  double target_segs = std::max(w_cubic_segs, w_est_segments_);
  target_segs = std::min(target_segs, cwnd_segs * 1.5);

  if (target_segs > cwnd_segs) {
    const double seg_inc =
        ((target_segs - cwnd_segs) / std::max(1.0, cwnd_segs)) * acked_segs;
    cwnd_frac_accum_ += seg_inc * static_cast<double>(mss_);
  } else {
    cwnd_frac_accum_ += (0.01 * acked_segs * static_cast<double>(mss_)) /
                        std::max(1.0, cwnd_segs);
  }

  if (cwnd_frac_accum_ >= 1.0) {
    const size_t add_b = static_cast<size_t>(cwnd_frac_accum_);
    cwnd_frac_accum_ -= static_cast<double>(add_b);
    cwnd_bytes_ = std::min(kMaxCwndBytes, cwnd_bytes_ + add_b);
  }
}

void CubicQuicCongestionController::OnCongestionEvent(
    int64_t now_us,
    size_t prior_in_flight_bytes,
    size_t /*bytes_in_flight*/,
    const QuicRttSample& rtt,
    const std::vector<QuicAckedPacket>& acked_packets,
    const std::vector<QuicLostPacket>& lost_packets) {
  if (rtt.smoothed_rtt_us > 0) {
    last_smoothed_rtt_us_ = rtt.smoothed_rtt_us;
  }

  if (!acked_packets.empty()) {
    for (const auto& p : acked_packets) {
      delivered_bytes_ += p.bytes;
    }
    if (acked_packets.back().packet_number >= round_end_pn_) {
      round_end_pn_ = highest_sent_pn_;
      last_round_min_rtt_us_ = curr_round_min_rtt_us_;
      curr_round_min_rtt_us_ = 0;
      rtt_sample_count_ = 0;
    }
    MaybeExitSlowStartHyStart(now_us, rtt);
  }

  // 处理丢包恢复阶段（乘性减小系数 beta = 0.7）。
  int64_t largest_lost_sent_us = -1;
  for (const auto& l : lost_packets) {
    largest_lost_sent_us = std::max(largest_lost_sent_us, l.sent_time_us);
  }
  if (largest_lost_sent_us >= 0 &&
      (recovery_start_time_us_ < 0 ||
       largest_lost_sent_us > recovery_start_time_us_)) {
    recovery_start_time_us_ = now_us;
    epoch_start_us_ = -1;
    app_limited_start_us_ = -1;
    last_cwnd_limited_us_ = -1;
    const double cur_segs =
        static_cast<double>(cwnd_bytes_) / static_cast<double>(mss_);
    // RFC 9438 第 4.7 节：快速收敛（Fast Convergence）。
    if (cur_segs < w_max_segments_) {
      w_max_segments_ = cur_segs * 0.85;
    } else {
      w_max_segments_ = cur_segs;
    }
    cwnd_bytes_ = std::max(
        2 * mss_,
        static_cast<size_t>(static_cast<double>(cwnd_bytes_) * 0.70));
    ssthresh_bytes_ = cwnd_bytes_;
  }

  if (acked_packets.empty()) {
    return;
  }
  if (!IsCwndLimited(prior_in_flight_bytes)) {
    if (epoch_start_us_ >= 0 && app_limited_start_us_ < 0) {
      app_limited_start_us_ =
          (last_cwnd_limited_us_ > 0) ? last_cwnd_limited_us_ : now_us;
    }
    return;
  }

  // RFC 9438 第 5.8 节：跨越应用受限或空闲期后恢复 cwnd 受限发送时平移 epoch_start_us_。
  if (app_limited_start_us_ >= 0) {
    if (epoch_start_us_ >= 0 && now_us > app_limited_start_us_) {
      epoch_start_us_ += (now_us - app_limited_start_us_);
    }
    app_limited_start_us_ = -1;
  } else if (epoch_start_us_ >= 0 && last_cwnd_limited_us_ > 0 &&
             now_us - last_cwnd_limited_us_ >
                 std::max<int64_t>(200'000, 4 * last_smoothed_rtt_us_)) {
    epoch_start_us_ +=
        (now_us - last_cwnd_limited_us_ - last_smoothed_rtt_us_);
  }
  last_cwnd_limited_us_ = now_us;

  if (recovery_start_time_us_ >= 0 &&
      acked_packets.back().sent_time_us <= recovery_start_time_us_) {
    return;
  }

  size_t newly_acked = 0;
  for (const auto& p : acked_packets) {
    if (recovery_start_time_us_ < 0 ||
        p.sent_time_us > recovery_start_time_us_) {
      newly_acked += p.bytes;
    }
  }

  if (cwnd_bytes_ < ssthresh_bytes_) {
    cwnd_bytes_ = std::min(kMaxCwndBytes, cwnd_bytes_ + newly_acked);
  } else {
    UpdateCubicCongestionAvoidance(newly_acked, now_us, last_smoothed_rtt_us_);
  }
}

void CubicQuicCongestionController::OnPersistentCongestion(int64_t /*now_us*/) {
  ssthresh_bytes_ = std::max(
      2 * mss_,
      static_cast<size_t>(static_cast<double>(cwnd_bytes_) * 0.70));
  w_max_segments_ =
      static_cast<double>(cwnd_bytes_) / static_cast<double>(mss_);
  cwnd_bytes_ = 2 * mss_;
  epoch_start_us_ = -1;
  app_limited_start_us_ = -1;
  last_cwnd_limited_us_ = -1;
  recovery_start_time_us_ = -1;
}

int64_t CubicQuicCongestionController::GetPacingRateBps(
    int64_t smoothed_rtt_us) const {
  const double gain = (cwnd_bytes_ < ssthresh_bytes_) ? 2.0 : 1.25;
  return ComputeRateBpsFromCwnd(
      cwnd_bytes_, smoothed_rtt_us > 0 ? smoothed_rtt_us : last_smoothed_rtt_us_,
      gain);
}

int64_t CubicQuicCongestionController::GetBandwidthEstimateBps() const {
  return ComputeRateBpsFromCwnd(cwnd_bytes_, last_smoothed_rtt_us_, 1.0);
}

QuicCcMigrationState
CubicQuicCongestionController::ExportMigrationState() const {
  QuicCcMigrationState st;
  st.cwnd_bytes = cwnd_bytes_;
  st.ssthresh_bytes = ssthresh_bytes_;
  st.pacing_rate_bps = GetPacingRateBps(last_smoothed_rtt_us_);
  st.bandwidth_estimate_bps = GetBandwidthEstimateBps();
  st.smoothed_rtt_us = last_smoothed_rtt_us_;
  st.delivered_bytes = delivered_bytes_;
  return st;
}

void CubicQuicCongestionController::ImportMigrationState(
    const QuicCcMigrationState& state,
    int64_t /*now_us*/) {
  cwnd_bytes_ = std::clamp(state.cwnd_bytes, 2 * mss_, kMaxCwndBytes);
  ssthresh_bytes_ = std::clamp(state.ssthresh_bytes, 2 * mss_, kMaxCwndBytes);
  delivered_bytes_ = state.delivered_bytes;
  if (state.smoothed_rtt_us > 0) {
    last_smoothed_rtt_us_ = state.smoothed_rtt_us;
  } else if (state.min_rtt_us > 0) {
    last_smoothed_rtt_us_ = state.min_rtt_us;
  }
  w_max_segments_ =
      static_cast<double>(cwnd_bytes_) / static_cast<double>(mss_);
  epoch_start_us_ = -1;
  app_limited_start_us_ = -1;
  last_cwnd_limited_us_ = -1;
}

// ======================= 4. Copa 拥塞控制算法 =======================

CopaQuicCongestionController::CopaQuicCongestionController(
    size_t max_datagram_size)
    : mss_(std::max<size_t>(512, max_datagram_size)),
      cwnd_bytes_(10 * mss_),
      cwnd_bytes_fp_(static_cast<double>(10 * mss_)),
      cwnd_at_round_start_(10 * mss_) {}

void CopaQuicCongestionController::OnPacketSent(int64_t /*now_us*/,
                                                uint64_t packet_number,
                                                size_t /*bytes*/,
                                                bool in_flight,
                                                size_t /*prior_in_flight*/) {
  if (in_flight) {
    highest_sent_pn_ = std::max(highest_sent_pn_, packet_number);
  }
}

int64_t CopaQuicCongestionController::ComputeStandingRttUs(int64_t now_us,
                                                           int64_t window_us) {
  while (!rtt_samples_.empty() &&
         rtt_samples_.front().time_us + window_us < now_us) {
    rtt_samples_.pop_front();
  }
  int64_t best = 0;
  for (const auto& s : rtt_samples_) {
    if (best == 0 || s.rtt_us < best) {
      best = s.rtt_us;
    }
  }
  return best;
}

void CopaQuicCongestionController::OnCongestionEvent(
    int64_t now_us,
    size_t prior_in_flight_bytes,
    size_t /*bytes_in_flight*/,
    const QuicRttSample& rtt,
    const std::vector<QuicAckedPacket>& acked_packets,
    const std::vector<QuicLostPacket>& lost_packets) {
  const int64_t sample_rtt =
      (rtt.latest_rtt_us > 0) ? rtt.latest_rtt_us : rtt.smoothed_rtt_us;
  if (sample_rtt > 0) {
    const bool expired =
        (base_min_rtt_us_ > 0) &&
        (now_us > base_min_rtt_stamp_us_ + kRtpropExpiryUs);
    if (base_min_rtt_us_ == 0 || sample_rtt <= base_min_rtt_us_ || expired) {
      base_min_rtt_us_ = sample_rtt;
      base_min_rtt_stamp_us_ = now_us;
    }
    rtt_samples_.push_back(TimedRtt{now_us, sample_rtt});
    const int64_t tau_us =
        std::max<int64_t>(4000, rtt.smoothed_rtt_us / 2);
    const int64_t standing = ComputeStandingRttUs(now_us, tau_us);
    if (standing > 0) {
      standing_rtt_us_ = standing;
    }

    const int64_t five_rtt_win_us = std::max<int64_t>(
        20'000, 5 * std::max<int64_t>(standing_rtt_us_, rtt.smoothed_rtt_us));
    five_rtt_samples_.push_back(TimedRtt{now_us, sample_rtt});
    while (!five_rtt_samples_.empty() &&
           five_rtt_samples_.front().time_us + five_rtt_win_us < now_us) {
      five_rtt_samples_.pop_front();
    }
    const int64_t cur_qdelay_us =
        std::max<int64_t>(0, standing_rtt_us_ - base_min_rtt_us_);
    standing_qdelay_samples_.push_back(TimedRtt{now_us, cur_qdelay_us});
    while (!standing_qdelay_samples_.empty() &&
           standing_qdelay_samples_.front().time_us + five_rtt_win_us < now_us) {
      standing_qdelay_samples_.pop_front();
    }
  }

  size_t newly_acked = 0;
  for (const auto& p : acked_packets) {
    newly_acked += p.bytes;
    round_acked_bytes_ += p.bytes;
    delivered_bytes_ += p.bytes;
  }
  for (const auto& l : lost_packets) {
    round_lost_bytes_ += l.bytes;
  }

  // 当浅缓冲或随机限速导致单轮丢包率超过 10% 时，主动收敛窗口并限制步长因子 velocity。
  const size_t round_total_bytes = round_acked_bytes_ + round_lost_bytes_;
  if (!lost_packets.empty() && !loss_reduced_in_round_ &&
      round_total_bytes >= 4 * mss_ &&
      round_lost_bytes_ * 10 > round_total_bytes) {
    in_slow_start_ = false;
    velocity_ = 1.0;
    direction_ = -1;
    same_direction_rounds_ = 0;
    cwnd_bytes_fp_ = std::max<double>(static_cast<double>(2 * mss_),
                                      cwnd_bytes_fp_ * 0.75);
    cwnd_bytes_ = static_cast<size_t>(cwnd_bytes_fp_);
    loss_reduced_in_round_ = true;
  }

  if (acked_packets.empty()) {
    return;
  }

  const int64_t queueing_delay_us =
      std::max<int64_t>(0, standing_rtt_us_ - base_min_rtt_us_);
  const double current_rate_pkts_per_sec =
      (static_cast<double>(cwnd_bytes_) / static_cast<double>(mss_)) /
      (static_cast<double>(std::max<int64_t>(1000, standing_rtt_us_)) /
       1'000'000.0);

  double target_rate_pkts_per_sec = std::numeric_limits<double>::infinity();
  if (queueing_delay_us > 250) {
    target_rate_pkts_per_sec =
        1'000'000.0 / (delta_ * static_cast<double>(queueing_delay_us));
  }

  const bool should_increase =
      (current_rate_pkts_per_sec <= target_rate_pkts_per_sec);
  if (!should_increase) {
    in_slow_start_ = false;
  }

  // 轮次边界处的速率步长系数（velocity）与竞争模式检查。
  if (acked_packets.back().packet_number >= round_end_pn_) {
    round_end_pn_ = highest_sent_pn_;

    int64_t max_rtt_5rtt_us = standing_rtt_us_;
    for (const auto& s : five_rtt_samples_) {
      max_rtt_5rtt_us = std::max(max_rtt_5rtt_us, s.rtt_us);
    }
    int64_t min_standing_qdelay_us = queueing_delay_us;
    for (const auto& s : standing_qdelay_samples_) {
      min_standing_qdelay_us = std::min(min_standing_qdelay_us, s.rtt_us);
    }
    const double rtt_range_thresh_us =
        0.1 * static_cast<double>(
                  std::max<int64_t>(0, max_rtt_5rtt_us - base_min_rtt_us_));
    const int64_t est_bw_bps = GetBandwidthEstimateBps();
    const double pkt_ser_delay_us =
        (static_cast<double>(mss_) * 8'000'000.0) /
        static_cast<double>(std::max<int64_t>(100'000, est_bw_bps));

    if (queueing_delay_us > 0 &&
        static_cast<double>(min_standing_qdelay_us) > rtt_range_thresh_us &&
        static_cast<double>(min_standing_qdelay_us) > 2.0 * pkt_ser_delay_us) {
      ++unemptied_queue_rounds_;
      if (unemptied_queue_rounds_ >= 5) {
        delta_ = std::max(0.125, delta_ * 0.85);  // 竞争模式（存在长驻队列时提高激进度）
      }
    } else {
      unemptied_queue_rounds_ = 0;
      delta_ = 0.5;  // 默认低延迟视频模式（约 2 个数据包的驻留队列）
    }

    if (!in_slow_start_) {
      if (cwnd_bytes_ == cwnd_at_round_start_) {
        // 应用受限导致 cwnd 未发生实质增减时严禁虚增 velocity_。
        direction_ = 0;
        same_direction_rounds_ = 0;
        velocity_ = 1.0;
      } else {
        const int new_dir = (cwnd_bytes_ > cwnd_at_round_start_) ? 1 : -1;
        if (new_dir == direction_) {
          ++same_direction_rounds_;
          if (same_direction_rounds_ >= 3) {
            velocity_ = std::min(32.0, velocity_ * 2.0);
          }
        } else {
          direction_ = new_dir;
          same_direction_rounds_ = 1;
          velocity_ = 1.0;
        }
      }
    }
    cwnd_at_round_start_ = cwnd_bytes_;
    round_acked_bytes_ = 0;
    round_lost_bytes_ = 0;
    loss_reduced_in_round_ = false;
  }

  const bool is_cwnd_limited =
      (prior_in_flight_bytes >= cwnd_bytes_) ||
      (cwnd_bytes_ - prior_in_flight_bytes <= 3 * mss_) ||
      (prior_in_flight_bytes * 2 >= cwnd_bytes_);

  if (in_slow_start_) {
    if (is_cwnd_limited) {
      cwnd_bytes_fp_ = std::min<double>(static_cast<double>(kMaxCwndBytes),
                                        cwnd_bytes_fp_ + newly_acked);
      cwnd_bytes_ = static_cast<size_t>(cwnd_bytes_fp_);
    }
    return;
  }

  const double cwnd_pkts = std::max(2.0, cwnd_bytes_fp_ / static_cast<double>(mss_));
  const double acked_pkts = static_cast<double>(newly_acked) / static_cast<double>(mss_);
  const double step_bytes =
      ((velocity_ * acked_pkts) / (delta_ * cwnd_pkts)) * static_cast<double>(mss_);

  if (should_increase) {
    if (is_cwnd_limited) {
      cwnd_bytes_fp_ = std::min<double>(static_cast<double>(kMaxCwndBytes),
                                        cwnd_bytes_fp_ + step_bytes);
    }
  } else {
    cwnd_bytes_fp_ = std::max<double>(static_cast<double>(2 * mss_),
                                      cwnd_bytes_fp_ - step_bytes);
  }
  cwnd_bytes_ = static_cast<size_t>(cwnd_bytes_fp_);
}

void CopaQuicCongestionController::OnPersistentCongestion(int64_t /*now_us*/) {
  cwnd_bytes_ = 2 * mss_;
  cwnd_bytes_fp_ = static_cast<double>(cwnd_bytes_);
  cwnd_at_round_start_ = cwnd_bytes_;
  direction_ = 0;
  same_direction_rounds_ = 0;
  velocity_ = 1.0;
  delta_ = 0.5;
  unemptied_queue_rounds_ = 0;
  round_acked_bytes_ = 0;
  round_lost_bytes_ = 0;
  loss_reduced_in_round_ = false;
  in_slow_start_ = true;
}

int64_t CopaQuicCongestionController::GetPacingRateBps(
    int64_t smoothed_rtt_us) const {
  const int64_t rtt = (standing_rtt_us_ > 0) ? standing_rtt_us_ : smoothed_rtt_us;
  const double gain = in_slow_start_ ? 2.0 : 1.15;
  return ComputeRateBpsFromCwnd(cwnd_bytes_, rtt, gain);
}

int64_t CopaQuicCongestionController::GetBandwidthEstimateBps() const {
  return ComputeRateBpsFromCwnd(cwnd_bytes_, standing_rtt_us_, 1.0);
}

QuicCcMigrationState
CopaQuicCongestionController::ExportMigrationState() const {
  QuicCcMigrationState st;
  st.cwnd_bytes = cwnd_bytes_;
  st.ssthresh_bytes = GetSlowStartThresholdBytes();
  st.pacing_rate_bps = GetPacingRateBps(standing_rtt_us_);
  st.bandwidth_estimate_bps = GetBandwidthEstimateBps();
  st.min_rtt_us = base_min_rtt_us_;
  st.smoothed_rtt_us = standing_rtt_us_;
  st.delivered_bytes = delivered_bytes_;
  return st;
}

void CopaQuicCongestionController::ImportMigrationState(
    const QuicCcMigrationState& state,
    int64_t now_us) {
  cwnd_bytes_ = std::clamp(state.cwnd_bytes, 2 * mss_, kMaxCwndBytes);
  cwnd_bytes_fp_ = static_cast<double>(cwnd_bytes_);
  cwnd_at_round_start_ = cwnd_bytes_;
  delivered_bytes_ = state.delivered_bytes;
  in_slow_start_ = false;
  direction_ = 0;
  same_direction_rounds_ = 0;
  velocity_ = 1.0;
  if (state.min_rtt_us > 0) {
    base_min_rtt_us_ = state.min_rtt_us;
    base_min_rtt_stamp_us_ = now_us;
    standing_rtt_us_ = state.min_rtt_us;
  } else if (state.smoothed_rtt_us > 0) {
    standing_rtt_us_ = state.smoothed_rtt_us;
  }
}

// ======================= 5. NewReno 拥塞控制算法 =======================

NewRenoQuicCongestionController::NewRenoQuicCongestionController(
    size_t max_datagram_size)
    : mss_(std::max<size_t>(512, max_datagram_size)),
      cwnd_bytes_(10 * mss_) {}

void NewRenoQuicCongestionController::OnPacketSent(
    int64_t /*now_us*/,
    uint64_t /*packet_number*/,
    size_t /*bytes*/,
    bool /*in_flight*/,
    size_t /*prior_in_flight_bytes*/) {}

bool NewRenoQuicCongestionController::IsCwndLimited(
    size_t prior_in_flight_bytes) const {
  return (prior_in_flight_bytes >= cwnd_bytes_) ||
         (cwnd_bytes_ - prior_in_flight_bytes <= 3 * mss_) ||
         (prior_in_flight_bytes * 2 >= cwnd_bytes_);
}

void NewRenoQuicCongestionController::OnCongestionEvent(
    int64_t now_us,
    size_t prior_in_flight_bytes,
    size_t /*bytes_in_flight*/,
    const QuicRttSample& rtt,
    const std::vector<QuicAckedPacket>& acked_packets,
    const std::vector<QuicLostPacket>& lost_packets) {
  if (rtt.smoothed_rtt_us > 0) {
    last_smoothed_rtt_us_ = rtt.smoothed_rtt_us;
  }

  int64_t largest_lost_sent_us = -1;
  for (const auto& l : lost_packets) {
    largest_lost_sent_us = std::max(largest_lost_sent_us, l.sent_time_us);
  }
  if (largest_lost_sent_us >= 0 &&
      (recovery_start_time_us_ < 0 ||
       largest_lost_sent_us > recovery_start_time_us_)) {
    recovery_start_time_us_ = now_us;
    cwnd_bytes_ = std::max(2 * mss_, cwnd_bytes_ / 2);  // RFC 9002 丢包窗口折减因子 kLossReductionFactor = 0.5
    ssthresh_bytes_ = cwnd_bytes_;
    ca_byte_accum_ = 0;
  }

  for (const auto& pkt : acked_packets) {
    delivered_bytes_ += pkt.bytes;
  }
  if (acked_packets.empty() || !IsCwndLimited(prior_in_flight_bytes)) {
    return;
  }

  for (const auto& pkt : acked_packets) {
    if (recovery_start_time_us_ >= 0 &&
        pkt.sent_time_us <= recovery_start_time_us_) {
      continue;
    }
    if (cwnd_bytes_ < ssthresh_bytes_) {
      cwnd_bytes_ = std::min(kMaxCwndBytes, cwnd_bytes_ + pkt.bytes);
    } else {
      ca_byte_accum_ += mss_ * pkt.bytes;
      const size_t inc = ca_byte_accum_ / cwnd_bytes_;
      ca_byte_accum_ %= cwnd_bytes_;
      cwnd_bytes_ = std::min(kMaxCwndBytes, cwnd_bytes_ + inc);
    }
  }
}

void NewRenoQuicCongestionController::OnPersistentCongestion(int64_t /*now_us*/) {
  ssthresh_bytes_ = std::max(cwnd_bytes_ / 2, 2 * mss_);
  cwnd_bytes_ = 2 * mss_;
  ca_byte_accum_ = 0;
  recovery_start_time_us_ = -1;
}

int64_t NewRenoQuicCongestionController::GetPacingRateBps(
    int64_t smoothed_rtt_us) const {
  const double gain = (cwnd_bytes_ < ssthresh_bytes_) ? 2.0 : 1.25;
  return ComputeRateBpsFromCwnd(
      cwnd_bytes_, smoothed_rtt_us > 0 ? smoothed_rtt_us : last_smoothed_rtt_us_,
      gain);
}

int64_t NewRenoQuicCongestionController::GetBandwidthEstimateBps() const {
  return ComputeRateBpsFromCwnd(cwnd_bytes_, last_smoothed_rtt_us_, 1.0);
}

QuicCcMigrationState
NewRenoQuicCongestionController::ExportMigrationState() const {
  QuicCcMigrationState st;
  st.cwnd_bytes = cwnd_bytes_;
  st.ssthresh_bytes = ssthresh_bytes_;
  st.pacing_rate_bps = GetPacingRateBps(last_smoothed_rtt_us_);
  st.bandwidth_estimate_bps = GetBandwidthEstimateBps();
  st.smoothed_rtt_us = last_smoothed_rtt_us_;
  st.delivered_bytes = delivered_bytes_;
  return st;
}

void NewRenoQuicCongestionController::ImportMigrationState(
    const QuicCcMigrationState& state,
    int64_t /*now_us*/) {
  cwnd_bytes_ = std::clamp(state.cwnd_bytes, 2 * mss_, kMaxCwndBytes);
  ssthresh_bytes_ = std::clamp(state.ssthresh_bytes, 2 * mss_, kMaxCwndBytes);
  delivered_bytes_ = state.delivered_bytes;
  if (state.smoothed_rtt_us > 0) {
    last_smoothed_rtt_us_ = state.smoothed_rtt_us;
  } else if (state.min_rtt_us > 0) {
    last_smoothed_rtt_us_ = state.min_rtt_us;
  }
}

// ======================= 拥塞控制器工厂与辅助函数 =======================

std::unique_ptr<IQuicCongestionController>
CreateBuiltinQuicCongestionController(rtc_quic_cc_algo_e algo,
                                      size_t max_datagram_size) {
  switch (algo) {
    case RTC_QUIC_CC_BBR:
      return std::make_unique<BbrQuicCongestionController>(max_datagram_size);
    case RTC_QUIC_CC_BBR2:
      return std::make_unique<Bbr2QuicCongestionController>(max_datagram_size);
    case RTC_QUIC_CC_CUBIC:
      return std::make_unique<CubicQuicCongestionController>(max_datagram_size);
    case RTC_QUIC_CC_COPA:
      return std::make_unique<CopaQuicCongestionController>(max_datagram_size);
    case RTC_QUIC_CC_NEWRENO:
      return std::make_unique<NewRenoQuicCongestionController>(
          max_datagram_size);
    default:
      return nullptr;
  }
}

std::shared_ptr<IQuicCongestionControllerFactory> CreateBuiltinQuicCcFactory(
    rtc_quic_cc_algo_e algo) {
  switch (algo) {
    case RTC_QUIC_CC_BBR:
    case RTC_QUIC_CC_BBR2:
    case RTC_QUIC_CC_CUBIC:
    case RTC_QUIC_CC_COPA:
    case RTC_QUIC_CC_NEWRENO:
      return std::make_shared<BuiltinQuicCcFactory>(algo);
    default:
      return nullptr;
  }
}

}  // namespace rtc
