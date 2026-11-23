#include "modules/congestion_controller/goog_cc/goog_cc_controller.h"

#include <algorithm>
#include <cmath>

#include "rtc_base/logging.h"

namespace rtc {

// ======================= 1. InterArrivalDelta 包组到达间隔差值计算 =======================

InterArrivalDelta::InterArrivalDelta(TimeDelta send_time_group_length)
    : send_time_group_length_(send_time_group_length) {}

void InterArrivalDelta::Reset() {
  current_timestamp_group_ = SendTimeGroup{};
  prev_timestamp_group_ = SendTimeGroup{};
  num_consecutive_reordered_packets_ = 0;
}

bool InterArrivalDelta::ComputeDeltas(Timestamp send_time,
                                      Timestamp arrival_time,
                                      Timestamp system_time,
                                      size_t packet_size,
                                      TimeDelta* send_time_delta,
                                      TimeDelta* arrival_time_delta,
                                      int* packet_size_delta) {
  bool calculated_deltas = false;
  if (current_timestamp_group_.first_send_time.IsMinusInfinity()) {
    current_timestamp_group_.send_time = send_time;
    current_timestamp_group_.first_send_time = send_time;
    current_timestamp_group_.first_arrival = arrival_time;
  } else if (current_timestamp_group_.first_send_time > send_time) {
    return false;
  } else if (NewTimestampGroup(arrival_time, send_time)) {
    if (prev_timestamp_group_.complete_time.IsFinite()) {
      *send_time_delta =
          current_timestamp_group_.send_time - prev_timestamp_group_.send_time;
      *arrival_time_delta = current_timestamp_group_.complete_time -
                            prev_timestamp_group_.complete_time;
      const TimeDelta system_time_delta =
          current_timestamp_group_.last_system_time -
          prev_timestamp_group_.last_system_time;

      if (*arrival_time_delta - system_time_delta >= TimeDelta::Millis(3000)) {
        RTC_LOG(kWarning)
            << "InterArrivalDelta reset due to arrival clock jump";
        Reset();
        return false;
      }
      if (*arrival_time_delta < TimeDelta::Zero()) {
        ++num_consecutive_reordered_packets_;
        if (num_consecutive_reordered_packets_ >= 3) {
          Reset();
        }
        return false;
      }
      num_consecutive_reordered_packets_ = 0;
      *packet_size_delta = static_cast<int>(current_timestamp_group_.size) -
                           static_cast<int>(prev_timestamp_group_.size);
      calculated_deltas = true;
    }
    prev_timestamp_group_ = current_timestamp_group_;
    current_timestamp_group_.first_send_time = send_time;
    current_timestamp_group_.send_time = send_time;
    current_timestamp_group_.first_arrival = arrival_time;
    current_timestamp_group_.size = 0;
  } else {
    current_timestamp_group_.send_time =
        std::max(current_timestamp_group_.send_time, send_time);
  }

  current_timestamp_group_.size += packet_size;
  current_timestamp_group_.complete_time = arrival_time;
  current_timestamp_group_.last_system_time = system_time;
  return calculated_deltas;
}

bool InterArrivalDelta::NewTimestampGroup(Timestamp arrival_time,
                                          Timestamp send_time) const {
  if (current_timestamp_group_.complete_time.IsMinusInfinity()) {
    return false;
  }
  if (BelongsToBurst(arrival_time, send_time)) {
    return false;
  }
  return (send_time - current_timestamp_group_.first_send_time) >
         send_time_group_length_;
}

bool InterArrivalDelta::BelongsToBurst(Timestamp arrival_time,
                                       Timestamp send_time) const {
  const TimeDelta arrival_time_delta =
      arrival_time - current_timestamp_group_.complete_time;
  const TimeDelta send_time_delta =
      send_time - current_timestamp_group_.send_time;
  if (send_time_delta.IsZero()) {
    return true;
  }
  const TimeDelta propagation_delta = arrival_time_delta - send_time_delta;
  return propagation_delta < TimeDelta::Zero() &&
         arrival_time_delta <= TimeDelta::Millis(5) &&
         (arrival_time - current_timestamp_group_.first_arrival) <
             TimeDelta::Millis(100);
}

// ======================= 2. TrendlineEstimator 趋势线延迟梯度估计 =======================

TrendlineEstimator::TrendlineEstimator(size_t window_size,
                                       double smoothing_coef,
                                       double threshold_gain)
    : window_size_(window_size),
      smoothing_coef_(smoothing_coef),
      threshold_gain_(threshold_gain) {}

std::optional<double> TrendlineEstimator::LinearFitSlope(
    const std::deque<PacketTiming>& packets) const {
  if (packets.size() < 2) {
    return std::nullopt;
  }
  double sum_x = 0.0;
  double sum_y = 0.0;
  for (const auto& pkt : packets) {
    sum_x += pkt.arrival_time_ms;
    sum_y += pkt.smoothed_delay_ms;
  }
  const double x_avg = sum_x / static_cast<double>(packets.size());
  const double y_avg = sum_y / static_cast<double>(packets.size());

  double numerator = 0.0;
  double denominator = 0.0;
  for (const auto& pkt : packets) {
    const double x = pkt.arrival_time_ms;
    const double y = pkt.smoothed_delay_ms;
    numerator += (x - x_avg) * (y - y_avg);
    denominator += (x - x_avg) * (x - x_avg);
  }
  if (denominator == 0.0) {
    return std::nullopt;
  }
  return numerator / denominator;
}

void TrendlineEstimator::Update(TimeDelta recv_delta,
                                TimeDelta send_delta,
                                Timestamp /*send_time*/,
                                Timestamp arrival_time,
                                size_t /*packet_size*/,
                                bool calculated_deltas) {
  if (!calculated_deltas) {
    return;
  }
  const double delta_ms = (recv_delta - send_delta).ms_double();
  num_of_deltas_ = std::min(num_of_deltas_ + 1, 1000);
  if (first_arrival_time_.IsMinusInfinity()) {
    first_arrival_time_ = arrival_time;
  }

  accumulated_delay_ms_ += delta_ms;
  smoothed_delay_ms_ = smoothing_coef_ * smoothed_delay_ms_ +
                       (1.0 - smoothing_coef_) * accumulated_delay_ms_;

  delay_hist_.push_back(
      PacketTiming{(arrival_time - first_arrival_time_).ms_double(),
                   smoothed_delay_ms_, accumulated_delay_ms_});
  if (delay_hist_.size() > window_size_) {
    delay_hist_.pop_front();
  }

  double trend = prev_trend_;
  if (delay_hist_.size() == window_size_) {
    trend = LinearFitSlope(delay_hist_).value_or(trend);
  }
  Detect(trend, send_delta.ms_double(), arrival_time);
}

void TrendlineEstimator::Detect(double trend, double ts_delta, Timestamp now) {
  if (num_of_deltas_ < 2) {
    hypothesis_ = BandwidthUsage::kBwNormal;
    return;
  }
  const double modified_trend =
      std::min(num_of_deltas_, 60) * trend * threshold_gain_;

  if (modified_trend > threshold_) {
    if (time_over_using_ms_ == -1.0) {
      time_over_using_ms_ = ts_delta / 2.0;
    } else {
      time_over_using_ms_ += ts_delta;
    }
    ++overuse_counter_;
    if (time_over_using_ms_ > overusing_time_threshold_ms_ &&
        overuse_counter_ > 1) {
      if (trend >= prev_trend_) {
        time_over_using_ms_ = 0.0;
        overuse_counter_ = 0;
        hypothesis_ = BandwidthUsage::kBwOverusing;
      } else if (trend <= 0.0) {
        hypothesis_ = BandwidthUsage::kBwNormal;
      }
    }
  } else if (modified_trend < -threshold_) {
    time_over_using_ms_ = -1.0;
    overuse_counter_ = 0;
    hypothesis_ = BandwidthUsage::kBwUnderusing;
  } else {
    time_over_using_ms_ = -1.0;
    overuse_counter_ = 0;
    hypothesis_ = BandwidthUsage::kBwNormal;
  }
  prev_trend_ = trend;
  UpdateThreshold(modified_trend, now);
}

void TrendlineEstimator::UpdateThreshold(double modified_trend, Timestamp now) {
  if (last_update_time_.IsMinusInfinity()) {
    last_update_time_ = now;
  }
  if (std::fabs(modified_trend) > threshold_ + 15.0) {
    last_update_time_ = now;
    return;
  }
  const double k = (std::fabs(modified_trend) < threshold_) ? k_down_ : k_up_;
  const int64_t time_delta_ms =
      std::min<int64_t>((now - last_update_time_).ms(), 100);
  threshold_ += k * (std::fabs(modified_trend) - threshold_) *
                static_cast<double>(time_delta_ms);
  threshold_ = std::clamp(threshold_, 6.0, 600.0);
  last_update_time_ = now;
}

// ======================= 3. AckedBitrateEstimator 已确认码率估计与 AlrDetector =======================

void AckedBitrateEstimator::IncomingPacketFeedbackVector(
    const std::vector<PacketResult>& packet_feedback_vector) {
  for (const auto& pkt : packet_feedback_vector) {
    if (!pkt.IsReceived()) {
      continue;
    }
    if (alr_ended_time_.IsFinite() &&
        pkt.sent_packet.send_time > alr_ended_time_) {
      bitrate_estimate_var_ += 200.0f;
      alr_ended_time_ = Timestamp::MinusInfinity();
    }
    const int window_ms = (bitrate_estimate_kbps_ < 0.0f) ? 500 : 150;
    UpdateWindow(pkt.receive_time, pkt.sent_packet.size, window_ms);
  }
}

void AckedBitrateEstimator::UpdateWindow(Timestamp now,
                                         DataSize bytes,
                                         int rate_window_ms) {
  if (prev_time_.IsFinite() && now < prev_time_) {
    prev_time_ = Timestamp::MinusInfinity();
    sum_bytes_ = 0;
    current_window_ = Timestamp::MinusInfinity();
  }
  if (prev_time_.IsFinite()) {
    current_window_ = current_window_ + (now - prev_time_);
    if (now - prev_time_ > TimeDelta::Millis(rate_window_ms)) {
      sum_bytes_ = 0;
      current_window_ =
          Timestamp::Zero() + TimeDelta::Millis(now.ms() % rate_window_ms);
    }
  } else {
    current_window_ = Timestamp::Zero();
  }
  prev_time_ = now;
  sum_bytes_ += static_cast<int>(bytes.bytes());

  if (current_window_.us() < rate_window_ms * 1000) {
    return;
  }
  const float bitrate_sample_kbps =
      8.0f * static_cast<float>(sum_bytes_) / static_cast<float>(rate_window_ms);
  current_window_ = current_window_ - TimeDelta::Millis(rate_window_ms);
  sum_bytes_ = 0;

  if (bitrate_estimate_kbps_ < 0.0f) {
    bitrate_estimate_kbps_ = bitrate_sample_kbps;
    return;
  }

  const float sample_uncertainty =
      10.0f * std::fabs(bitrate_estimate_kbps_ - bitrate_sample_kbps) /
      std::max(bitrate_estimate_kbps_, 1.0f);
  const float sample_var = sample_uncertainty * sample_uncertainty;
  const float pred_var = bitrate_estimate_var_ + 5.0f;
  bitrate_estimate_kbps_ = (sample_var * bitrate_estimate_kbps_ +
                            pred_var * bitrate_sample_kbps) /
                           (sample_var + pred_var);
  bitrate_estimate_kbps_ = std::max(bitrate_estimate_kbps_, 10.0f);
  bitrate_estimate_var_ = (sample_var * pred_var) / (sample_var + pred_var);
}

std::optional<DataRate> AckedBitrateEstimator::bitrate() const {
  if (bitrate_estimate_kbps_ < 0.0f) {
    return std::nullopt;
  }
  return DataRate::BitsPerSec(
      static_cast<int64_t>(bitrate_estimate_kbps_ * 1000.0f));
}

std::optional<DataRate> AckedBitrateEstimator::PeekRate() const {
  return bitrate();
}

AlrDetector::AlrDetector() : alr_budget_(0, true) {}

void AlrDetector::SetEstimatedBitrate(DataRate bitrate) {
  const int target_kbps = static_cast<int>(bitrate.kbps() * 0.65);
  alr_budget_.set_target_rate_kbps(target_kbps);
}

void AlrDetector::OnBytesSent(size_t bytes_sent, Timestamp send_time) {
  if (last_send_time_.IsMinusInfinity()) {
    last_send_time_ = send_time;
    return;
  }
  const int64_t delta_us =
      std::max<int64_t>(0, (send_time - last_send_time_).us());
  last_send_time_ = send_time;

  alr_budget_.UseBudget(bytes_sent);
  alr_budget_.IncreaseBudgetUs(delta_us);

  if (alr_budget_.budget_ratio() > 0.80 && !alr_started_time_.has_value()) {
    alr_started_time_ = send_time;
    RTC_LOG(kVerbose) << "Entered Application-Limited Region (ALR)";
  } else if (alr_budget_.budget_ratio() < 0.50 &&
             alr_started_time_.has_value()) {
    alr_started_time_.reset();
    RTC_LOG(kVerbose) << "Exited Application-Limited Region (ALR)";
  }
}

// ======================= 4. AimdRateControl AIMD 码率控制 =======================

AimdRateControl::AimdRateControl(DataRate min_bitrate,
                                 DataRate max_bitrate,
                                 DataRate start_bitrate)
    : min_configured_bitrate_(min_bitrate),
      max_configured_bitrate_(max_bitrate),
      current_bitrate_(std::clamp(start_bitrate, min_bitrate, max_bitrate)),
      bitrate_is_initialized_(start_bitrate > DataRate::Zero()) {}

void AimdRateControl::SetStartBitrate(DataRate start_bitrate) {
  current_bitrate_ =
      std::clamp(start_bitrate, min_configured_bitrate_, max_configured_bitrate_);
  bitrate_is_initialized_ = true;
}

void AimdRateControl::SetCapacityEstimate(DataRate link_capacity) {
  if (link_capacity > DataRate::Zero()) {
    link_capacity_estimate_kbps_ = link_capacity;
  }
}

void AimdRateControl::SetEstimate(DataRate bitrate, Timestamp at_time) {
  bitrate_is_initialized_ = true;
  const DataRate prev = current_bitrate_;
  current_bitrate_ =
      std::clamp(bitrate, min_configured_bitrate_, max_configured_bitrate_);
  time_last_bitrate_change_ = at_time;
  if (current_bitrate_ < prev) {
    time_last_bitrate_decrease_ = at_time;
  } else if (link_capacity_estimate_kbps_.has_value() &&
             current_bitrate_ > *link_capacity_estimate_kbps_) {
    link_capacity_estimate_kbps_.reset();
  }
}

void AimdRateControl::SetMinMaxBitrate(DataRate min_bitrate,
                                       DataRate max_bitrate) {
  min_configured_bitrate_ = min_bitrate;
  max_configured_bitrate_ = std::max(min_bitrate, max_bitrate);
  current_bitrate_ = std::clamp(current_bitrate_, min_configured_bitrate_,
                                max_configured_bitrate_);
}

bool AimdRateControl::TimeToReduceFurther(
    Timestamp at_time,
    DataRate estimated_throughput) const {
  const TimeDelta reduction_interval =
      std::clamp(rtt_, TimeDelta::Millis(10), TimeDelta::Millis(200));
  if (at_time - time_last_bitrate_change_ >= reduction_interval) {
    return true;
  }
  return estimated_throughput < current_bitrate_ * 0.5;
}

DataRate AimdRateControl::Update(BandwidthUsage bw_state,
                                 std::optional<DataRate> estimated_throughput,
                                 Timestamp at_time) {
  if (!bitrate_is_initialized_ && estimated_throughput.has_value()) {
    if (time_first_throughput_estimate_.IsMinusInfinity()) {
      time_first_throughput_estimate_ = at_time;
    } else if (at_time - time_first_throughput_estimate_ >
               TimeDelta::Seconds(3)) {
      current_bitrate_ = *estimated_throughput;
      bitrate_is_initialized_ = true;
    }
  }

  ChangeState(bw_state, at_time);
  if (time_last_bitrate_change_.IsMinusInfinity()) {
    time_last_bitrate_change_ = at_time;
  }

  const DataRate throughput = estimated_throughput.value_or(current_bitrate_);

  switch (rate_control_state_) {
    case RateControlState::kRcHold:
      break;

    case RateControlState::kRcIncrease: {
      if (link_capacity_estimate_kbps_.has_value() &&
          throughput >
              *link_capacity_estimate_kbps_ +
                  DataRate::KilobitsPerSec(static_cast<int64_t>(
                      3.0 * std::sqrt(var_max_bitrate_kbps_) *
                      link_capacity_estimate_kbps_->kbps()))) {
        link_capacity_estimate_kbps_.reset();
      }

      DataRate increased = current_bitrate_;
      if (link_capacity_estimate_kbps_.has_value()) {
        increased += AdditiveRateIncrease(at_time, time_last_bitrate_change_);
      } else {
        increased = MultiplicativeRateIncrease(
            at_time, time_last_bitrate_change_, current_bitrate_);
      }
      if (estimated_throughput.has_value()) {
        const DataRate upper_bound =
            (*estimated_throughput * 1.5) + DataRate::KilobitsPerSec(20);
        if (increased > current_bitrate_ && increased > upper_bound) {
          increased = std::max(current_bitrate_, upper_bound);
        }
      }
      current_bitrate_ = std::min(increased, max_configured_bitrate_);
      time_last_bitrate_change_ = at_time;
      break;
    }

    case RateControlState::kRcDecrease: {
      DataRate decreased = throughput * beta_;
      if (decreased > current_bitrate_) {
        if (link_capacity_estimate_kbps_.has_value()) {
          decreased = *link_capacity_estimate_kbps_ * beta_;
        }
        decreased = std::min(decreased, current_bitrate_ * beta_);
      }

      const double sample_kbps = static_cast<double>(throughput.kbps());
      if (!link_capacity_estimate_kbps_.has_value()) {
        link_capacity_estimate_kbps_ = throughput;
      } else {
        const double norm =
            std::max<double>(link_capacity_estimate_kbps_->kbps(), 1.0);
        const double err =
            (link_capacity_estimate_kbps_->kbps() - sample_kbps) / norm;
        var_max_bitrate_kbps_ =
            std::clamp(0.95 * var_max_bitrate_kbps_ + 0.05 * err * err, 0.01,
                       0.5);
        link_capacity_estimate_kbps_ = DataRate::KilobitsPerSec(
            static_cast<int64_t>(0.90 * link_capacity_estimate_kbps_->kbps() +
                                 0.10 * sample_kbps));
      }

      const DataRate prev_rate = current_bitrate_;
      bitrate_is_initialized_ = true;
      current_bitrate_ = std::clamp(decreased, min_configured_bitrate_,
                                    max_configured_bitrate_);
      RTC_LOG(kInfo) << "GoogCC AIMD delay-overuse backoff: "
                     << prev_rate.kbps() << " kbps -> "
                     << current_bitrate_.kbps()
                     << " kbps (acked=" << throughput.kbps() << " kbps)";
      rate_control_state_ = RateControlState::kRcHold;
      time_last_bitrate_change_ = at_time;
      time_last_bitrate_decrease_ = at_time;
      break;
    }
  }
  return current_bitrate_;
}

DataRate AimdRateControl::MultiplicativeRateIncrease(
    Timestamp at_time,
    Timestamp last_time,
    DataRate current_bitrate) const {
  double alpha = 1.08;
  if (last_time.IsFinite()) {
    const double seconds = std::min((at_time - last_time).seconds_double(), 1.0);
    alpha = std::pow(alpha, seconds);
  }
  const DataRate inc =
      std::max(current_bitrate * (alpha - 1.0), DataRate::BitsPerSec(1000));
  return current_bitrate + inc;
}

DataRate AimdRateControl::AdditiveRateIncrease(Timestamp at_time,
                                               Timestamp last_time) const {
  const double time_delta_s =
      last_time.IsFinite() ? std::min((at_time - last_time).seconds_double(), 1.0)
                           : 0.0;
  const double response_time_s = 0.100 + rtt_.seconds_double();
  constexpr double kAvgPacketBits = 1100.0 * 8.0;
  const double bps_increase =
      std::max(4000.0, (kAvgPacketBits / response_time_s) * time_delta_s);
  return DataRate::BitsPerSec(static_cast<int64_t>(bps_increase));
}

void AimdRateControl::ChangeState(BandwidthUsage bw_state, Timestamp at_time) {
  switch (bw_state) {
    case BandwidthUsage::kBwNormal:
      if (rate_control_state_ == RateControlState::kRcHold) {
        time_last_bitrate_change_ = at_time;
        rate_control_state_ = RateControlState::kRcIncrease;
      }
      break;
    case BandwidthUsage::kBwOverusing:
      if (rate_control_state_ != RateControlState::kRcDecrease) {
        rate_control_state_ = RateControlState::kRcDecrease;
      }
      break;
    case BandwidthUsage::kBwUnderusing:
      rate_control_state_ = RateControlState::kRcHold;
      break;
  }
}

// ======================= 5. SendSideBandwidthEstimation 发送端带宽估计 =======================

SendSideBandwidthEstimation::SendSideBandwidthEstimation(DataRate min_bitrate,
                                                         DataRate max_bitrate,
                                                         DataRate start_bitrate)
    : min_bitrate_(min_bitrate),
      max_bitrate_(max_bitrate),
      current_target_(std::clamp(start_bitrate, min_bitrate, max_bitrate)) {}

void SendSideBandwidthEstimation::UpdateReceiverReport(Timestamp at_time,
                                                       uint8_t fraction_lost,
                                                       TimeDelta rtt) {
  last_fraction_loss_ = fraction_lost;
  if (rtt > TimeDelta::Zero()) {
    last_rtt_ = rtt;
  }
  last_loss_feedback_ = at_time;
  last_loss_packet_report_ = at_time;
  UpdateEstimate(at_time);
}

void SendSideBandwidthEstimation::UpdatePacketsLost(int64_t packets_lost,
                                                    int64_t number_of_packets,
                                                    Timestamp at_time) {
  last_loss_feedback_ = at_time;
  lost_packets_since_last_loss_update_ += packets_lost;
  expected_packets_since_last_loss_update_ += number_of_packets;

  if (expected_packets_since_last_loss_update_ < 12) {
    return;
  }
  const int64_t lost_q8 = std::clamp<int64_t>(
      (lost_packets_since_last_loss_update_ * 256) /
          expected_packets_since_last_loss_update_,
      0, 255);
  last_fraction_loss_ = static_cast<uint8_t>(lost_q8);
  last_loss_packet_report_ = at_time;
  lost_packets_since_last_loss_update_ = 0;
  expected_packets_since_last_loss_update_ = 0;
  UpdateEstimate(at_time);
}

void SendSideBandwidthEstimation::UpdateDelayBasedEstimate(Timestamp at_time,
                                                           DataRate bitrate) {
  delay_based_limit_ =
      bitrate > DataRate::Zero() ? bitrate : DataRate::Infinity();
  UpdateEstimate(at_time);
}

void SendSideBandwidthEstimation::ApplyProbeBitrate(Timestamp at_time,
                                                    DataRate bitrate) {
  delay_based_limit_ =
      bitrate > DataRate::Zero() ? bitrate : DataRate::Infinity();
  // 当主动探测簇在当前低丢包条件下实测到更高的可用带宽时，解除陈旧的丢包限速状态并对齐目标码率。
  if (last_fraction_loss_ <= 12 && bitrate > current_target_) {
    is_loss_limited_ = false;
    current_target_ = std::clamp(bitrate, min_bitrate_, max_bitrate_);
    time_last_loss_ramp_ = at_time;
    return;
  }
  UpdateEstimate(at_time);
}

void SendSideBandwidthEstimation::SetAcknowledgedRate(
    std::optional<DataRate> acked_rate,
    Timestamp /*at_time*/) {
  acknowledged_rate_ = acked_rate;
}

void SendSideBandwidthEstimation::UpdateEstimate(Timestamp at_time) {
  // 若超过 1.5 秒未收到新的高丢包统计，自动衰减陈旧丢包率，防止定时器基于旧丢包率锁死码率。
  if (last_loss_packet_report_.IsFinite() &&
      (at_time - last_loss_packet_report_) > TimeDelta::Millis(1500) &&
      last_fraction_loss_ > 0) {
    last_fraction_loss_ = 0;
  }

  if (!is_loss_limited_ &&
      (!last_loss_feedback_.IsFinite() || last_fraction_loss_ <= 26)) {
    const DataRate uncapped = delay_based_limit_.IsFinite()
                                  ? delay_based_limit_
                                  : current_target_;
    current_target_ = std::clamp(uncapped, min_bitrate_, max_bitrate_);
    time_last_loss_ramp_ = at_time;
    return;
  }

  DataRate new_target = current_target_;
  if (last_loss_feedback_.IsFinite()) {
    const bool has_fresh_loss_report =
        last_loss_packet_report_.IsFinite() &&
        (time_last_decrease_.IsMinusInfinity() ||
         last_loss_packet_report_ > time_last_decrease_);
    if (last_fraction_loss_ > 26 && has_fresh_loss_report) {
      const TimeDelta min_decrease_interval =
          TimeDelta::Millis(300) + last_rtt_;
      if (time_last_decrease_.IsMinusInfinity() ||
          (at_time - time_last_decrease_) >= min_decrease_interval) {
        const double loss = static_cast<double>(last_fraction_loss_) / 256.0;
        DataRate base = current_target_;
        if (acknowledged_rate_.has_value()) {
          base = std::max(*acknowledged_rate_, current_target_ * 0.7);
        }
        new_target = base * std::max(0.5, 1.0 - 0.5 * loss);
        is_loss_limited_ = true;
        time_last_decrease_ = at_time;
        time_last_loss_ramp_ = at_time;
        RTC_LOG(kWarning) << "SendSideBWE high packet loss ("
                          << static_cast<int>(loss * 100.0)
                          << "%), reducing target to " << new_target.kbps()
                          << " kbps";
      }
    } else if (last_fraction_loss_ <= 12) {
      // 丢包缓解后，按时间步进执行乘性加性码率恢复。
      const double dt_sec =
          time_last_loss_ramp_.IsFinite()
              ? std::clamp((at_time - time_last_loss_ramp_).seconds_double(),
                           0.0, 1.0)
              : 0.0;
      if (dt_sec >= 0.025) {
        time_last_loss_ramp_ = at_time;
        const DataRate stepped =
            current_target_ * std::pow(1.08, dt_sec) +
            DataRate::BitsPerSec(static_cast<int64_t>(4000.0 * dt_sec));
        new_target = std::min(delay_based_limit_, stepped);
        if (delay_based_limit_.IsFinite() && new_target >= delay_based_limit_) {
          is_loss_limited_ = false;
        }
      }
    }
  }

  new_target = std::min(new_target, delay_based_limit_);
  current_target_ = std::clamp(new_target, min_bitrate_, max_bitrate_);
}

// ======================= 5b. ProbeBitrateEstimator 探测码率估计 =======================

void ProbeBitrateEstimator::EraseOldClusters(Timestamp timestamp) {
  for (auto it = clusters_.begin(); it != clusters_.end();) {
    if (it->second.last_receive + TimeDelta::Seconds(1) < timestamp) {
      it = clusters_.erase(it);
    } else {
      ++it;
    }
  }
}

std::optional<DataRate> ProbeBitrateEstimator::HandleProbeAndEstimateBitrate(
    const PacketResult& packet_feedback) {
  const int cluster_id = packet_feedback.sent_packet.pacing_info.probe_cluster_id;
  if (cluster_id == PacedPacketInfo::kNotAProbe ||
      !packet_feedback.IsReceived()) {
    return std::nullopt;
  }

  EraseOldClusters(packet_feedback.receive_time);
  AggregatedCluster* cluster = &clusters_[cluster_id];

  if (packet_feedback.sent_packet.send_time < cluster->first_send) {
    cluster->first_send = packet_feedback.sent_packet.send_time;
  }
  if (packet_feedback.sent_packet.send_time > cluster->last_send) {
    cluster->last_send = packet_feedback.sent_packet.send_time;
    cluster->size_last_send = packet_feedback.sent_packet.size;
  } else if (packet_feedback.sent_packet.send_time == cluster->last_send) {
    cluster->size_last_send += packet_feedback.sent_packet.size;
  }
  if (packet_feedback.receive_time < cluster->first_receive) {
    cluster->first_receive = packet_feedback.receive_time;
    cluster->size_first_receive = packet_feedback.sent_packet.size;
  } else if (packet_feedback.receive_time == cluster->first_receive) {
    cluster->size_first_receive += packet_feedback.sent_packet.size;
  }
  if (packet_feedback.receive_time > cluster->last_receive) {
    cluster->last_receive = packet_feedback.receive_time;
  }
  cluster->size_total += packet_feedback.sent_packet.size;
  cluster->num_probes += 1;

  const int min_probes =
      std::max(3, packet_feedback.sent_packet.pacing_info.probe_cluster_min_probes);
  const DataSize min_bytes = DataSize::Bytes(std::max(
      400, packet_feedback.sent_packet.pacing_info.probe_cluster_min_bytes));
  if (cluster->num_probes < min_probes || cluster->size_total < min_bytes) {
    return std::nullopt;
  }

  const TimeDelta send_interval = cluster->last_send - cluster->first_send;
  const TimeDelta receive_interval =
      cluster->last_receive - cluster->first_receive;
  if (send_interval <= TimeDelta::Zero() ||
      receive_interval <= TimeDelta::Zero()) {
    return std::nullopt;
  }

  const DataSize send_size = cluster->size_total - cluster->size_last_send;
  const DataSize receive_size =
      cluster->size_total - cluster->size_first_receive;
  if (send_size <= DataSize::Zero() || receive_size <= DataSize::Zero()) {
    return std::nullopt;
  }

  const DataRate send_rate = send_size / send_interval;
  const DataRate receive_rate = receive_size / receive_interval;
  const double ratio =
      static_cast<double>(receive_rate.bps()) /
      std::max<double>(1.0, static_cast<double>(send_rate.bps()));
  if (ratio > 2.0) {
    clusters_.erase(cluster_id);
    return std::nullopt;
  }

  DataRate res = std::min(send_rate, receive_rate);
  if (receive_rate < send_rate * 0.90) {
    // 探测期间链路饱和：此时接收速率即反映瓶颈链路容量。
    res = receive_rate * 0.95;
    last_probe_saturated_ = true;
  } else {
    last_probe_saturated_ = false;
  }

  clusters_.erase(cluster_id);
  estimated_data_rate_ = res;
  RTC_LOG(kVerbose) << "ProbeBitrateEstimator cluster=" << cluster_id
                    << " send_kbps=" << send_rate.kbps()
                    << " recv_kbps=" << receive_rate.kbps()
                    << " estimated_kbps=" << res.kbps();
  return res;
}

std::optional<DataRate>
ProbeBitrateEstimator::FetchAndResetLastEstimatedBitrate() {
  std::optional<DataRate> est = estimated_data_rate_;
  estimated_data_rate_.reset();
  return est;
}

// ======================= 6. ProbeController 带宽探测控制器 =======================

std::vector<ProbeClusterConfig> ProbeController::SetBitrates(
    DataRate /*min_bitrate*/,
    DataRate start_bitrate,
    DataRate max_bitrate,
    Timestamp at_time) {
  start_bitrate_ = start_bitrate;
  max_bitrate_ = max_bitrate;
  if (state_ == State::kInit && start_bitrate_ > DataRate::Zero()) {
    return InitiateProbing(
        at_time, {start_bitrate_ * 3.0, start_bitrate_ * 6.0}, true);
  }
  return {};
}

std::vector<ProbeClusterConfig> ProbeController::SetEstimatedBitrate(
    DataRate bitrate,
    bool bwe_limited_due_to_packet_loss,
    Timestamp at_time) {
  estimated_bitrate_ = bitrate;
  if (bwe_limited_due_to_packet_loss) {
    state_ = State::kProbingComplete;
    return {};
  }
  if (state_ == State::kWaitingForProbingResult &&
      bitrate >= min_bitrate_to_probe_further_) {
    return InitiateProbing(at_time, {bitrate * 2.0}, true);
  }
  return {};
}

std::vector<ProbeClusterConfig> ProbeController::RequestProbe(
    Timestamp at_time) {
  if (alr_start_time_.has_value() && estimated_bitrate_ > DataRate::Zero()) {
    const DataRate suggested = std::min(max_bitrate_, estimated_bitrate_ * 2.0);
    if (suggested > estimated_bitrate_) {
      return InitiateProbing(at_time, {suggested}, true);
    }
  }
  return {};
}

std::vector<ProbeClusterConfig> ProbeController::Process(Timestamp at_time) {
  // 对齐上游 WebRTC kMaxWaitingTimeForProbingResult (1s)：防止探测包丢失或过载抑制导致状态永久卡在等待态。
  if (state_ == State::kWaitingForProbingResult &&
      time_last_probing_initiated_.IsFinite() &&
      (at_time - time_last_probing_initiated_) >= TimeDelta::Seconds(1)) {
    state_ = State::kProbingComplete;
    min_bitrate_to_probe_further_ = DataRate::Infinity();
  }

  if (alr_start_time_.has_value() && estimated_bitrate_ > DataRate::Zero() &&
      (time_last_probing_initiated_.IsMinusInfinity() ||
       (at_time - time_last_probing_initiated_) >= TimeDelta::Seconds(5))) {
    const DataRate probe_rate =
        std::min(max_bitrate_, estimated_bitrate_ * 2.0);
    if (probe_rate > estimated_bitrate_ * 1.15) {
      return InitiateProbing(at_time, {probe_rate}, true);
    }
  }
  // 拥塞降码率后的周期性恢复探测：当估计码率显著低于最大允许码率时，每 1.8 秒发起一次短促 1.8x 探测簇，
  // 以便在物理瓶颈带宽恢复后迅速探测到新增容量；若链路仍饱和则由 ProbeBitrateEstimator 自动截断。
  if (state_ == State::kProbingComplete &&
      estimated_bitrate_ > DataRate::Zero() &&
      estimated_bitrate_ < max_bitrate_ * 0.75 &&
      (time_last_probing_initiated_.IsMinusInfinity() ||
       (at_time - time_last_probing_initiated_) >= TimeDelta::Millis(1800))) {
    const DataRate probe_rate =
        std::min(max_bitrate_, estimated_bitrate_ * 1.8);
    if (probe_rate > estimated_bitrate_ * 1.15) {
      return InitiateProbing(at_time, {probe_rate}, true);
    }
  }
  return {};
}

std::vector<ProbeClusterConfig> ProbeController::InitiateProbing(
    Timestamp now,
    std::vector<DataRate> bitrates_to_probe,
    bool probe_further) {
  std::vector<ProbeClusterConfig> pending;
  for (DataRate rate : bitrates_to_probe) {
    rate = std::min(rate, max_bitrate_);
    if (rate <= DataRate::Zero()) {
      continue;
    }

    ProbeClusterConfig cfg;
    cfg.at_time = now;
    cfg.target_data_rate = rate;
    cfg.target_duration = TimeDelta::Millis(15);
    cfg.target_probe_count = 5;
    cfg.id = next_probe_cluster_id_++;
    pending.push_back(cfg);
  }
  time_last_probing_initiated_ = now;
  if (probe_further && !pending.empty()) {
    state_ = State::kWaitingForProbingResult;
    min_bitrate_to_probe_further_ = pending.back().target_data_rate * 0.7;
  } else {
    state_ = State::kProbingComplete;
    min_bitrate_to_probe_further_ = DataRate::Infinity();
  }
  return pending;
}

// ======================= 7. TransportFeedbackAdapter 传输反馈适配器 =======================

void TransportFeedbackAdapter::AddPacket(uint16_t transport_seq_num,
                                         DataSize packet_size,
                                         const PacedPacketInfo& pacing_info,
                                         Timestamp /*creation_time*/) {
  const int64_t unwrapped = seq_unwrapper_.Unwrap(transport_seq_num);
  PacketFeedbackRecord rec;
  rec.sent.sequence_number = unwrapped;
  rec.sent.size = packet_size;
  rec.sent.pacing_info = pacing_info;
  history_[unwrapped] = rec;

  while (history_.size() > 4096) {
    if (!history_.begin()->second.has_been_acked &&
        history_.begin()->second.sent.send_time.IsFinite()) {
      in_flight_bytes_ -= history_.begin()->second.sent.size;
    }
    history_.erase(history_.begin());
  }
}

std::optional<SentPacket> TransportFeedbackAdapter::ProcessSentPacket(
    uint16_t transport_seq_num,
    Timestamp send_time) {
  const int64_t unwrapped = seq_unwrapper_.PeekUnwrap(transport_seq_num);
  const auto it = history_.find(unwrapped);
  if (it == history_.end()) {
    return std::nullopt;
  }
  auto& rec = it->second;
  const bool first_send = rec.sent.send_time.IsMinusInfinity();
  rec.sent.send_time = send_time;
  rec.sent.prior_unacked_data = in_flight_bytes_;
  if (first_send && !rec.has_been_acked) {
    in_flight_bytes_ += rec.sent.size;
  }
  rec.sent.data_in_flight = in_flight_bytes_;
  return rec.sent;
}

std::optional<TransportPacketsFeedback>
TransportFeedbackAdapter::ProcessTransportFeedback(
    const RtcpTransportFeedback& feedback,
    Timestamp feedback_receive_time) {
  if (feedback.num_seq_no() == 0) {
    return std::nullopt;
  }
  TransportPacketsFeedback msg;
  msg.feedback_time = feedback_receive_time;
  msg.prior_in_flight = in_flight_bytes_;

  // 对 24 位 TWCC 基准时间刻度（单位 64ms）执行模 2^24 单调展开，消除跨 6.21 天边界的时间跳变。
  constexpr int64_t kTwccBaseTickUs = 64000;
  constexpr int64_t kTwccMod = int64_t{1} << 24;
  const int64_t wire_ref_ticks =
      (feedback.BaseTime().us() / kTwccBaseTickUs) & (kTwccMod - 1);
  if (!last_unwrapped_ref_ticks_.has_value()) {
    last_unwrapped_ref_ticks_ = wire_ref_ticks;
  } else {
    int64_t diff =
        (wire_ref_ticks - (*last_unwrapped_ref_ticks_ & (kTwccMod - 1))) &
        (kTwccMod - 1);
    if (diff >= (kTwccMod / 2)) {
      diff -= kTwccMod;
    }
    *last_unwrapped_ref_ticks_ += diff;
  }
  const TimeDelta base_offset =
      Timestamp::Micros(*last_unwrapped_ref_ticks_ * kTwccBaseTickUs) -
      feedback.BaseTime();

  const auto statuses = feedback.AllPacketStatuses();
  if (statuses.empty()) {
    return std::nullopt;
  }
  msg.packet_feedbacks.reserve(statuses.size() + 16);

  // 回收两次 TWCC 报告之间因尾部丢包被跳过的未确认序列号区间，彻底防止 in_flight_bytes_ 泄漏导致 Pacer 拥塞窗口死锁。
  const int64_t first_seq_unwrapped =
      seq_unwrapper_.PeekUnwrap(statuses.front().sequence_number);
  if (last_ack_seq_num_ >= 0 && first_seq_unwrapped > last_ack_seq_num_ + 1) {
    auto gap_it = history_.upper_bound(last_ack_seq_num_);
    while (gap_it != history_.end() && gap_it->first < first_seq_unwrapped) {
      auto& rec = gap_it->second;
      if (rec.sent.send_time.IsFinite() && !rec.has_been_acked) {
        rec.has_been_acked = true;
        in_flight_bytes_ =
            std::max(DataSize::Zero(), in_flight_bytes_ - rec.sent.size);
        PacketResult lost_res;
        lost_res.sent_packet = rec.sent;
        lost_res.receive_time = Timestamp::PlusInfinity();
        msg.packet_feedbacks.push_back(lost_res);
      }
      ++gap_it;
    }
  }

  for (const auto& st : statuses) {
    const int64_t unwrapped = seq_unwrapper_.PeekUnwrap(st.sequence_number);
    last_ack_seq_num_ = std::max(last_ack_seq_num_, unwrapped);
    const auto it = history_.find(unwrapped);
    if (it == history_.end() ||
        it->second.sent.send_time.IsMinusInfinity()) {
      continue;
    }
    auto& rec = it->second;
    if (!rec.has_been_acked) {
      rec.has_been_acked = true;
      in_flight_bytes_ =
          std::max(DataSize::Zero(), in_flight_bytes_ - rec.sent.size);
    }
    PacketResult res;
    res.sent_packet = rec.sent;
    res.receive_time = st.receive_time.IsFinite()
                           ? (st.receive_time + base_offset)
                           : st.receive_time;
    msg.packet_feedbacks.push_back(res);
  }

  CullExpiredInFlight(feedback_receive_time);

  msg.data_in_flight = in_flight_bytes_;
  for (const auto& [seq, rec] : history_) {
    (void)seq;
    if (!rec.has_been_acked && rec.sent.send_time.IsFinite()) {
      msg.first_unacked_send_time = rec.sent.send_time;
      break;
    }
  }
  if (msg.packet_feedbacks.empty()) {
    return std::nullopt;
  }
  return msg;
}

void TransportFeedbackAdapter::CullExpiredInFlight(Timestamp now) {
  if (!now.IsFinite()) {
    return;
  }
  // 回收超过 1000ms 仍未收到任何反馈的超时在途字节，配合 Pacer 60ms 保活探测彻底消除死锁且不误伤深队列报文。
  for (auto& [seq, rec] : history_) {
    (void)seq;
    if (rec.sent.send_time.IsFinite() &&
        (now - rec.sent.send_time) > TimeDelta::Millis(1000)) {
      if (!rec.has_been_acked) {
        rec.has_been_acked = true;
        in_flight_bytes_ =
            std::max(DataSize::Zero(), in_flight_bytes_ - rec.sent.size);
      }
    } else if (rec.sent.send_time.IsFinite()) {
      break;
    }
  }
}

// ======================= 8. GoogCcNetworkController 拥塞控制器 =======================

GoogCcNetworkController::GoogCcNetworkController(const GoogCcConfig& config)
    : config_(config),
      delay_based_bwe_(config.min_bitrate,
                       config.max_bitrate,
                       config.start_bitrate),
      bandwidth_estimation_(config.min_bitrate,
                            config.max_bitrate,
                            config.start_bitrate) {
  alr_detector_.SetEstimatedBitrate(config.start_bitrate);
}

NetworkControlUpdate GoogCcNetworkController::OnNetworkAvailability(
    Timestamp at_time,
    bool network_available) {
  NetworkControlUpdate update;
  if (network_available) {
    update.probe_cluster_configs = probe_controller_.SetBitrates(
        config_.min_bitrate, config_.start_bitrate, config_.max_bitrate,
        at_time);
    MaybeTriggerOnNetworkChanged(&update, at_time);
  }
  return update;
}

NetworkControlUpdate GoogCcNetworkController::OnSentPacket(
    const SentPacket& sent_packet) {
  alr_detector_.OnBytesSent(static_cast<size_t>(sent_packet.size.bytes()),
                            sent_packet.send_time);
  const auto alr_start = alr_detector_.GetApplicationLimitedRegionStartTime();
  acked_bitrate_estimator_.set_alr(alr_start.has_value());
  if (!previously_in_alr_ && alr_start.has_value()) {
    previously_in_alr_ = true;
  }
  probe_controller_.set_alr_start_time(alr_start);
  return NetworkControlUpdate{};
}

NetworkControlUpdate GoogCcNetworkController::OnTransportPacketsFeedback(
    const TransportPacketsFeedback& report) {
  NetworkControlUpdate update;
  if (report.packet_feedbacks.empty()) {
    return update;
  }

  const bool currently_in_alr =
      alr_detector_.GetApplicationLimitedRegionStartTime().has_value();
  if (previously_in_alr_ && !currently_in_alr) {
    acked_bitrate_estimator_.set_alr_ended_time(report.feedback_time);
    auto probes = probe_controller_.RequestProbe(report.feedback_time);
    update.probe_cluster_configs.insert(update.probe_cluster_configs.end(),
                                        probes.begin(), probes.end());
  }
  previously_in_alr_ = currently_in_alr;

  const auto received = report.ReceivedWithSendInfo();
  const int64_t lost_count =
      static_cast<int64_t>(report.packet_feedbacks.size()) -
      static_cast<int64_t>(received.size());
  bandwidth_estimation_.UpdatePacketsLost(
      lost_count, static_cast<int64_t>(report.packet_feedbacks.size()),
      report.feedback_time);

  acked_bitrate_estimator_.IncomingPacketFeedbackVector(received);
  const auto acked_bitrate = acked_bitrate_estimator_.bitrate();
  bandwidth_estimation_.SetAcknowledgedRate(acked_bitrate, report.feedback_time);

  Timestamp latest_packet_send_time = Timestamp::MinusInfinity();
  bool has_probe_feedback = false;
  for (const auto& fb : received) {
    latest_packet_send_time =
        std::max(latest_packet_send_time, fb.sent_packet.send_time);
    if (fb.sent_packet.pacing_info.probe_cluster_id !=
        PacedPacketInfo::kNotAProbe) {
      has_probe_feedback = true;
    }
    probe_bitrate_estimator_.HandleProbeAndEstimateBitrate(fb);

    TimeDelta send_delta = TimeDelta::Zero();
    TimeDelta recv_delta = TimeDelta::Zero();
    int size_delta = 0;
    const bool has_deltas = inter_arrival_delta_.ComputeDeltas(
        fb.sent_packet.send_time, fb.receive_time, report.feedback_time,
        static_cast<size_t>(fb.sent_packet.size.bytes()), &send_delta,
        &recv_delta, &size_delta);
    trendline_estimator_.Update(
        recv_delta, send_delta, fb.sent_packet.send_time, fb.receive_time,
        static_cast<size_t>(fb.sent_packet.size.bytes()), has_deltas);
  }

  if (latest_packet_send_time.IsFinite() &&
      report.feedback_time > latest_packet_send_time) {
    const TimeDelta fb_rtt = report.feedback_time - latest_packet_send_time;
    delay_based_bwe_.set_rtt(fb_rtt);
  }

  const std::optional<DataRate> probe_bitrate =
      probe_bitrate_estimator_.FetchAndResetLastEstimatedBitrate();
  BandwidthUsage state = trendline_estimator_.State();

  // 拥塞窗口回推：若在途数据量顶满拥塞窗口，且实际吞吐量明显低于当前估计值，
  // 则触发过载信号以排空驻留队列；但在主动探测刚提速后的吞吐量滑窗预热期内跳过回推，避免误杀新探测结果。
  const bool in_probe_grace_window =
      has_probe_feedback || probe_bitrate.has_value() ||
      (last_probe_result_time_.IsFinite() &&
       (report.feedback_time - last_probe_result_time_) <
           TimeDelta::Millis(550));
  const DataSize current_cwnd = std::max(
      DataSize::Bytes(4800),
      bandwidth_estimation_.target_rate() *
          (bandwidth_estimation_.rtt() + TimeDelta::Millis(150)));
  if (!in_probe_grace_window && state == BandwidthUsage::kBwNormal &&
      acked_bitrate.has_value() &&
      report.prior_in_flight.bytes() * 10 >= current_cwnd.bytes() * 8 &&
      *acked_bitrate < delay_based_bwe_.LatestEstimate() * 0.82) {
    state = BandwidthUsage::kBwOverusing;
  }

  if (probe_bitrate.has_value()) {
    if (state != BandwidthUsage::kBwOverusing) {
      last_probe_result_time_ = report.feedback_time;
      delay_based_bwe_.SetEstimate(*probe_bitrate, report.feedback_time);
      if (probe_bitrate_estimator_.last_probe_saturated()) {
        delay_based_bwe_.SetCapacityEstimate(*probe_bitrate * (1.0 / 0.95));
      }
      bandwidth_estimation_.ApplyProbeBitrate(
          report.feedback_time, delay_based_bwe_.LatestEstimate());
      const bool stop_further_probing =
          (bandwidth_estimation_.target_rate() < *probe_bitrate) ||
          probe_bitrate_estimator_.last_probe_saturated() ||
          (*probe_bitrate < bandwidth_estimation_.target_rate());
      auto probes = probe_controller_.SetEstimatedBitrate(
          bandwidth_estimation_.target_rate(), stop_further_probing,
          report.feedback_time);
      update.probe_cluster_configs.insert(update.probe_cluster_configs.end(),
                                          probes.begin(), probes.end());
    } else {
      // 探测簇期间处于过载状态，立即结束本轮探测等待，以便后续周期性恢复探测正常触发。
      probe_controller_.SetEstimatedBitrate(bandwidth_estimation_.target_rate(),
                                            /*bwe_limited_due_to_packet_loss=*/true,
                                            report.feedback_time);
    }
  }

  const bool fresh_packets_since_last_decrease =
      delay_based_bwe_.LastDecreaseTime().IsMinusInfinity() ||
      (latest_packet_send_time.IsFinite() &&
       latest_packet_send_time > delay_based_bwe_.LastDecreaseTime());

  bool should_update_delay_bwe = false;
  if (state == BandwidthUsage::kBwOverusing) {
    if (prev_detector_state_ != BandwidthUsage::kBwOverusing &&
        fresh_packets_since_last_decrease) {
      should_update_delay_bwe = true;
    } else if (fresh_packets_since_last_decrease && acked_bitrate.has_value() &&
               delay_based_bwe_.TimeToReduceFurther(report.feedback_time,
                                                    *acked_bitrate)) {
      should_update_delay_bwe = true;
    }
  } else if (state == BandwidthUsage::kBwNormal) {
    should_update_delay_bwe = !probe_bitrate.has_value();
  } else {
    should_update_delay_bwe = (state != prev_detector_state_);
  }

  if (should_update_delay_bwe) {
    const DataRate new_delay_rate =
        delay_based_bwe_.Update(state, acked_bitrate, report.feedback_time);
    bandwidth_estimation_.UpdateDelayBasedEstimate(report.feedback_time,
                                                   new_delay_rate);

    const bool loss_limited =
        bandwidth_estimation_.target_rate() < new_delay_rate;
    auto probes = probe_controller_.SetEstimatedBitrate(
        bandwidth_estimation_.target_rate(), loss_limited,
        report.feedback_time);
    update.probe_cluster_configs.insert(update.probe_cluster_configs.end(),
                                        probes.begin(), probes.end());
  }

  if (prev_detector_state_ == BandwidthUsage::kBwOverusing &&
      state == BandwidthUsage::kBwNormal) {
    auto probes = probe_controller_.RequestProbe(report.feedback_time);
    update.probe_cluster_configs.insert(update.probe_cluster_configs.end(),
                                        probes.begin(), probes.end());
  }
  prev_detector_state_ = state;

  MaybeTriggerOnNetworkChanged(&update, report.feedback_time);
  return update;
}

NetworkControlUpdate GoogCcNetworkController::OnReceiverReport(
    Timestamp at_time,
    uint8_t fraction_lost,
    TimeDelta rtt) {
  NetworkControlUpdate update;
  if (rtt > TimeDelta::Zero()) {
    delay_based_bwe_.set_rtt(rtt);
  }
  bandwidth_estimation_.UpdateReceiverReport(at_time, fraction_lost, rtt);
  MaybeTriggerOnNetworkChanged(&update, at_time);
  return update;
}

NetworkControlUpdate GoogCcNetworkController::OnProcessInterval(
    Timestamp at_time) {
  NetworkControlUpdate update;
  bandwidth_estimation_.UpdateEstimate(at_time);
  auto probes = probe_controller_.Process(at_time);
  update.probe_cluster_configs.insert(update.probe_cluster_configs.end(),
                                      probes.begin(), probes.end());
  MaybeTriggerOnNetworkChanged(&update, at_time);
  return update;
}

PacerConfig GoogCcNetworkController::GetPacerRates(Timestamp at_time) const {
  const DataRate pacing_rate =
      std::max(config_.min_bitrate, bandwidth_estimation_.target_rate()) *
      config_.pacing_factor;
  PacerConfig cfg;
  cfg.at_time = at_time;
  cfg.time_window = TimeDelta::Seconds(1);
  cfg.data_window = pacing_rate * TimeDelta::Seconds(1);
  cfg.pad_window = DataSize::Zero();
  return cfg;
}

void GoogCcNetworkController::MaybeTriggerOnNetworkChanged(
    NetworkControlUpdate* update,
    Timestamp at_time) {
  const DataRate target = bandwidth_estimation_.target_rate();
  const uint8_t loss = bandwidth_estimation_.fraction_loss();
  const TimeDelta rtt = bandwidth_estimation_.rtt();

  if (target != last_reported_target_rate_ ||
      loss != last_reported_fraction_loss_ ||
      std::abs((rtt - last_reported_rtt_).ms()) >= 5) {
    last_reported_target_rate_ = target;
    last_reported_fraction_loss_ = loss;
    last_reported_rtt_ = rtt;

    alr_detector_.SetEstimatedBitrate(target);

    TargetTransferRate msg;
    msg.at_time = at_time;
    msg.target_rate = target;
    msg.stable_target_rate =
        std::min(target, delay_based_bwe_.LatestEstimate());
    msg.rtt = rtt;
    msg.loss_rate_ratio = bandwidth_estimation_.loss_ratio();
    msg.network_estimate.update_time = at_time;
    msg.network_estimate.link_capacity = target;

    update->target_rate = msg;
    update->pacer_config = GetPacerRates(at_time);
    update->congestion_window =
        std::max(DataSize::Bytes(4800), target * (rtt + TimeDelta::Millis(150)));
  }
}

}  // namespace rtc
