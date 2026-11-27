#include "rtc_base/timestamp_extrapolator.h"

#include <algorithm>
#include <cmath>

namespace rtc {

namespace {
constexpr double kLambda = 1.0;
constexpr uint32_t kStartUpFilterDelayInPackets = 2;
constexpr double kAlarmThreshold = 60e3;
constexpr double kAccDrift = 6600.0;
constexpr double kAccMaxError = 7000.0;
constexpr double kP11 = 1e10;
}  // namespace

TimestampExtrapolator::TimestampExtrapolator(Timestamp start_time) {
  Reset(start_time);
}

void TimestampExtrapolator::Reset(Timestamp start_time) {
  start_ = start_time;
  prev_ = start_;
  first_unwrapped_timestamp_.reset();
  prev_unwrapped_timestamp_.reset();
  unwrapper_.Reset();
  w_[0] = 90.0;
  w_[1] = 0.0;
  p_[0][0] = 1.0;
  p_[1][1] = kP11;
  p_[0][1] = 0.0;
  p_[1][0] = 0.0;
  packet_count_ = 0;
  detector_accumulator_pos_ = 0.0;
  detector_accumulator_neg_ = 0.0;
}

void TimestampExtrapolator::Update(Timestamp now, uint32_t ts90khz) {
  if (now - prev_ > TimeDelta::Seconds(10)) {
    Reset(now);
  } else {
    prev_ = now;
  }

  const TimeDelta offset = now - start_;
  const double t_ms = offset.ms_double();

  const int64_t unwrapped_ts90khz = unwrapper_.Unwrap(ts90khz);
  if (!first_unwrapped_timestamp_.has_value()) {
    w_[1] = -w_[0] * t_ms;
    first_unwrapped_timestamp_ = unwrapped_ts90khz;
  }

  const double residual = (static_cast<double>(unwrapped_ts90khz) -
                           static_cast<double>(*first_unwrapped_timestamp_)) -
                          t_ms * w_[0] - w_[1];

  if (DelayChangeDetection(residual) &&
      packet_count_ >= kStartUpFilterDelayInPackets) {
    p_[1][1] = kP11;
  }

  if (prev_unwrapped_timestamp_.has_value() &&
      unwrapped_ts90khz < *prev_unwrapped_timestamp_) {
    return;
  }

  double k_gain[2];
  k_gain[0] = p_[0][0] * t_ms + p_[0][1];
  k_gain[1] = p_[1][0] * t_ms + p_[1][1];
  const double t_pt = kLambda + t_ms * k_gain[0] + k_gain[1];
  k_gain[0] /= t_pt;
  k_gain[1] /= t_pt;

  w_[0] += k_gain[0] * residual;
  w_[1] += k_gain[1] * residual;

  const double p00 =
      (1.0 / kLambda) *
      (p_[0][0] - (k_gain[0] * t_ms * p_[0][0] + k_gain[0] * p_[1][0]));
  const double p01 =
      (1.0 / kLambda) *
      (p_[0][1] - (k_gain[0] * t_ms * p_[0][1] + k_gain[0] * p_[1][1]));
  p_[1][0] =
      (1.0 / kLambda) *
      (p_[1][0] - (k_gain[1] * t_ms * p_[0][0] + k_gain[1] * p_[1][0]));
  p_[1][1] =
      (1.0 / kLambda) *
      (p_[1][1] - (k_gain[1] * t_ms * p_[0][1] + k_gain[1] * p_[1][1]));
  p_[0][0] = p00;
  p_[0][1] = p01;

  prev_unwrapped_timestamp_ = unwrapped_ts90khz;
  if (packet_count_ < kStartUpFilterDelayInPackets) {
    ++packet_count_;
  }
}

std::optional<Timestamp> TimestampExtrapolator::ExtrapolateLocalTime(
    uint32_t timestamp90khz) const {
  if (!first_unwrapped_timestamp_.has_value()) {
    return std::nullopt;
  }
  constexpr double kMaxExtrapolateDeltaUs = 3.6e10;  // 10 小时安全边界
  const int64_t unwrapped_ts90khz = unwrapper_.PeekUnwrap(timestamp90khz);
  if (packet_count_ < kStartUpFilterDelayInPackets) {
    if (!prev_unwrapped_timestamp_.has_value() || !prev_.IsFinite()) {
      return std::nullopt;
    }
    constexpr double kRtpTicksPerMs = 90.0;
    const double raw_us =
        (static_cast<double>(unwrapped_ts90khz - *prev_unwrapped_timestamp_) /
         kRtpTicksPerMs) *
        1000.0;
    if (!std::isfinite(raw_us) || std::fabs(raw_us) > kMaxExtrapolateDeltaUs) {
      return std::nullopt;
    }
    const TimeDelta diff =
        TimeDelta::Micros(static_cast<int64_t>(std::llround(raw_us)));
    const Timestamp res = prev_ + diff;
    if (!res.IsFinite() || res.us() < 0) {
      return std::nullopt;
    }
    return res;
  }
  if (!std::isfinite(w_[0]) || w_[0] < 1e-3 || !start_.IsFinite()) {
    return start_;
  }
  const double timestamp_diff =
      static_cast<double>(unwrapped_ts90khz - *first_unwrapped_timestamp_);
  const double raw_us = ((timestamp_diff - w_[1]) / w_[0]) * 1000.0;
  if (!std::isfinite(raw_us) || std::fabs(raw_us) > kMaxExtrapolateDeltaUs) {
    return std::nullopt;
  }
  const TimeDelta diff_ms =
      TimeDelta::Micros(static_cast<int64_t>(std::llround(raw_us)));
  const Timestamp res = start_ + diff_ms;
  if (!res.IsFinite() || res.us() < 0) {
    return std::nullopt;
  }
  return res;
}

bool TimestampExtrapolator::DelayChangeDetection(double error) {
  error = std::clamp(error, -kAccMaxError, kAccMaxError);
  detector_accumulator_pos_ =
      std::max(detector_accumulator_pos_ + error - kAccDrift, 0.0);
  detector_accumulator_neg_ =
      std::min(detector_accumulator_neg_ + error + kAccDrift, 0.0);
  if (detector_accumulator_pos_ > kAlarmThreshold ||
      detector_accumulator_neg_ < -kAlarmThreshold) {
    detector_accumulator_pos_ = 0.0;
    detector_accumulator_neg_ = 0.0;
    return true;
  }
  return false;
}

}  // namespace rtc
