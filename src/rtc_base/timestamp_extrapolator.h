#ifndef SRC_RTC_BASE_TIMESTAMP_EXTRAPOLATOR_H_
#define SRC_RTC_BASE_TIMESTAMP_EXTRAPOLATOR_H_

// 1:1 对标 libwebrtc/rtc_base/time/timestamp_extrapolator.h 实现。
// 使用双状态卡尔曼滤波器跟踪收发端之间的 90kHz 时钟频偏。

#include <cstdint>
#include <optional>

#include "api/units.h"
#include "rtc_base/seq_num_unwrapper.h"

namespace rtc {

class TimestampExtrapolator {
 public:
  explicit TimestampExtrapolator(Timestamp start_time);

  void Reset(Timestamp start_time);
  void Update(Timestamp now, uint32_t ts90khz);
  std::optional<Timestamp> ExtrapolateLocalTime(uint32_t timestamp90khz) const;

 private:
  bool DelayChangeDetection(double error);

  double w_[2];
  double p_[2][2];
  Timestamp start_ = Timestamp::Zero();
  Timestamp prev_ = Timestamp::Zero();
  std::optional<int64_t> first_unwrapped_timestamp_;
  std::optional<int64_t> prev_unwrapped_timestamp_;
  RtpTimestampUnwrapper unwrapper_;
  uint32_t packet_count_ = 0;
  double detector_accumulator_pos_ = 0.0;
  double detector_accumulator_neg_ = 0.0;
};

}  // namespace rtc

#endif  // SRC_RTC_BASE_TIMESTAMP_EXTRAPOLATOR_H_
