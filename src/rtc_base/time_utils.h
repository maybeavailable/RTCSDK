#ifndef SRC_RTC_BASE_TIME_UTILS_H_
#define SRC_RTC_BASE_TIME_UTILS_H_

// 对标 libwebrtc/system_wrappers/include/clock.h 实现的时钟工具。

#include <atomic>
#include <chrono>
#include <cstdint>

#include "api/units.h"

namespace rtc {

class Clock {
 public:
  virtual ~Clock() = default;
  virtual Timestamp CurrentTime() const = 0;

  static Clock* GetRealTimeClock();
};

class RealTimeClock final : public Clock {
 public:
  Timestamp CurrentTime() const override {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    const int64_t us =
        std::chrono::duration_cast<std::chrono::microseconds>(now).count();
    return Timestamp::Micros(us);
  }
};

inline Clock* Clock::GetRealTimeClock() {
  static RealTimeClock instance;
  return &instance;
}

class SimulatedClock final : public Clock {
 public:
  explicit SimulatedClock(Timestamp initial = Timestamp::Millis(100'000))
      : current_us_(initial.us()) {}

  SimulatedClock(const SimulatedClock&) = delete;
  SimulatedClock& operator=(const SimulatedClock&) = delete;

  Timestamp CurrentTime() const override {
    return Timestamp::Micros(current_us_.load(std::memory_order_acquire));
  }

  void AdvanceTime(TimeDelta delta) {
    current_us_.fetch_add(delta.us(), std::memory_order_acq_rel);
  }

 private:
  std::atomic<int64_t> current_us_;
};

}  // namespace rtc

#endif  // SRC_RTC_BASE_TIME_UTILS_H_
