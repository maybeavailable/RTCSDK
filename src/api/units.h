#ifndef SRC_API_UNITS_H_
#define SRC_API_UNITS_H_

// 1:1 参照 libwebrtc/api/units/ 建模的强类型物理量纲单位
// （Timestamp、TimeDelta、DataSize、DataRate），用于防止 ms/us/bps/Bps 单位混用缺陷。

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace rtc {

class TimeDelta {
 public:
  constexpr TimeDelta() : us_(0) {}

  static constexpr TimeDelta Zero() { return TimeDelta(0); }
  static constexpr TimeDelta PlusInfinity() {
    return TimeDelta(std::numeric_limits<int64_t>::max());
  }
  static constexpr TimeDelta MinusInfinity() {
    return TimeDelta(std::numeric_limits<int64_t>::min());
  }
  static constexpr TimeDelta Micros(int64_t us) { return TimeDelta(us); }
  static constexpr TimeDelta Millis(int64_t ms) { return TimeDelta(ms * 1000); }
  static constexpr TimeDelta Seconds(int64_t s) {
    return TimeDelta(s * 1'000'000);
  }

  constexpr int64_t us() const { return us_; }
  constexpr int64_t ms() const { return us_ / 1000; }
  constexpr double seconds_double() const {
    return static_cast<double>(us_) / 1e6;
  }
  constexpr double ms_double() const {
    return static_cast<double>(us_) / 1e3;
  }

  constexpr bool IsZero() const { return us_ == 0; }
  constexpr bool IsFinite() const {
    return us_ != std::numeric_limits<int64_t>::max() &&
           us_ != std::numeric_limits<int64_t>::min();
  }
  constexpr bool IsInfinite() const { return !IsFinite(); }
  constexpr bool IsPlusInfinity() const {
    return us_ == std::numeric_limits<int64_t>::max();
  }

  constexpr TimeDelta operator+(TimeDelta other) const {
    return TimeDelta(us_ + other.us_);
  }
  constexpr TimeDelta operator-(TimeDelta other) const {
    return TimeDelta(us_ - other.us_);
  }
  constexpr TimeDelta operator-() const { return TimeDelta(-us_); }
  constexpr TimeDelta& operator+=(TimeDelta other) {
    us_ += other.us_;
    return *this;
  }
  constexpr TimeDelta& operator-=(TimeDelta other) {
    us_ -= other.us_;
    return *this;
  }

  template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
  constexpr TimeDelta operator*(T scalar) const {
    return TimeDelta(us_ * static_cast<int64_t>(scalar));
  }
  template <typename T, std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
  constexpr TimeDelta operator*(T scalar) const {
    return TimeDelta(static_cast<int64_t>(
        std::llround(static_cast<double>(us_) * static_cast<double>(scalar))));
  }
  template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
  constexpr TimeDelta operator/(T scalar) const {
    return TimeDelta(us_ / static_cast<int64_t>(scalar));
  }

  constexpr bool operator==(TimeDelta o) const { return us_ == o.us_; }
  constexpr bool operator!=(TimeDelta o) const { return us_ != o.us_; }
  constexpr bool operator<(TimeDelta o) const { return us_ < o.us_; }
  constexpr bool operator<=(TimeDelta o) const { return us_ <= o.us_; }
  constexpr bool operator>(TimeDelta o) const { return us_ > o.us_; }
  constexpr bool operator>=(TimeDelta o) const { return us_ >= o.us_; }

 private:
  explicit constexpr TimeDelta(int64_t us) : us_(us) {}
  int64_t us_;
};

class Timestamp {
 public:
  constexpr Timestamp() : us_(std::numeric_limits<int64_t>::min()) {}

  static constexpr Timestamp Zero() { return Timestamp(0); }
  static constexpr Timestamp MinusInfinity() {
    return Timestamp(std::numeric_limits<int64_t>::min());
  }
  static constexpr Timestamp PlusInfinity() {
    return Timestamp(std::numeric_limits<int64_t>::max());
  }
  static constexpr Timestamp Micros(int64_t us) { return Timestamp(us); }
  static constexpr Timestamp Millis(int64_t ms) { return Timestamp(ms * 1000); }
  static constexpr Timestamp Seconds(int64_t s) {
    return Timestamp(s * 1'000'000);
  }

  constexpr bool IsFinite() const {
    return us_ != std::numeric_limits<int64_t>::min() &&
           us_ != std::numeric_limits<int64_t>::max();
  }
  constexpr bool IsInfinite() const { return !IsFinite(); }
  constexpr bool IsMinusInfinity() const {
    return us_ == std::numeric_limits<int64_t>::min();
  }
  constexpr bool IsPlusInfinity() const {
    return us_ == std::numeric_limits<int64_t>::max();
  }

  constexpr int64_t us() const { return us_; }
  constexpr int64_t ms() const { return us_ / 1000; }

  constexpr Timestamp operator+(TimeDelta d) const {
    return Timestamp(us_ + d.us());
  }
  constexpr Timestamp operator-(TimeDelta d) const {
    return Timestamp(us_ - d.us());
  }
  constexpr TimeDelta operator-(Timestamp other) const {
    return TimeDelta::Micros(us_ - other.us_);
  }
  constexpr Timestamp& operator+=(TimeDelta d) {
    us_ += d.us();
    return *this;
  }

  constexpr bool operator==(Timestamp o) const { return us_ == o.us_; }
  constexpr bool operator!=(Timestamp o) const { return us_ != o.us_; }
  constexpr bool operator<(Timestamp o) const { return us_ < o.us_; }
  constexpr bool operator<=(Timestamp o) const { return us_ <= o.us_; }
  constexpr bool operator>(Timestamp o) const { return us_ > o.us_; }
  constexpr bool operator>=(Timestamp o) const { return us_ >= o.us_; }

 private:
  explicit constexpr Timestamp(int64_t us) : us_(us) {}
  int64_t us_;
};

class DataSize {
 public:
  constexpr DataSize() : bytes_(0) {}

  static constexpr DataSize Zero() { return DataSize(0); }
  static constexpr DataSize Infinity() {
    return DataSize(std::numeric_limits<int64_t>::max());
  }
  static constexpr DataSize Bytes(int64_t bytes) { return DataSize(bytes); }

  constexpr int64_t bytes() const { return bytes_; }
  constexpr int64_t bits() const { return bytes_ * 8; }
  constexpr bool IsZero() const { return bytes_ == 0; }
  constexpr bool IsFinite() const {
    return bytes_ != std::numeric_limits<int64_t>::max();
  }

  constexpr DataSize operator+(DataSize o) const {
    return DataSize(bytes_ + o.bytes_);
  }
  constexpr DataSize operator-(DataSize o) const {
    return DataSize(bytes_ - o.bytes_);
  }
  constexpr DataSize& operator+=(DataSize o) {
    bytes_ += o.bytes_;
    return *this;
  }
  constexpr DataSize& operator-=(DataSize o) {
    bytes_ -= o.bytes_;
    return *this;
  }

  constexpr bool operator==(DataSize o) const { return bytes_ == o.bytes_; }
  constexpr bool operator!=(DataSize o) const { return bytes_ != o.bytes_; }
  constexpr bool operator<(DataSize o) const { return bytes_ < o.bytes_; }
  constexpr bool operator<=(DataSize o) const { return bytes_ <= o.bytes_; }
  constexpr bool operator>(DataSize o) const { return bytes_ > o.bytes_; }
  constexpr bool operator>=(DataSize o) const { return bytes_ >= o.bytes_; }

 private:
  explicit constexpr DataSize(int64_t b) : bytes_(b) {}
  int64_t bytes_;
};

class DataRate {
 public:
  constexpr DataRate() : bps_(0) {}

  static constexpr DataRate Zero() { return DataRate(0); }
  static constexpr DataRate Infinity() {
    return DataRate(std::numeric_limits<int64_t>::max());
  }
  static constexpr DataRate BitsPerSec(int64_t bps) { return DataRate(bps); }
  static constexpr DataRate KilobitsPerSec(int64_t kbps) {
    return DataRate(kbps * 1000);
  }
  static constexpr DataRate BytesPerSec(int64_t bytes_per_sec) {
    return DataRate(bytes_per_sec * 8);
  }

  constexpr int64_t bps() const { return bps_; }
  constexpr int64_t kbps() const { return bps_ / 1000; }
  constexpr int64_t bytes_per_sec() const { return bps_ / 8; }

  constexpr bool IsZero() const { return bps_ == 0; }
  constexpr bool IsFinite() const {
    return bps_ != std::numeric_limits<int64_t>::max();
  }
  constexpr bool IsInfinite() const { return !IsFinite(); }

  constexpr DataSize operator*(TimeDelta d) const {
    const double bits = static_cast<double>(bps_) * d.seconds_double();
    return DataSize::Bytes(static_cast<int64_t>(std::llround(bits / 8.0)));
  }
  constexpr DataRate operator*(double factor) const {
    return DataRate(
        static_cast<int64_t>(std::llround(static_cast<double>(bps_) * factor)));
  }
  constexpr DataRate operator+(DataRate o) const {
    return DataRate(bps_ + o.bps_);
  }
  constexpr DataRate operator-(DataRate o) const {
    return DataRate(std::max<int64_t>(0, bps_ - o.bps_));
  }
  constexpr DataRate& operator+=(DataRate o) {
    bps_ += o.bps_;
    return *this;
  }

  constexpr bool operator==(DataRate o) const { return bps_ == o.bps_; }
  constexpr bool operator!=(DataRate o) const { return bps_ != o.bps_; }
  constexpr bool operator<(DataRate o) const { return bps_ < o.bps_; }
  constexpr bool operator<=(DataRate o) const { return bps_ <= o.bps_; }
  constexpr bool operator>(DataRate o) const { return bps_ > o.bps_; }
  constexpr bool operator>=(DataRate o) const { return bps_ >= o.bps_; }

 private:
  explicit constexpr DataRate(int64_t bps) : bps_(bps) {}
  int64_t bps_;
};

inline DataRate operator/(DataSize size, TimeDelta duration) {
  if (duration.us() <= 0) {
    return DataRate::Infinity();
  }
  const double bps =
      (static_cast<double>(size.bits()) * 1e6) / static_cast<double>(duration.us());
  return DataRate::BitsPerSec(static_cast<int64_t>(std::llround(bps)));
}

inline TimeDelta operator/(DataSize size, DataRate rate) {
  if (rate.bps() <= 0) {
    return TimeDelta::PlusInfinity();
  }
  const double us =
      (static_cast<double>(size.bits()) * 1e6) / static_cast<double>(rate.bps());
  return TimeDelta::Micros(static_cast<int64_t>(std::llround(us)));
}

}  // namespace rtc

#endif  // SRC_API_UNITS_H_
