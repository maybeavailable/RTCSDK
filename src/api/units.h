#ifndef SRC_API_UNITS_H_
#define SRC_API_UNITS_H_

// 1:1 参照 libwebrtc/api/units/ 建模的强类型物理量纲单位
// （Timestamp、TimeDelta、DataSize、DataRate），用于防止 ms/us/bps/Bps 单位混用与有符号溢出缺陷。

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace rtc {

namespace units_detail {

constexpr int64_t kPlusInf = std::numeric_limits<int64_t>::max();
constexpr int64_t kMinusInf = std::numeric_limits<int64_t>::min();
constexpr int64_t kMaxFinite = kPlusInf - 1;
constexpr int64_t kMinFinite = kMinusInf + 1;

constexpr int64_t ClampFinite(int64_t v) {
  return v >= kPlusInf ? kMaxFinite : (v <= kMinusInf ? kMinFinite : v);
}

constexpr int64_t SatAddSigned(int64_t a, int64_t b) {
  if (a == kPlusInf || b == kPlusInf) {
    return (a == kMinusInf || b == kMinusInf) ? 0 : kPlusInf;
  }
  if (a == kMinusInf || b == kMinusInf) {
    return kMinusInf;
  }
  if (b > 0 && a > kMaxFinite - b) {
    return kPlusInf;
  }
  if (b < 0 && a < kMinFinite - b) {
    return kMinusInf;
  }
  return a + b;
}

constexpr int64_t SatSubSigned(int64_t a, int64_t b) {
  if (b == kPlusInf) {
    return a == kPlusInf ? 0 : kMinusInf;
  }
  if (b == kMinusInf) {
    return a == kMinusInf ? 0 : kPlusInf;
  }
  return SatAddSigned(a, -b);
}

constexpr int64_t SatMulSigned(int64_t a, int64_t b) {
  if (a == 0 || b == 0) {
    return 0;
  }
  if (a == kPlusInf || a == kMinusInf) {
    const bool neg = (a < 0) != (b < 0);
    return neg ? kMinusInf : kPlusInf;
  }
  if (b == kPlusInf || b == kMinusInf) {
    const bool neg = (a < 0) != (b < 0);
    return neg ? kMinusInf : kPlusInf;
  }
  if (a > 0) {
    if (b > 0 && a > kMaxFinite / b) {
      return kPlusInf;
    }
    if (b < 0 && b < kMinFinite / a) {
      return kMinusInf;
    }
  } else {
    if (b > 0 && a < kMinFinite / b) {
      return kMinusInf;
    }
    if (b < 0 && a < kMaxFinite / b) {
      return kPlusInf;
    }
  }
  return a * b;
}

inline int64_t RoundClampDouble(double v, int64_t non_neg_min = kMinFinite) {
  if (std::isnan(v)) {
    return 0;
  }
  constexpr double kMaxD = 9.223372036854774e18;  // < INT64_MAX
  if (v >= kMaxD) {
    return kPlusInf;
  }
  if (v <= -kMaxD) {
    return non_neg_min >= 0 ? non_neg_min : kMinusInf;
  }
  const int64_t r = static_cast<int64_t>(std::llround(v));
  return r < non_neg_min ? non_neg_min : ClampFinite(r);
}

}  // namespace units_detail

class TimeDelta {
 public:
  constexpr TimeDelta() : us_(0) {}

  static constexpr TimeDelta Zero() { return TimeDelta(0); }
  static constexpr TimeDelta PlusInfinity() {
    return TimeDelta(units_detail::kPlusInf);
  }
  static constexpr TimeDelta MinusInfinity() {
    return TimeDelta(units_detail::kMinusInf);
  }
  static constexpr TimeDelta Micros(int64_t us) { return TimeDelta(us); }
  static constexpr TimeDelta Millis(int64_t ms) {
    return TimeDelta(units_detail::SatMulSigned(ms, 1000));
  }
  static constexpr TimeDelta Seconds(int64_t s) {
    return TimeDelta(units_detail::SatMulSigned(s, 1'000'000));
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
    return us_ != units_detail::kPlusInf && us_ != units_detail::kMinusInf;
  }
  constexpr bool IsInfinite() const { return !IsFinite(); }
  constexpr bool IsPlusInfinity() const {
    return us_ == units_detail::kPlusInf;
  }

  constexpr TimeDelta operator+(TimeDelta other) const {
    return TimeDelta(units_detail::SatAddSigned(us_, other.us_));
  }
  constexpr TimeDelta operator-(TimeDelta other) const {
    return TimeDelta(units_detail::SatSubSigned(us_, other.us_));
  }
  constexpr TimeDelta operator-() const {
    if (us_ == units_detail::kMinusInf) {
      return PlusInfinity();
    }
    if (us_ == units_detail::kPlusInf) {
      return MinusInfinity();
    }
    return TimeDelta(-us_);
  }
  constexpr TimeDelta& operator+=(TimeDelta other) {
    us_ = units_detail::SatAddSigned(us_, other.us_);
    return *this;
  }
  constexpr TimeDelta& operator-=(TimeDelta other) {
    us_ = units_detail::SatSubSigned(us_, other.us_);
    return *this;
  }

  template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
  constexpr TimeDelta operator*(T scalar) const {
    return TimeDelta(
        units_detail::SatMulSigned(us_, static_cast<int64_t>(scalar)));
  }
  template <typename T, std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
  TimeDelta operator*(T scalar) const {
    if (IsInfinite()) {
      if (scalar == T{0}) {
        return Zero();
      }
      const bool neg = (us_ < 0) != (scalar < T{0});
      return neg ? MinusInfinity() : PlusInfinity();
    }
    return TimeDelta(units_detail::RoundClampDouble(
        static_cast<double>(us_) * static_cast<double>(scalar)));
  }
  template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
  constexpr TimeDelta operator/(T scalar) const {
    const int64_t s = static_cast<int64_t>(scalar);
    if (s == 0) {
      return us_ < 0 ? MinusInfinity() : PlusInfinity();
    }
    if (IsInfinite()) {
      const bool neg = (us_ < 0) != (s < 0);
      return neg ? MinusInfinity() : PlusInfinity();
    }
    return TimeDelta(us_ / s);
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
  constexpr Timestamp() : us_(units_detail::kMinusInf) {}

  static constexpr Timestamp Zero() { return Timestamp(0); }
  static constexpr Timestamp MinusInfinity() {
    return Timestamp(units_detail::kMinusInf);
  }
  static constexpr Timestamp PlusInfinity() {
    return Timestamp(units_detail::kPlusInf);
  }
  static constexpr Timestamp Micros(int64_t us) { return Timestamp(us); }
  static constexpr Timestamp Millis(int64_t ms) {
    return Timestamp(units_detail::SatMulSigned(ms, 1000));
  }
  static constexpr Timestamp Seconds(int64_t s) {
    return Timestamp(units_detail::SatMulSigned(s, 1'000'000));
  }

  constexpr bool IsFinite() const {
    return us_ != units_detail::kMinusInf && us_ != units_detail::kPlusInf;
  }
  constexpr bool IsInfinite() const { return !IsFinite(); }
  constexpr bool IsMinusInfinity() const {
    return us_ == units_detail::kMinusInf;
  }
  constexpr bool IsPlusInfinity() const {
    return us_ == units_detail::kPlusInf;
  }

  constexpr int64_t us() const { return us_; }
  constexpr int64_t ms() const { return us_ / 1000; }

  constexpr Timestamp operator+(TimeDelta d) const {
    return Timestamp(units_detail::SatAddSigned(us_, d.us()));
  }
  constexpr Timestamp operator-(TimeDelta d) const {
    return Timestamp(units_detail::SatSubSigned(us_, d.us()));
  }
  constexpr TimeDelta operator-(Timestamp other) const {
    return TimeDelta::Micros(units_detail::SatSubSigned(us_, other.us_));
  }
  constexpr Timestamp& operator+=(TimeDelta d) {
    us_ = units_detail::SatAddSigned(us_, d.us());
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
    return DataSize(units_detail::kPlusInf);
  }
  static constexpr DataSize Bytes(int64_t bytes) {
    return DataSize(bytes < 0 ? 0 : bytes);
  }

  constexpr int64_t bytes() const { return bytes_; }
  constexpr int64_t bits() const {
    return units_detail::SatMulSigned(bytes_, 8);
  }
  constexpr bool IsZero() const { return bytes_ == 0; }
  constexpr bool IsFinite() const {
    return bytes_ >= 0 && bytes_ != units_detail::kPlusInf;
  }

  constexpr DataSize operator+(DataSize o) const {
    return DataSize(units_detail::SatAddSigned(bytes_, o.bytes_));
  }
  constexpr DataSize operator-(DataSize o) const {
    return DataSize(
        std::max<int64_t>(0, units_detail::SatSubSigned(bytes_, o.bytes_)));
  }
  constexpr DataSize& operator+=(DataSize o) {
    bytes_ = units_detail::SatAddSigned(bytes_, o.bytes_);
    return *this;
  }
  constexpr DataSize& operator-=(DataSize o) {
    bytes_ = std::max<int64_t>(0, units_detail::SatSubSigned(bytes_, o.bytes_));
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
    return DataRate(units_detail::kPlusInf);
  }
  static constexpr DataRate BitsPerSec(int64_t bps) {
    return DataRate(bps < 0 ? 0 : bps);
  }
  static constexpr DataRate KilobitsPerSec(int64_t kbps) {
    return DataRate(
        kbps <= 0 ? 0 : units_detail::SatMulSigned(kbps, 1000));
  }
  static constexpr DataRate BytesPerSec(int64_t bytes_per_sec) {
    return DataRate(bytes_per_sec <= 0
                        ? 0
                        : units_detail::SatMulSigned(bytes_per_sec, 8));
  }

  constexpr int64_t bps() const { return bps_; }
  constexpr int64_t kbps() const { return bps_ / 1000; }
  constexpr int64_t bytes_per_sec() const { return bps_ / 8; }

  constexpr bool IsZero() const { return bps_ == 0; }
  constexpr bool IsFinite() const {
    return bps_ >= 0 && bps_ != units_detail::kPlusInf;
  }
  constexpr bool IsInfinite() const { return !IsFinite(); }

  DataSize operator*(TimeDelta d) const {
    if (IsInfinite() || !d.IsFinite()) {
      return d.us() <= 0 ? DataSize::Zero() : DataSize::Infinity();
    }
    if (d.us() <= 0 || bps_ <= 0) {
      return DataSize::Zero();
    }
    const double bits = static_cast<double>(bps_) * d.seconds_double();
    return DataSize::Bytes(units_detail::RoundClampDouble(bits / 8.0, 0));
  }
  DataRate operator*(double factor) const {
    if (factor <= 0.0 || std::isnan(factor)) {
      return Zero();
    }
    if (IsInfinite() || std::isinf(factor)) {
      return Infinity();
    }
    return DataRate(
        units_detail::RoundClampDouble(static_cast<double>(bps_) * factor, 0));
  }
  constexpr DataRate operator+(DataRate o) const {
    return DataRate(units_detail::SatAddSigned(bps_, o.bps_));
  }
  constexpr DataRate operator-(DataRate o) const {
    return DataRate(std::max<int64_t>(0, units_detail::SatSubSigned(bps_, o.bps_)));
  }
  constexpr DataRate& operator+=(DataRate o) {
    bps_ = units_detail::SatAddSigned(bps_, o.bps_);
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
  if (size.bytes() <= 0) {
    return DataRate::Zero();
  }
  if (!size.IsFinite() || duration.us() <= 0) {
    return DataRate::Infinity();
  }
  if (!duration.IsFinite()) {
    return DataRate::Zero();
  }
  const double bps =
      (static_cast<double>(size.bytes()) * 8e6) / static_cast<double>(duration.us());
  return DataRate::BitsPerSec(units_detail::RoundClampDouble(bps, 0));
}

inline TimeDelta operator/(DataSize size, DataRate rate) {
  if (size.bytes() <= 0) {
    return TimeDelta::Zero();
  }
  if (!size.IsFinite() || rate.bps() <= 0) {
    return TimeDelta::PlusInfinity();
  }
  if (!rate.IsFinite()) {
    return TimeDelta::Zero();
  }
  const double us =
      (static_cast<double>(size.bytes()) * 8e6) / static_cast<double>(rate.bps());
  return TimeDelta::Micros(units_detail::RoundClampDouble(us, 0));
}

}  // namespace rtc

#endif  // SRC_API_UNITS_H_
