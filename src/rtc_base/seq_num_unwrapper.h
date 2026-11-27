#ifndef SRC_RTC_BASE_SEQ_NUM_UNWRAPPER_H_
#define SRC_RTC_BASE_SEQ_NUM_UNWRAPPER_H_

// 1:1 对标 libwebrtc/rtc_base/numerics/sequence_number_unwrapper.h 实现。
// 实现符合 RFC 1982 规范的序列号回绕算术运算。

#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

namespace rtc {

template <typename U>
constexpr bool AheadOrAt(U a, U b) {
  static_assert(std::is_unsigned_v<U>, "U must be an unsigned integer");
  constexpr U kHalf = (std::numeric_limits<U>::max() >> 1) + 1;
  if (a == b) {
    return true;
  }
  const U diff = static_cast<U>(a - b);
  return diff < kHalf;
}

template <typename U>
constexpr bool AheadOf(U a, U b) {
  return a != b && AheadOrAt(a, b);
}

constexpr bool IsNewerSequenceNumber(uint16_t seq, uint16_t prev_seq) {
  return AheadOf<uint16_t>(seq, prev_seq);
}

constexpr bool IsNewerTimestamp(uint32_t ts, uint32_t prev_ts) {
  return AheadOf<uint32_t>(ts, prev_ts);
}

template <typename U>
class SeqNumUnwrapper {
  static_assert(std::is_unsigned_v<U> && sizeof(U) <= 4,
                "SeqNumUnwrapper supports uint8_t, uint16_t, uint32_t");

 public:
  int64_t Unwrap(U value) {
    if (!last_value_.has_value()) {
      last_value_ = value;
      last_unwrapped_ = static_cast<int64_t>(value);
      return last_unwrapped_;
    }
    const int64_t unwrapped = last_unwrapped_ + ForwardDiff(*last_value_, value);
    if (unwrapped > last_unwrapped_) {
      last_unwrapped_ = unwrapped;
      last_value_ = value;
    }
    return unwrapped;
  }

  int64_t PeekUnwrap(U value) const {
    if (!last_value_.has_value()) {
      return static_cast<int64_t>(value);
    }
    return last_unwrapped_ + ForwardDiff(*last_value_, value);
  }

  void Reset() {
    last_value_.reset();
    last_unwrapped_ = 0;
  }

 private:
  static constexpr int64_t ForwardDiff(U prev, U cur) {
    constexpr int64_t kModulus = int64_t{1} << (sizeof(U) * 8);
    constexpr U kHalf = (std::numeric_limits<U>::max() >> 1) + 1;
    const U unsigned_diff = static_cast<U>(cur - prev);
    if (unsigned_diff < kHalf) {
      return static_cast<int64_t>(unsigned_diff);
    }
    return static_cast<int64_t>(unsigned_diff) - kModulus;
  }

  std::optional<U> last_value_;
  int64_t last_unwrapped_ = 0;
};

using RtpSeqUnwrapper = SeqNumUnwrapper<uint16_t>;
using RtpTimestampUnwrapper = SeqNumUnwrapper<uint32_t>;

}  // namespace rtc

#endif  // SRC_RTC_BASE_SEQ_NUM_UNWRAPPER_H_
