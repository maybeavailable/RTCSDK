#ifndef SRC_RTC_BASE_LOGGING_H_
#define SRC_RTC_BASE_LOGGING_H_

// 1:1 对标 libwebrtc/rtc_base/logging.h 设计的统一日志子系统。
// 核心特性：
//   - 无锁原子快速路径日志级别检查（关闭时零格式化开销）
//   - 自动解析当前 TaskQueue 名称（[rtc-sig]、[rtc-work]、[rtc-net] 等）
//   - 可插拔 C++ LogSink 与 C99 回调接收器，并提供面向嵌入式 SoC 的 RingBufferLogSink
//   - 通过 LogMessageVoidify 实现规避悬空 else 问题的安全三元宏

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "rtc_video_engine.hpp"

namespace rtc {

constexpr std::string_view StripDirectoryPath(std::string_view full_path) {
  const size_t slash = full_path.find_last_of("/\\");
  return (slash == std::string_view::npos) ? full_path
                                           : full_path.substr(slash + 1);
}

// 用于嵌入式事后故障诊断的有界内存环形日志接收器。
class RingBufferLogSink final : public LogSink {
 public:
  explicit RingBufferLogSink(size_t capacity = 256);
  ~RingBufferLogSink() override = default;

  RingBufferLogSink(const RingBufferLogSink&) = delete;
  RingBufferLogSink& operator=(const RingBufferLogSink&) = delete;

  void OnLogMessage(const LogEntryView& entry,
                    std::string_view formatted_line) override;

  std::vector<std::string> Snapshot() const;
  void Clear();
  size_t Size() const;

 private:
  const size_t capacity_;
  mutable std::mutex mutex_;
  std::deque<std::string> lines_;
};

class LogMessage {
 public:
  LogMessage(std::string_view file, int line, LoggingSeverity severity);
  ~LogMessage();

  LogMessage(const LogMessage&) = delete;
  LogMessage& operator=(const LogMessage&) = delete;

  std::ostream& stream() { return stream_; }

  static bool IsEnabled(LoggingSeverity severity) noexcept {
    return static_cast<int>(severity) >=
           min_severity_.load(std::memory_order_relaxed);
  }

  static void SetMinLogSeverity(LoggingSeverity severity) noexcept;
  static LoggingSeverity GetMinLogSeverity() noexcept;

  static void SetLogToStderr(bool enable) noexcept;
  static bool GetLogToStderr() noexcept;

  static void AddLogSink(LogSink* sink,
                         LoggingSeverity min_severity = LoggingSeverity::kInfo);
  static void RemoveLogSink(LogSink* sink);

  static void SetCLogCallback(rtc_log_callback_fn callback, void* user_data);

 private:
  static void RecomputeEffectiveMinSeverityLocked();

  static std::atomic<int> min_severity_;
  static std::atomic<bool> log_to_stderr_;

  const std::string_view file_name_;
  const int line_;
  const LoggingSeverity severity_;
  const int64_t timestamp_us_;
  std::ostringstream stream_;
};

class LogMessageVoidify {
 public:
  constexpr LogMessageVoidify() = default;
  // 运算符优先级低于 <<，但高于 ?: 三元运算符。
  void operator&(std::ostream&) const noexcept {}
};

#define RTC_LOG_IS_ON(sev) \
  (::rtc::LogMessage::IsEnabled(::rtc::LoggingSeverity::sev))

#define RTC_LOG(sev)                                                      \
  !RTC_LOG_IS_ON(sev)                                                     \
      ? static_cast<void>(0)                                              \
      : ::rtc::LogMessageVoidify() &                                      \
            ::rtc::LogMessage(::rtc::StripDirectoryPath(__FILE__),        \
                              __LINE__, ::rtc::LoggingSeverity::sev)      \
                .stream()

#define RTC_LOG_F(sev) RTC_LOG(sev) << __func__ << ": "

#ifndef NDEBUG
#define RTC_DLOG(sev) RTC_LOG(sev)
#else
#define RTC_DLOG(sev) \
  true ? static_cast<void>(0) : ::rtc::LogMessageVoidify() & std::cerr
#endif

}  // namespace rtc

#endif  // SRC_RTC_BASE_LOGGING_H_
