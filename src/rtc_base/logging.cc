#include "rtc_base/logging.h"

#include <unistd.h>
#include <sys/syscall.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <iostream>

#include "rtc_base/task_queue.h"

namespace rtc {

namespace {

struct RegisteredSink {
  LogSink* sink = nullptr;
  LoggingSeverity min_severity = LoggingSeverity::kInfo;
};

struct GlobalLogRegistry {
  std::mutex mutex;
  LoggingSeverity configured_min_severity = LoggingSeverity::kInfo;
  std::vector<RegisteredSink> sinks;
  rtc_log_callback_fn c_callback = nullptr;
  void* c_user_data = nullptr;
};

GlobalLogRegistry& GetLogRegistry() {
  static GlobalLogRegistry* registry = new GlobalLogRegistry();
  return *registry;
}

const char* SeverityToString(LoggingSeverity severity) {
  switch (severity) {
    case LoggingSeverity::kVerbose:
      return "VERBOSE";
    case LoggingSeverity::kInfo:
      return "INFO";
    case LoggingSeverity::kWarning:
      return "WARNING";
    case LoggingSeverity::kError:
      return "ERROR";
    case LoggingSeverity::kNone:
      return "NONE";
  }
  return "INFO";
}

std::string CurrentExecutionContextName() {
  const TaskQueueBase* current_tq = TaskQueueBase::Current();
  if (current_tq != nullptr && !current_tq->name().empty()) {
    return std::string(current_tq->name());
  }
#if defined(__linux__)
  static thread_local long cached_tid = syscall(SYS_gettid);
  return "tid:" + std::to_string(cached_tid);
#else
  return "ext-thread";
#endif
}

std::string FormatTimestampWallClock(int64_t* out_epoch_us) {
  const auto now = std::chrono::system_clock::now();
  const auto epoch_us = std::chrono::duration_cast<std::chrono::microseconds>(
                            now.time_since_epoch())
                            .count();
  if (out_epoch_us != nullptr) {
    *out_epoch_us = epoch_us;
  }

  const std::time_t sec = static_cast<std::time_t>(epoch_us / 1'000'000);
  const int millis = static_cast<int>((epoch_us % 1'000'000) / 1000);

  struct tm tm_buf {};
  localtime_r(&sec, &tm_buf);

  char buf[80];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, millis);
  return std::string(buf);
}

}  // namespace

// ======================= RingBufferLogSink 环形缓冲日志接收器 =======================

RingBufferLogSink::RingBufferLogSink(size_t capacity)
    : capacity_(std::max<size_t>(capacity, 16)) {}

void RingBufferLogSink::OnLogMessage(const LogEntryView& /*entry*/,
                                     std::string_view formatted_line) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (lines_.size() >= capacity_) {
    lines_.pop_front();
  }
  lines_.emplace_back(formatted_line);
}

std::vector<std::string> RingBufferLogSink::Snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return std::vector<std::string>(lines_.begin(), lines_.end());
}

void RingBufferLogSink::Clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  lines_.clear();
}

size_t RingBufferLogSink::Size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return lines_.size();
}

// ======================= LogMessage 日志消息核心实现 =======================

std::atomic<int> LogMessage::min_severity_{
    static_cast<int>(LoggingSeverity::kInfo)};
std::atomic<bool> LogMessage::log_to_stderr_{true};

LogMessage::LogMessage(std::string_view file,
                       int line,
                       LoggingSeverity severity)
    : file_name_(file),
      line_(line),
      severity_(severity),
      timestamp_us_(std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count()) {}

LogMessage::~LogMessage() {
  const std::string payload = stream_.str();
  const std::string queue_tag = CurrentExecutionContextName();
  const std::string file_str(file_name_);

  int64_t wall_us = 0;
  const std::string wall_str = FormatTimestampWallClock(&wall_us);

  std::ostringstream full;
  full << "[" << wall_str << "] [" << SeverityToString(severity_) << "] ["
       << queue_tag << "] [" << file_name_ << ":" << line_ << "] " << payload;
  const std::string formatted = full.str();

  if (log_to_stderr_.load(std::memory_order_relaxed)) {
    std::fprintf(stderr, "%s\n", formatted.c_str());
  }

  LogEntryView view;
  view.severity = severity_;
  view.timestamp_us = timestamp_us_;
  view.queue_name = queue_tag;
  view.file_name = file_str;
  view.line = line_;
  view.message = payload;

  GlobalLogRegistry& reg = GetLogRegistry();
  std::lock_guard<std::mutex> lock(reg.mutex);
  for (const auto& item : reg.sinks) {
    if (item.sink != nullptr &&
        static_cast<int>(severity_) >= static_cast<int>(item.min_severity)) {
      item.sink->OnLogMessage(view, formatted);
    }
  }
  if (reg.c_callback != nullptr) {
    reg.c_callback(reg.c_user_data,
                   static_cast<rtc_log_severity_e>(severity_),
                   queue_tag.c_str(), file_str.c_str(), line_, payload.c_str());
  }
}

void LogMessage::RecomputeEffectiveMinSeverityLocked() {
  GlobalLogRegistry& reg = GetLogRegistry();
  int effective = static_cast<int>(reg.configured_min_severity);
  for (const auto& item : reg.sinks) {
    effective = std::min(effective, static_cast<int>(item.min_severity));
  }
  min_severity_.store(effective, std::memory_order_relaxed);
}

void LogMessage::SetMinLogSeverity(LoggingSeverity severity) noexcept {
  GlobalLogRegistry& reg = GetLogRegistry();
  std::lock_guard<std::mutex> lock(reg.mutex);
  reg.configured_min_severity = severity;
  RecomputeEffectiveMinSeverityLocked();
}

LoggingSeverity LogMessage::GetMinLogSeverity() noexcept {
  return static_cast<LoggingSeverity>(
      min_severity_.load(std::memory_order_relaxed));
}

void LogMessage::SetLogToStderr(bool enable) noexcept {
  log_to_stderr_.store(enable, std::memory_order_relaxed);
}

bool LogMessage::GetLogToStderr() noexcept {
  return log_to_stderr_.load(std::memory_order_relaxed);
}

void LogMessage::AddLogSink(LogSink* sink, LoggingSeverity min_severity) {
  if (sink == nullptr) {
    return;
  }
  GlobalLogRegistry& reg = GetLogRegistry();
  std::lock_guard<std::mutex> lock(reg.mutex);
  for (auto& item : reg.sinks) {
    if (item.sink == sink) {
      item.min_severity = min_severity;
      RecomputeEffectiveMinSeverityLocked();
      return;
    }
  }
  reg.sinks.push_back(RegisteredSink{sink, min_severity});
  RecomputeEffectiveMinSeverityLocked();
}

void LogMessage::RemoveLogSink(LogSink* sink) {
  if (sink == nullptr) {
    return;
  }
  GlobalLogRegistry& reg = GetLogRegistry();
  std::lock_guard<std::mutex> lock(reg.mutex);
  reg.sinks.erase(
      std::remove_if(reg.sinks.begin(), reg.sinks.end(),
                     [sink](const RegisteredSink& r) { return r.sink == sink; }),
      reg.sinks.end());
  RecomputeEffectiveMinSeverityLocked();
}

void LogMessage::SetCLogCallback(rtc_log_callback_fn callback,
                                 void* user_data) {
  GlobalLogRegistry& reg = GetLogRegistry();
  std::lock_guard<std::mutex> lock(reg.mutex);
  reg.c_callback = callback;
  reg.c_user_data = user_data;
}

}  // namespace rtc
