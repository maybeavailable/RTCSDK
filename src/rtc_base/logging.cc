#include "rtc_base/logging.h"

#if defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>

#include "rtc_base/task_queue.h"

namespace rtc {

namespace {

struct RegisteredSink {
  explicit RegisteredSink(LogSink* s, LoggingSeverity sev)
      : sink(s), min_severity(static_cast<int>(sev)) {}

  LogSink* const sink;
  std::atomic<int> min_severity;
  std::atomic<bool> active{true};
  std::mutex inflight_mu;
  std::condition_variable inflight_cv;
  uint32_t inflight_count = 0;
};

struct GlobalLogRegistry {
  std::mutex mutex;
  LoggingSeverity configured_min_severity = LoggingSeverity::kInfo;
  std::vector<std::shared_ptr<RegisteredSink>> sinks;
};

thread_local bool g_in_log_sink_dispatch = false;
thread_local RegisteredSink* g_current_dispatch_sink = nullptr;
std::atomic<int> g_stderr_min_severity{
    static_cast<int>(LoggingSeverity::kInfo)};

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
#if defined(_WIN32)
  localtime_s(&tm_buf, &sec);
#else
  localtime_r(&sec, &tm_buf);
#endif

  char buf[80];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, millis);
  return std::string(buf);
}

}  // namespace

// ======================= RingBufferLogSink 环形缓冲日志接收器 =======================

LogSink::~LogSink() { LogMessage::RemoveLogSink(this); }

RingBufferLogSink::RingBufferLogSink(size_t capacity)
    : capacity_(std::max<size_t>(capacity, 16)) {}

RingBufferLogSink::~RingBufferLogSink() { LogMessage::RemoveLogSink(this); }

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

  if (log_to_stderr_.load(std::memory_order_relaxed) &&
      static_cast<int>(severity_) >=
          g_stderr_min_severity.load(std::memory_order_relaxed)) {
    std::fprintf(stderr, "%s\n", formatted.c_str());
  }

  if (g_in_log_sink_dispatch) {
    return;
  }

  LogEntryView view;
  view.severity = severity_;
  view.timestamp_us = timestamp_us_;
  view.queue_name = queue_tag;
  view.file_name = file_str;
  view.line = line_;
  view.message = payload;

  std::vector<std::shared_ptr<RegisteredSink>> snapshot;
  {
    GlobalLogRegistry& reg = GetLogRegistry();
    std::lock_guard<std::mutex> lock(reg.mutex);
    snapshot = reg.sinks;
  }

  struct ReentrancyGuard {
    ReentrancyGuard() { g_in_log_sink_dispatch = true; }
    ~ReentrancyGuard() {
      g_in_log_sink_dispatch = false;
      g_current_dispatch_sink = nullptr;
    }
  } guard;

  for (const auto& item : snapshot) {
    if (!item || item->sink == nullptr ||
        !item->active.load(std::memory_order_acquire) ||
        static_cast<int>(severity_) <
            item->min_severity.load(std::memory_order_relaxed)) {
      continue;
    }
    {
      std::lock_guard<std::mutex> lk(item->inflight_mu);
      if (!item->active.load(std::memory_order_relaxed)) {
        continue;
      }
      ++item->inflight_count;
    }
    g_current_dispatch_sink = item.get();
    item->sink->OnLogMessage(view, formatted);
    g_current_dispatch_sink = nullptr;
    {
      std::lock_guard<std::mutex> lk(item->inflight_mu);
      if (--item->inflight_count == 0) {
        item->inflight_cv.notify_all();
      }
    }
  }
}

void LogMessage::RecomputeEffectiveMinSeverityLocked() {
  GlobalLogRegistry& reg = GetLogRegistry();
  int effective = static_cast<int>(reg.configured_min_severity);
  for (const auto& item : reg.sinks) {
    if (item) {
      effective =
          std::min(effective, item->min_severity.load(std::memory_order_relaxed));
    }
  }
  min_severity_.store(effective, std::memory_order_relaxed);
}

void LogMessage::SetMinLogSeverity(LoggingSeverity severity) noexcept {
  GlobalLogRegistry& reg = GetLogRegistry();
  std::lock_guard<std::mutex> lock(reg.mutex);
  reg.configured_min_severity = severity;
  g_stderr_min_severity.store(static_cast<int>(severity),
                              std::memory_order_relaxed);
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
    if (item && item->sink == sink) {
      item->min_severity.store(static_cast<int>(min_severity),
                               std::memory_order_relaxed);
      RecomputeEffectiveMinSeverityLocked();
      return;
    }
  }
  reg.sinks.push_back(std::make_shared<RegisteredSink>(sink, min_severity));
  RecomputeEffectiveMinSeverityLocked();
}

void LogMessage::RemoveLogSink(LogSink* sink) {
  if (sink == nullptr) {
    return;
  }
  std::shared_ptr<RegisteredSink> removed;
  {
    GlobalLogRegistry& reg = GetLogRegistry();
    std::lock_guard<std::mutex> lock(reg.mutex);
    for (auto it = reg.sinks.begin(); it != reg.sinks.end(); ++it) {
      if (*it && (*it)->sink == sink) {
        removed = *it;
        removed->active.store(false, std::memory_order_release);
        reg.sinks.erase(it);
        break;
      }
    }
    RecomputeEffectiveMinSeverityLocked();
  }
  if (removed && g_current_dispatch_sink != removed.get()) {
    std::unique_lock<std::mutex> lk(removed->inflight_mu);
    removed->inflight_cv.wait(lk, [&]() { return removed->inflight_count == 0; });
  }
}

}  // namespace rtc
