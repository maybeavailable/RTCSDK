#ifndef SRC_RTC_BASE_SEQUENCE_CHECKER_H_
#define SRC_RTC_BASE_SEQUENCE_CHECKER_H_

// 1:1 对标 libwebrtc/api/sequence_checker.h 实现。
// 在 SDK 各层强制执行无锁单队列/单线程归属不变量检查，
// 并在触发断言终止前将违规诊断信息路由至统一 LogMessage 日志接收器。

#include <atomic>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <thread>

#include "rtc_base/logging.h"

namespace rtc {

class TaskQueueBase;

#define RTC_CHECK(cond)                                                 \
  do {                                                                  \
    if (!(cond)) {                                                      \
      RTC_LOG(kError) << "Fatal check failed: " << #cond;               \
      std::abort();                                                     \
    }                                                                   \
  } while (0)

#if !defined(NDEBUG) || defined(RTC_DCHECK_IS_ON)
#define RTC_DCHECK(cond) RTC_CHECK(cond)
#else
#define RTC_DCHECK(cond) ((void)sizeof(cond))
#endif

class SequenceChecker {
 public:
  SequenceChecker();
  explicit SequenceChecker(TaskQueueBase* attached_queue);

  SequenceChecker(const SequenceChecker&) = delete;
  SequenceChecker& operator=(const SequenceChecker&) = delete;

  bool IsCurrent() const;
  void Detach();

 private:
  mutable std::mutex mutex_;
  mutable bool attached_ = false;
  // 仅用于不透明地址比较，严禁解引用（避免关联队列析构后虚函数调用悬垂）。
  mutable const void* valid_queue_ = nullptr;
  mutable std::shared_ptr<const std::atomic<bool>> valid_queue_shutdown_;
  mutable std::thread::id valid_system_thread_{};
};

#if !defined(NDEBUG) || defined(RTC_DCHECK_IS_ON)
#define RTC_DCHECK_RUN_ON(checker_ptr) RTC_CHECK((checker_ptr)->IsCurrent())
#else
#define RTC_DCHECK_RUN_ON(checker_ptr) ((void)(checker_ptr))
#endif

}  // namespace rtc

#endif  // SRC_RTC_BASE_SEQUENCE_CHECKER_H_
