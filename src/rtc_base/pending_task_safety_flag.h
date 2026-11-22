#ifndef SRC_RTC_BASE_PENDING_TASK_SAFETY_FLAG_H_
#define SRC_RTC_BASE_PENDING_TASK_SAFETY_FLAG_H_

// 1:1 对标 libwebrtc/api/task_queue/pending_task_safety_flag.h 实现。
// 在不引入循环 std::shared_ptr 所有权的前提下，消除跨异步 TaskQueue 的释放后使用（UAF）风险。

#include <atomic>
#include <memory>
#include <utility>

#include "rtc_base/sequence_checker.h"

namespace rtc {

class PendingTaskSafetyFlag final {
 public:
  static std::shared_ptr<PendingTaskSafetyFlag> Create() {
    return std::shared_ptr<PendingTaskSafetyFlag>(
        new PendingTaskSafetyFlag(true));
  }

  static std::shared_ptr<PendingTaskSafetyFlag> CreateDetached() {
    auto flag =
        std::shared_ptr<PendingTaskSafetyFlag>(new PendingTaskSafetyFlag(true));
    flag->checker_.Detach();
    return flag;
  }

  static std::shared_ptr<PendingTaskSafetyFlag> CreateDetachedInactive() {
    auto flag = std::shared_ptr<PendingTaskSafetyFlag>(
        new PendingTaskSafetyFlag(false));
    flag->checker_.Detach();
    return flag;
  }

  PendingTaskSafetyFlag(const PendingTaskSafetyFlag&) = delete;
  PendingTaskSafetyFlag& operator=(const PendingTaskSafetyFlag&) = delete;

  void SetNotAlive() {
    RTC_DCHECK_RUN_ON(&checker_);
    alive_.store(false, std::memory_order_release);
  }

  void SetAlive() {
    RTC_DCHECK_RUN_ON(&checker_);
    alive_.store(true, std::memory_order_release);
  }

  bool alive() const { return alive_.load(std::memory_order_acquire); }

 private:
  explicit PendingTaskSafetyFlag(bool alive) : alive_(alive) {}

  std::atomic<bool> alive_;
  SequenceChecker checker_;
};

class ScopedTaskSafety final {
 public:
  ScopedTaskSafety() : flag_(PendingTaskSafetyFlag::Create()) {}
  explicit ScopedTaskSafety(std::shared_ptr<PendingTaskSafetyFlag> flag)
      : flag_(std::move(flag)) {}

  ~ScopedTaskSafety() {
    if (flag_ && flag_->alive()) {
      flag_->SetNotAlive();
    }
  }

  ScopedTaskSafety(const ScopedTaskSafety&) = delete;
  ScopedTaskSafety& operator=(const ScopedTaskSafety&) = delete;

  std::shared_ptr<PendingTaskSafetyFlag> flag() const { return flag_; }

  void Reset(std::shared_ptr<PendingTaskSafetyFlag> new_flag =
                 PendingTaskSafetyFlag::Create()) {
    if (flag_ && flag_->alive()) {
      flag_->SetNotAlive();
    }
    flag_ = std::move(new_flag);
  }

 private:
  std::shared_ptr<PendingTaskSafetyFlag> flag_;
};

template <typename Closure>
auto SafeTask(std::shared_ptr<PendingTaskSafetyFlag> flag, Closure&& closure) {
  return [flag = std::move(flag),
          task = std::forward<Closure>(closure)](auto&&... args) mutable {
    if (flag->alive()) {
      task(std::forward<decltype(args)>(args)...);
    }
  };
}

}  // namespace rtc

#endif  // SRC_RTC_BASE_PENDING_TASK_SAFETY_FLAG_H_
