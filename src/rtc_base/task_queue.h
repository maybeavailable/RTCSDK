#ifndef SRC_RTC_BASE_TASK_QUEUE_H_
#define SRC_RTC_BASE_TASK_QUEUE_H_

// 1:1 对标 libwebrtc/api/task_queue/task_queue_base.h、queued_task.h 与
// pc/proxy.h 实现。采用仅支持移动语义的 QueuedTask，底层基于 Boost.Asio
// io_context + strand + steady_timer 实现确定性的串行任务调度。

#include <atomic>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include "api/units.h"
#include "rtc_base/sequence_checker.h"

namespace rtc {

class QueuedTask {
 public:
  virtual ~QueuedTask() = default;
  virtual void Run() = 0;
};

template <typename Closure>
class ClosureTask final : public QueuedTask {
 public:
  explicit ClosureTask(Closure&& closure)
      : closure_(std::forward<Closure>(closure)) {}

  void Run() override { closure_(); }

 private:
  std::decay_t<Closure> closure_;
};

template <typename Closure>
std::unique_ptr<QueuedTask> ToQueuedTask(Closure&& closure) {
  return std::make_unique<ClosureTask<Closure>>(std::forward<Closure>(closure));
}

enum class TaskQueuePriority {
  kNormal = 0,
  kHigh = 1,
};

class TaskQueueBase {
 public:
  TaskQueueBase() = default;
  virtual ~TaskQueueBase() = default;

  TaskQueueBase(const TaskQueueBase&) = delete;
  TaskQueueBase& operator=(const TaskQueueBase&) = delete;

  static TaskQueueBase* Current();

  bool IsCurrent() const { return Current() == this; }
  virtual bool IsStopped() const = 0;
  virtual std::string_view name() const = 0;

  virtual void PostTaskImpl(std::unique_ptr<QueuedTask> task) = 0;
  virtual void PostDelayedTaskImpl(std::unique_ptr<QueuedTask> task,
                                   TimeDelta delay) = 0;
  virtual void PostDelayedHighPrecisionTaskImpl(
      std::unique_ptr<QueuedTask> task,
      TimeDelta delay) = 0;

  template <typename Closure>
  void PostTask(Closure&& closure) {
    PostTaskImpl(ToQueuedTask(std::forward<Closure>(closure)));
  }

  template <typename Closure>
  void PostDelayedTask(Closure&& closure, TimeDelta delay) {
    PostDelayedTaskImpl(ToQueuedTask(std::forward<Closure>(closure)), delay);
  }

  template <typename Closure>
  void PostDelayedHighPrecisionTask(Closure&& closure, TimeDelta delay) {
    PostDelayedHighPrecisionTaskImpl(
        ToQueuedTask(std::forward<Closure>(closure)), delay);
  }

  template <typename Functor>
  auto Invoke(Functor&& fn) -> decltype(fn()) {
    using ReturnT = decltype(fn());
    if (IsCurrent() || IsStopped()) {
      return fn();
    }
    std::packaged_task<ReturnT()> pkg(std::forward<Functor>(fn));
    std::future<ReturnT> fut = pkg.get_future();
    PostTask([p = std::move(pkg)]() mutable { p(); });
    return fut.get();
  }

 protected:
  class CurrentTaskQueueSetter {
   public:
    explicit CurrentTaskQueueSetter(TaskQueueBase* task_queue);
    ~CurrentTaskQueueSetter();

    CurrentTaskQueueSetter(const CurrentTaskQueueSetter&) = delete;
    CurrentTaskQueueSetter& operator=(const CurrentTaskQueueSetter&) = delete;

   private:
    TaskQueueBase* const previous_;
  };
};

class TaskQueueBoost final : public TaskQueueBase {
 public:
  explicit TaskQueueBoost(std::string queue_name,
                          TaskQueuePriority priority = TaskQueuePriority::kNormal);
  ~TaskQueueBoost() override;

  TaskQueueBoost(const TaskQueueBoost&) = delete;
  TaskQueueBoost& operator=(const TaskQueueBoost&) = delete;

  bool IsStopped() const override {
    return stopped_.load(std::memory_order_acquire);
  }
  std::string_view name() const override { return name_; }

  void PostTaskImpl(std::unique_ptr<QueuedTask> task) override;
  void PostDelayedTaskImpl(std::unique_ptr<QueuedTask> task,
                           TimeDelta delay) override;
  void PostDelayedHighPrecisionTaskImpl(std::unique_ptr<QueuedTask> task,
                                        TimeDelta delay) override;

  void Shutdown();

  boost::asio::io_context& io_context() { return io_ctx_; }

 private:
  using WorkGuard =
      boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;

  void ScheduleTimerTask(std::unique_ptr<QueuedTask> task, TimeDelta delay);

  const std::string name_;
  const TaskQueuePriority priority_;
  boost::asio::io_context io_ctx_;
  std::unique_ptr<WorkGuard> work_guard_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  std::thread thread_;
  std::atomic<bool> stopped_{false};
};

// 持有并管理 SDK 的 5 个隔离执行域队列。
class SdkTaskQueues {
 public:
  SdkTaskQueues();
  ~SdkTaskQueues();

  SdkTaskQueues(const SdkTaskQueues&) = delete;
  SdkTaskQueues& operator=(const SdkTaskQueues&) = delete;

  void ShutdownAll();

  TaskQueueBoost* signaling() { return signaling_queue_.get(); }
  TaskQueueBoost* worker() { return worker_queue_.get(); }
  TaskQueueBoost* pacer() { return pacer_queue_.get(); }
  TaskQueueBoost* network() { return network_queue_.get(); }
  TaskQueueBoost* callback() { return callback_queue_.get(); }

 private:
  std::unique_ptr<TaskQueueBoost> signaling_queue_;
  std::unique_ptr<TaskQueueBoost> worker_queue_;
  std::unique_ptr<TaskQueueBoost> pacer_queue_;
  std::unique_ptr<TaskQueueBoost> network_queue_;
  std::unique_ptr<TaskQueueBoost> callback_queue_;
};

}  // namespace rtc

#endif  // SRC_RTC_BASE_TASK_QUEUE_H_
