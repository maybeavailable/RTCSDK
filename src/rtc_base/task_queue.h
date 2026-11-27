#ifndef SRC_RTC_BASE_TASK_QUEUE_H_
#define SRC_RTC_BASE_TASK_QUEUE_H_

// 1:1 对标 libwebrtc/api/task_queue/task_queue_base.h、queued_task.h 与
// pc/proxy.h 实现。采用仅支持移动语义的 QueuedTask，底层基于 Boost.Asio
// io_context + strand + steady_timer 实现确定性的串行任务调度。

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

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
  virtual bool IsShutdownComplete() const { return IsStopped(); }
  virtual std::shared_ptr<const std::atomic<bool>> ShutdownToken() const {
    return nullptr;
  }
  virtual std::string_view name() const = 0;

  virtual void PostTaskImpl(std::unique_ptr<QueuedTask> task) = 0;
  virtual void PostDelayedTaskImpl(std::unique_ptr<QueuedTask> task,
                                   TimeDelta delay) = 0;
  virtual void PostDelayedHighPrecisionTaskImpl(
      std::unique_ptr<QueuedTask> task,
      TimeDelta delay) = 0;
  virtual void InvokeImpl(QueuedTask* task);

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

  // 在目标队列上同步阻塞执行 `fn` 并返回结果。
  // 调用约束：必须严格遵循单向有向无环图顺序（外部线程 -> signaling -> worker -> network/pacer，
  // 严禁两个 TaskQueue 互相跨队列 Invoke，否则会形成循环等待死锁；开启 DCHECK 时会自动断言检测环路）。
  template <typename Functor>
  auto Invoke(Functor&& fn) -> decltype(fn()) {
    using ReturnT = decltype(fn());
    if (IsCurrent()) {
      return fn();
    }
    if constexpr (std::is_void_v<ReturnT>) {
      ClosureTask<Functor> task(std::forward<Functor>(fn));
      InvokeImpl(&task);
    } else {
      std::optional<ReturnT> ret;
      auto wrapper = [&fn, &ret]() { ret.emplace(std::forward<Functor>(fn)()); };
      ClosureTask<decltype(wrapper)> task(std::move(wrapper));
      InvokeImpl(&task);
      return std::move(*ret);
    }
  }

 protected:
  class InvokeWaitGuard {
   public:
    InvokeWaitGuard(TaskQueueBase* caller, const TaskQueueBase* target);
    ~InvokeWaitGuard();

    InvokeWaitGuard(const InvokeWaitGuard&) = delete;
    InvokeWaitGuard& operator=(const InvokeWaitGuard&) = delete;

   private:
    TaskQueueBase* const caller_;
  };

  class CurrentTaskQueueSetter {
   public:
    explicit CurrentTaskQueueSetter(TaskQueueBase* task_queue);
    ~CurrentTaskQueueSetter();

    CurrentTaskQueueSetter(const CurrentTaskQueueSetter&) = delete;
    CurrentTaskQueueSetter& operator=(const CurrentTaskQueueSetter&) = delete;

   private:
    TaskQueueBase* const previous_;
  };

 private:
  std::atomic<const TaskQueueBase*> blocked_on_{nullptr};
};

class TaskQueueBoost final : public TaskQueueBase {
 public:
  explicit TaskQueueBoost(std::string queue_name,
                          TaskQueuePriority priority = TaskQueuePriority::kNormal);
  ~TaskQueueBoost() override;

  TaskQueueBoost(const TaskQueueBoost&) = delete;
  TaskQueueBoost& operator=(const TaskQueueBoost&) = delete;

  bool IsStopped() const override {
    return state_->stopped.load(std::memory_order_acquire);
  }
  bool IsShutdownComplete() const override {
    return state_->shutdown_complete.load(std::memory_order_acquire);
  }
  std::shared_ptr<const std::atomic<bool>> ShutdownToken() const override {
    return state_->checker_shutdown_flag;
  }
  std::string_view name() const override { return state_->name; }

  void PostTaskImpl(std::unique_ptr<QueuedTask> task) override;
  void PostDelayedTaskImpl(std::unique_ptr<QueuedTask> task,
                           TimeDelta delay) override;
  void PostDelayedHighPrecisionTaskImpl(std::unique_ptr<QueuedTask> task,
                                        TimeDelta delay) override;
  void InvokeImpl(QueuedTask* task) override;

  void Shutdown();

  boost::asio::io_context& io_context() { return state_->io_ctx; }

 private:
  using WorkGuard =
      boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;

  struct InvokeWaitSlot {
    explicit InvokeWaitSlot(QueuedTask* t) : task(t) {}
    std::mutex mu;
    std::condition_variable cv;
    QueuedTask* task = nullptr;
    bool finished = false;
  };

  struct CoreState {
    explicit CoreState(std::string queue_name)
        : name(std::move(queue_name)),
          io_ctx(1),
          work_guard(
              std::make_unique<WorkGuard>(boost::asio::make_work_guard(io_ctx))),
          strand(boost::asio::make_strand(io_ctx)),
          checker_shutdown_flag(std::make_shared<std::atomic<bool>>(false)) {}

    const std::string name;
    boost::asio::io_context io_ctx;
    std::unique_ptr<WorkGuard> work_guard;
    boost::asio::strand<boost::asio::io_context::executor_type> strand;
    std::atomic<bool> stopped{false};
    std::atomic<bool> shutdown_complete{false};
    std::shared_ptr<std::atomic<bool>> checker_shutdown_flag;
    std::mutex lifecycle_mu;
    std::condition_variable lifecycle_cv;
    std::thread::id worker_tid{};
    std::mutex post_shutdown_exec_mu;
    std::vector<std::shared_ptr<InvokeWaitSlot>> pending_invokes;
    std::vector<std::weak_ptr<boost::asio::steady_timer>> active_timers;
  };

  void ScheduleTimerTask(std::unique_ptr<QueuedTask> task, TimeDelta delay);

  const TaskQueuePriority priority_;
  std::shared_ptr<CoreState> state_;
  std::thread thread_;
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
