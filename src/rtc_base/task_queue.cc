#include "rtc_base/task_queue.h"

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif

#include <algorithm>
#include <chrono>

#include "rtc_base/logging.h"

namespace rtc {

namespace {
thread_local TaskQueueBase* g_current_task_queue = nullptr;
}  // namespace

TaskQueueBase* TaskQueueBase::Current() { return g_current_task_queue; }

TaskQueueBase::CurrentTaskQueueSetter::CurrentTaskQueueSetter(
    TaskQueueBase* task_queue)
    : previous_(g_current_task_queue) {
  g_current_task_queue = task_queue;
}

TaskQueueBase::CurrentTaskQueueSetter::~CurrentTaskQueueSetter() {
  g_current_task_queue = previous_;
}

TaskQueueBase::InvokeWaitGuard::InvokeWaitGuard(TaskQueueBase* caller,
                                                const TaskQueueBase* target)
    : caller_(caller) {
  if (caller_ != nullptr && target != nullptr) {
    for (const TaskQueueBase* cur = target; cur != nullptr;
         cur = cur->blocked_on_.load(std::memory_order_acquire)) {
      RTC_DCHECK(cur != caller_);
      if (cur == caller_) {
        break;
      }
    }
    caller_->blocked_on_.store(target, std::memory_order_release);
  }
}

TaskQueueBase::InvokeWaitGuard::~InvokeWaitGuard() {
  if (caller_ != nullptr) {
    caller_->blocked_on_.store(nullptr, std::memory_order_release);
  }
}

void TaskQueueBase::InvokeImpl(QueuedTask* task) {
  if (task == nullptr) {
    return;
  }
  if (IsCurrent() || IsShutdownComplete()) {
    task->Run();
    return;
  }
  InvokeWaitGuard wait_guard(Current(), this);
  std::mutex mu;
  std::condition_variable cv;
  bool done = false;
  PostTask([task, &mu, &cv, &done]() {
    task->Run();
    std::lock_guard<std::mutex> lk(mu);
    done = true;
    cv.notify_all();
  });
  std::unique_lock<std::mutex> lk(mu);
  cv.wait(lk, [&done, this]() { return done || IsShutdownComplete(); });
  if (!done) {
    task->Run();
  }
}

SequenceChecker::SequenceChecker()
    : attached_(true),
      valid_queue_(TaskQueueBase::Current()),
      valid_queue_shutdown_(TaskQueueBase::Current() != nullptr
                                ? TaskQueueBase::Current()->ShutdownToken()
                                : nullptr),
      valid_system_thread_(std::this_thread::get_id()) {}

SequenceChecker::SequenceChecker(TaskQueueBase* attached_queue)
    : attached_(attached_queue != nullptr),
      valid_queue_(attached_queue),
      valid_queue_shutdown_(attached_queue != nullptr
                                ? attached_queue->ShutdownToken()
                                : nullptr),
      valid_system_thread_{} {}

bool SequenceChecker::IsCurrent() const {
  TaskQueueBase* current_queue = TaskQueueBase::Current();
  const std::thread::id current_thread = std::this_thread::get_id();
  std::lock_guard<std::mutex> lock(mutex_);
  if (!attached_) {
    attached_ = true;
    valid_queue_ = current_queue;
    valid_queue_shutdown_ =
        (current_queue != nullptr) ? current_queue->ShutdownToken() : nullptr;
    valid_system_thread_ = current_thread;
    return true;
  }
  if (valid_queue_ != nullptr) {
    return valid_queue_ == static_cast<const void*>(current_queue) ||
           (valid_queue_shutdown_ &&
            valid_queue_shutdown_->load(std::memory_order_acquire));
  }
  return valid_system_thread_ == current_thread;
}

void SequenceChecker::Detach() {
  std::lock_guard<std::mutex> lock(mutex_);
  attached_ = false;
  valid_queue_ = nullptr;
  valid_queue_shutdown_.reset();
  valid_system_thread_ = std::thread::id{};
}

TaskQueueBoost::TaskQueueBoost(std::string queue_name,
                               TaskQueuePriority priority)
    : priority_(priority),
      state_(std::make_shared<CoreState>(std::move(queue_name))) {
  std::shared_ptr<CoreState> state = state_;
  const TaskQueuePriority prio = priority_;
  thread_ = std::thread([this, state, prio]() {
    {
      std::lock_guard<std::mutex> lk(state->lifecycle_mu);
      state->worker_tid = std::this_thread::get_id();
    }
    {
      CurrentTaskQueueSetter setter(this);
#if defined(__linux__)
      const std::string short_name = state->name.substr(0, 15);
      pthread_setname_np(pthread_self(), short_name.c_str());
      if (prio == TaskQueuePriority::kHigh) {
        struct sched_param param {};
        param.sched_priority = 10;
        pthread_setschedparam(pthread_self(), SCHED_RR, &param);
      }
#endif
      RTC_LOG(kVerbose) << "TaskQueue started (priority="
                        << (prio == TaskQueuePriority::kHigh ? "kHigh"
                                                             : "kNormal")
                        << ")";
      state->io_ctx.run();
    }
    std::vector<std::shared_ptr<InvokeWaitSlot>> waiters;
    {
      std::lock_guard<std::mutex> lk(state->lifecycle_mu);
      state->worker_tid = std::thread::id{};
      state->shutdown_complete.store(true, std::memory_order_release);
      state->checker_shutdown_flag->store(true, std::memory_order_release);
      state->active_timers.clear();
      waiters.swap(state->pending_invokes);
      state->lifecycle_cv.notify_all();
    }
    for (const auto& slot : waiters) {
      std::lock_guard<std::mutex> slk(slot->mu);
      slot->cv.notify_all();
    }
  });
}

TaskQueueBoost::~TaskQueueBoost() { Shutdown(); }

void TaskQueueBoost::Shutdown() {
  std::vector<std::shared_ptr<boost::asio::steady_timer>> timers_to_cancel;
  {
    std::lock_guard<std::mutex> lk(state_->lifecycle_mu);
    if (state_->stopped.exchange(true, std::memory_order_acq_rel)) {
      return;
    }
    for (const auto& wt : state_->active_timers) {
      if (auto locked = wt.lock()) {
        timers_to_cancel.push_back(std::move(locked));
      }
    }
    state_->active_timers.clear();
    state_->work_guard.reset();
    state_->io_ctx.stop();
  }
  for (const auto& timer : timers_to_cancel) {
    boost::system::error_code ec;
    timer->cancel(ec);
  }
  timers_to_cancel.clear();

  if (thread_.joinable()) {
    if (thread_.get_id() == std::this_thread::get_id()) {
      // 当在回调线程自身内部销毁客户端时，提前清空 TLS 中的 TaskQueueBase* 悬垂指针，
      // 置位 checker_shutdown_flag 防止后续析构链触发虚调用，并由值捕获的 CoreState 保障安全退栈。
      if (g_current_task_queue == this) {
        g_current_task_queue = nullptr;
      }
      state_->checker_shutdown_flag->store(true, std::memory_order_release);
      thread_.detach();
      return;
    }
    thread_.join();
  }
  {
    std::lock_guard<std::mutex> lk(state_->lifecycle_mu);
    state_->worker_tid = std::thread::id{};
    state_->shutdown_complete.store(true, std::memory_order_release);
    state_->checker_shutdown_flag->store(true, std::memory_order_release);
    state_->lifecycle_cv.notify_all();
  }
}

void TaskQueueBoost::InvokeImpl(QueuedTask* task) {
  if (task == nullptr) {
    return;
  }
  if (IsCurrent()) {
    task->Run();
    return;
  }
  std::shared_ptr<CoreState> state = state_;
  {
    std::lock_guard<std::mutex> lk(state->lifecycle_mu);
    if (state->worker_tid == std::this_thread::get_id()) {
      // 回调线程自析构窗口（g_current_task_queue 已置空但 io_ctx.run() 尚未退栈）：
      // 直接在当前线程内联执行，避免等待自身线程退栈造成自死锁。
      task->Run();
      return;
    }
  }

  InvokeWaitGuard wait_guard(Current(), this);
  std::shared_ptr<InvokeWaitSlot> slot;
  {
    std::unique_lock<std::mutex> lk(state->lifecycle_mu);
    if (state->stopped.load(std::memory_order_acquire)) {
      state->lifecycle_cv.wait(lk, [&state]() {
        return state->shutdown_complete.load(std::memory_order_acquire);
      });
      lk.unlock();
      std::lock_guard<std::mutex> exec_lk(state->post_shutdown_exec_mu);
      CurrentTaskQueueSetter setter(nullptr);
      task->Run();
      return;
    }
    slot = std::make_shared<InvokeWaitSlot>(task);
    state->pending_invokes.push_back(slot);
    boost::asio::post(state->strand, [slot]() {
      slot->task->Run();
      {
        std::lock_guard<std::mutex> slk(slot->mu);
        slot->finished = true;
      }
      slot->cv.notify_all();
    });
  }

  bool ran_on_strand = false;
  {
    std::unique_lock<std::mutex> slk(slot->mu);
    slot->cv.wait(slk, [&slot, &state]() {
      return slot->finished ||
             state->shutdown_complete.load(std::memory_order_acquire);
    });
    ran_on_strand = slot->finished;
  }

  {
    std::lock_guard<std::mutex> lk(state->lifecycle_mu);
    state->pending_invokes.erase(
        std::remove(state->pending_invokes.begin(),
                    state->pending_invokes.end(), slot),
        state->pending_invokes.end());
  }

  if (!ran_on_strand) {
    // io_ctx.run() 已完全退栈且该槽位未在队列线程上运行，串行化兜底执行以确保不丢不并发不抛异常。
    std::lock_guard<std::mutex> exec_lk(state->post_shutdown_exec_mu);
    CurrentTaskQueueSetter setter(nullptr);
    task->Run();
  }
}

void TaskQueueBoost::PostTaskImpl(std::unique_ptr<QueuedTask> task) {
  if (!task) {
    return;
  }
  std::shared_ptr<CoreState> state = state_;
  std::lock_guard<std::mutex> lk(state->lifecycle_mu);
  if (state->stopped.load(std::memory_order_acquire)) {
    return;
  }
  std::weak_ptr<CoreState> weak_state = state;
  boost::asio::post(
      state->strand,
      [weak_state = std::move(weak_state), t = std::move(task)]() mutable {
        const auto locked = weak_state.lock();
        if (locked && !locked->stopped.load(std::memory_order_acquire) && t) {
          t->Run();
        }
      });
}

void TaskQueueBoost::PostDelayedTaskImpl(std::unique_ptr<QueuedTask> task,
                                         TimeDelta delay) {
  ScheduleTimerTask(std::move(task), delay);
}

void TaskQueueBoost::PostDelayedHighPrecisionTaskImpl(
    std::unique_ptr<QueuedTask> task,
    TimeDelta delay) {
  ScheduleTimerTask(std::move(task), delay);
}

void TaskQueueBoost::ScheduleTimerTask(std::unique_ptr<QueuedTask> task,
                                       TimeDelta delay) {
  if (!task) {
    return;
  }
  if (delay <= TimeDelta::Zero()) {
    PostTaskImpl(std::move(task));
    return;
  }
  std::shared_ptr<CoreState> state = state_;
  std::lock_guard<std::mutex> lk(state->lifecycle_mu);
  if (state->stopped.load(std::memory_order_acquire)) {
    return;
  }
  if (state->active_timers.size() >= 256) {
    state->active_timers.erase(
        std::remove_if(
            state->active_timers.begin(), state->active_timers.end(),
            [](const std::weak_ptr<boost::asio::steady_timer>& w) {
              return w.expired();
            }),
        state->active_timers.end());
  }
  auto timer = std::make_shared<boost::asio::steady_timer>(
      state->strand, std::chrono::microseconds(delay.us()));
  state->active_timers.push_back(timer);
  std::weak_ptr<CoreState> weak_state = state;
  timer->async_wait(
      [weak_state = std::move(weak_state), timer,
       t = std::move(task)](const boost::system::error_code& ec) mutable {
        const auto locked = weak_state.lock();
        if (!ec && locked && !locked->stopped.load(std::memory_order_acquire) &&
            t) {
          t->Run();
        }
      });
}

SdkTaskQueues::SdkTaskQueues()
    : signaling_queue_(
          std::make_unique<TaskQueueBoost>("rtc-sig", TaskQueuePriority::kNormal)),
      worker_queue_(
          std::make_unique<TaskQueueBoost>("rtc-work", TaskQueuePriority::kNormal)),
      pacer_queue_(
          std::make_unique<TaskQueueBoost>("rtc-pacer", TaskQueuePriority::kHigh)),
      network_queue_(
          std::make_unique<TaskQueueBoost>("rtc-net", TaskQueuePriority::kHigh)),
      callback_queue_(
          std::make_unique<TaskQueueBoost>("rtc-cb", TaskQueuePriority::kNormal)) {}

SdkTaskQueues::~SdkTaskQueues() { ShutdownAll(); }

void SdkTaskQueues::ShutdownAll() {
  if (pacer_queue_) {
    pacer_queue_->Shutdown();
  }
  if (worker_queue_) {
    worker_queue_->Shutdown();
  }
  if (network_queue_) {
    network_queue_->Shutdown();
  }
  if (signaling_queue_) {
    signaling_queue_->Shutdown();
  }
  if (callback_queue_) {
    callback_queue_->Shutdown();
  }
}

}  // namespace rtc
