#include "rtc_base/task_queue.h"

#include <pthread.h>
#include <sched.h>

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

SequenceChecker::SequenceChecker()
    : attached_(true),
      valid_queue_(TaskQueueBase::Current()),
      valid_system_thread_(std::this_thread::get_id()) {}

SequenceChecker::SequenceChecker(TaskQueueBase* attached_queue)
    : attached_(attached_queue != nullptr),
      valid_queue_(attached_queue),
      valid_system_thread_{} {}

bool SequenceChecker::IsCurrent() const {
  const TaskQueueBase* current_queue = TaskQueueBase::Current();
  const std::thread::id current_thread = std::this_thread::get_id();
  std::lock_guard<std::mutex> lock(mutex_);
  if (!attached_) {
    attached_ = true;
    valid_queue_ = current_queue;
    valid_system_thread_ = current_thread;
    return true;
  }
  if (valid_queue_ != nullptr) {
    return valid_queue_ == current_queue;
  }
  return valid_system_thread_ == current_thread;
}

void SequenceChecker::Detach() {
  std::lock_guard<std::mutex> lock(mutex_);
  attached_ = false;
  valid_queue_ = nullptr;
  valid_system_thread_ = std::thread::id{};
}

TaskQueueBoost::TaskQueueBoost(std::string queue_name,
                               TaskQueuePriority priority)
    : name_(std::move(queue_name)),
      priority_(priority),
      io_ctx_(1),
      work_guard_(
          std::make_unique<WorkGuard>(boost::asio::make_work_guard(io_ctx_))),
      strand_(boost::asio::make_strand(io_ctx_)) {
  thread_ = std::thread([this]() {
    CurrentTaskQueueSetter setter(this);
#if defined(__linux__)
    const std::string short_name = name_.substr(0, 15);
    pthread_setname_np(pthread_self(), short_name.c_str());
    if (priority_ == TaskQueuePriority::kHigh) {
      struct sched_param param {};
      param.sched_priority = 10;
      pthread_setschedparam(pthread_self(), SCHED_RR, &param);
    }
#endif
    RTC_LOG(kVerbose) << "TaskQueue started (priority="
                      << (priority_ == TaskQueuePriority::kHigh ? "kHigh"
                                                                : "kNormal")
                      << ")";
    io_ctx_.run();
    RTC_LOG(kVerbose) << "TaskQueue event loop exited";
  });
}

TaskQueueBoost::~TaskQueueBoost() { Shutdown(); }

void TaskQueueBoost::Shutdown() {
  bool expected = false;
  if (!stopped_.compare_exchange_strong(expected, true,
                                        std::memory_order_acq_rel)) {
    return;
  }
  work_guard_.reset();
  io_ctx_.stop();
  if (thread_.joinable()) {
    if (thread_.get_id() == std::this_thread::get_id()) {
      thread_.detach();
    } else {
      thread_.join();
    }
  }
}

void TaskQueueBoost::PostTaskImpl(std::unique_ptr<QueuedTask> task) {
  if (stopped_.load(std::memory_order_acquire) || !task) {
    return;
  }
  boost::asio::post(strand_, [t = std::move(task)]() mutable { t->Run(); });
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
  if (stopped_.load(std::memory_order_acquire) || !task) {
    return;
  }
  if (delay <= TimeDelta::Zero()) {
    PostTaskImpl(std::move(task));
    return;
  }
  auto timer = std::make_shared<boost::asio::steady_timer>(
      strand_, std::chrono::microseconds(delay.us()));
  timer->async_wait(
      [timer, t = std::move(task)](const boost::system::error_code& ec) mutable {
        if (!ec && t) {
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
