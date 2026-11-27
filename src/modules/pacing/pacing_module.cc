#include "modules/pacing/pacing_module.h"

#include <algorithm>
#include <cmath>

#include "rtc_base/logging.h"

namespace rtc {

namespace {
constexpr int64_t kWindowMs = 500;
constexpr int64_t kDeltaTimeMaxMs = 2000;

bool CompareQueuedPacket(const RoundRobinPacketQueue::QueuedPacket& a,
                         const RoundRobinPacketQueue::QueuedPacket& b) {
  if (a.type != b.type) {
    return static_cast<int>(a.type) > static_cast<int>(b.type);
  }
  return a.enqueue_order > b.enqueue_order;
}
}  // namespace

// ======================= IntervalBudget 时间区间发送预算 =======================

IntervalBudget::IntervalBudget(int initial_target_rate_kbps,
                               bool can_build_up_underuse)
    : can_build_up_underuse_(can_build_up_underuse) {
  set_target_rate_kbps(initial_target_rate_kbps);
}

void IntervalBudget::set_target_rate_kbps(int target_rate_kbps) {
  target_rate_kbps_ = std::max(0, target_rate_kbps);
  max_bytes_in_budget_ =
      (kWindowMs * static_cast<int64_t>(target_rate_kbps_)) / 8;
  bytes_remaining_ =
      std::clamp(bytes_remaining_, -max_bytes_in_budget_, max_bytes_in_budget_);
}

void IntervalBudget::IncreaseBudget(int64_t delta_time_ms) {
  IncreaseBudgetUs(std::clamp<int64_t>(delta_time_ms, 0, kDeltaTimeMaxMs) *
                   1000);
}

void IntervalBudget::IncreaseBudgetUs(int64_t delta_time_us) {
  delta_time_us =
      std::clamp<int64_t>(delta_time_us, 0, kDeltaTimeMaxMs * 1000);
  const int64_t total_kbps_us =
      static_cast<int64_t>(target_rate_kbps_) * delta_time_us +
      sub_byte_kbps_us_rem_;
  const int64_t bytes = total_kbps_us / 8000;
  sub_byte_kbps_us_rem_ = total_kbps_us % 8000;

  if (bytes_remaining_ < 0 || can_build_up_underuse_) {
    bytes_remaining_ = std::min(bytes_remaining_ + bytes, max_bytes_in_budget_);
  } else {
    bytes_remaining_ = std::min(std::max(bytes_remaining_, bytes),
                                max_bytes_in_budget_);
  }
}

void IntervalBudget::UseBudget(size_t bytes) {
  bytes_remaining_ = std::max(
      bytes_remaining_ - static_cast<int64_t>(bytes), -max_bytes_in_budget_);
}

size_t IntervalBudget::bytes_remaining() const {
  return bytes_remaining_ > 0 ? static_cast<size_t>(bytes_remaining_) : 0;
}

double IntervalBudget::budget_ratio() const {
  if (max_bytes_in_budget_ == 0) {
    return 0.0;
  }
  return static_cast<double>(bytes_remaining_) /
         static_cast<double>(max_bytes_in_budget_);
}

// ======================= BitrateProber 带宽码率探测器 =======================

void BitrateProber::SetEnabled(bool enable) {
  if (enable) {
    if (probing_state_ == ProbingState::kDisabled) {
      probing_state_ = ProbingState::kInactive;
    }
  } else {
    probing_state_ = ProbingState::kDisabled;
    while (!clusters_.empty()) {
      clusters_.pop();
    }
  }
}

void BitrateProber::OnIncomingPacket(DataSize packet_size) {
  if (probing_state_ == ProbingState::kInactive && !clusters_.empty() &&
      packet_size >=
          DataSize::Bytes(std::min<size_t>(RecommendedMinProbeSize(), 200))) {
    probing_state_ = ProbingState::kActive;
    next_probe_time_ = Timestamp::MinusInfinity();
  }
}

void BitrateProber::CreateProbeCluster(
    const ProbeClusterConfig& cluster_config) {
  if (probing_state_ == ProbingState::kDisabled) {
    return;
  }
  while (clusters_.size() >= 5) {
    clusters_.pop();
  }
  ProbeCluster cluster;
  cluster.requested_at = cluster_config.at_time;
  cluster.pace_info.probe_cluster_id = cluster_config.id;
  cluster.pace_info.probe_cluster_min_probes =
      cluster_config.target_probe_count;
  cluster.pace_info.probe_cluster_min_bytes = static_cast<int>(
      (cluster_config.target_data_rate * cluster_config.target_duration)
          .bytes());
  cluster.pace_info.send_bitrate = cluster_config.target_data_rate;
  clusters_.push(cluster);

  RTC_LOG(kVerbose) << "Created bandwidth probe cluster id=" << cluster_config.id
                    << " target_kbps="
                    << cluster_config.target_data_rate.kbps();

  if (probing_state_ == ProbingState::kInactive) {
    probing_state_ = ProbingState::kActive;
    next_probe_time_ = cluster_config.at_time;
  }
}

Timestamp BitrateProber::NextProbeTime(Timestamp now) const {
  if (probing_state_ != ProbingState::kActive || clusters_.empty()) {
    return Timestamp::PlusInfinity();
  }
  if (next_probe_time_.IsMinusInfinity()) {
    return now;
  }
  return next_probe_time_;
}

std::optional<PacedPacketInfo> BitrateProber::CurrentCluster(Timestamp now) {
  if (clusters_.empty() || probing_state_ != ProbingState::kActive) {
    return std::nullopt;
  }
  if ((next_probe_time_.IsFinite() &&
       (now - next_probe_time_) > TimeDelta::Millis(20)) ||
      (clusters_.front().started_at.IsFinite() &&
       (now - clusters_.front().started_at) > TimeDelta::Millis(100))) {
    clusters_.pop();
    if (clusters_.empty()) {
      probing_state_ = ProbingState::kInactive;
      next_probe_time_ = Timestamp::PlusInfinity();
      return std::nullopt;
    }
    next_probe_time_ = Timestamp::MinusInfinity();
  }
  ProbeCluster& cur = clusters_.front();
  if (cur.started_at.IsMinusInfinity()) {
    cur.started_at = now;
  }
  return cur.pace_info;
}

size_t BitrateProber::RecommendedMinProbeSize() const {
  if (clusters_.empty()) {
    return 0;
  }
  const DataSize min_size =
      clusters_.front().pace_info.send_bitrate * TimeDelta::Millis(2);
  return static_cast<size_t>(std::clamp<int64_t>(min_size.bytes(), 200, 1200));
}

Timestamp BitrateProber::CalculateNextProbeTime(
    const ProbeCluster& cluster) const {
  if (cluster.pace_info.send_bitrate.bps() <= 0 ||
      cluster.started_at.IsInfinite()) {
    return Timestamp::PlusInfinity();
  }
  const DataSize sent = DataSize::Bytes(cluster.sent_bytes);
  return cluster.started_at + (sent / cluster.pace_info.send_bitrate);
}

void BitrateProber::ProbeSent(Timestamp now, DataSize size) {
  if (clusters_.empty() || probing_state_ != ProbingState::kActive) {
    return;
  }
  ProbeCluster& cur = clusters_.front();
  if (cur.started_at.IsMinusInfinity()) {
    cur.started_at = now;
  }
  cur.sent_bytes += static_cast<int>(size.bytes());
  cur.sent_probes += 1;
  next_probe_time_ = CalculateNextProbeTime(cur);

  if (cur.sent_bytes >= cur.pace_info.probe_cluster_min_bytes &&
      cur.sent_probes >= cur.pace_info.probe_cluster_min_probes) {
    RTC_LOG(kVerbose) << "Completed probe cluster id="
                      << cur.pace_info.probe_cluster_id
                      << " sent_bytes=" << cur.sent_bytes;
    clusters_.pop();
    if (clusters_.empty()) {
      probing_state_ = ProbingState::kInactive;
      next_probe_time_ = Timestamp::PlusInfinity();
    } else {
      next_probe_time_ = now;
    }
  }
}

void BitrateProber::PauseUntilIncomingPacket() {
  if (probing_state_ != ProbingState::kActive) {
    return;
  }
  while (!clusters_.empty() && clusters_.front().sent_probes > 0) {
    clusters_.pop();
  }
  probing_state_ = ProbingState::kInactive;
  next_probe_time_ = Timestamp::PlusInfinity();
}

// ======================= RoundRobinPacketQueue 优先级轮询发包队列 =======================

RoundRobinPacketQueue::Stream::Stream() : packet_queue(&CompareQueuedPacket) {}

RoundRobinPacketQueue::RoundRobinPacketQueue(Timestamp start_time)
    : time_last_updated_(start_time) {}

void RoundRobinPacketQueue::Push(RtpPacketMediaType type,
                                 Timestamp enqueue_time,
                                 std::unique_ptr<RtpPacket> packet) {
  UpdateQueueTime(enqueue_time);
  const uint32_t ssrc = packet->ssrc();
  const DataSize pkt_size = DataSize::Bytes(packet->SerializedSize());

  Stream& stream = streams_[ssrc];
  stream.ssrc = ssrc;
  if (stream.packet_queue.empty()) {
    stream.size = std::max(stream.size, max_size_);
  }

  QueuedPacket qp;
  qp.type = type;
  qp.enqueue_time = enqueue_time;
  qp.enqueue_order = enqueue_count_++;
  qp.packet = std::move(packet);

  const bool was_empty = stream.packet_queue.empty();
  const RtpPacketMediaType prev_top_prio =
      was_empty ? RtpPacketMediaType::kPadding : stream.packet_queue.top().type;

  stream.packet_queue.push(std::move(qp));
  enqueue_times_.insert(enqueue_time);
  ++size_packets_;
  size_data_ += pkt_size;

  if (was_empty || static_cast<int>(type) < static_cast<int>(prev_top_prio)) {
    stream_priorities_.push(
        StreamPrioKey{stream.packet_queue.top().type, stream.size, ssrc});
    stream.in_prio_queue = true;
  }
}

RoundRobinPacketQueue::QueuedPacket RoundRobinPacketQueue::Pop() {
  while (!stream_priorities_.empty()) {
    const StreamPrioKey top_key = stream_priorities_.top();
    stream_priorities_.pop();

    const auto it = streams_.find(top_key.ssrc);
    if (it == streams_.end() || it->second.packet_queue.empty()) {
      continue;
    }
    Stream& stream = it->second;
    if (stream.packet_queue.top().type != top_key.priority ||
        stream.size != top_key.accumulated_size) {
      continue;
    }

    QueuedPacket qp =
        std::move(const_cast<QueuedPacket&>(stream.packet_queue.top()));
    stream.packet_queue.pop();
    const auto ts_it = enqueue_times_.find(qp.enqueue_time);
    if (ts_it != enqueue_times_.end()) {
      enqueue_times_.erase(ts_it);
    }

    const DataSize pkt_size = DataSize::Bytes(qp.packet->SerializedSize());
    const TimeDelta time_in_queue =
        std::max(TimeDelta::Zero(), time_last_updated_ - qp.enqueue_time);
    queue_time_sum_ = std::max(TimeDelta::Zero(), queue_time_sum_ - time_in_queue);

    stream.size += pkt_size;
    max_size_ = std::max(max_size_, stream.size);
    size_data_ -= pkt_size;
    --size_packets_;

    if (!stream.packet_queue.empty()) {
      stream_priorities_.push(StreamPrioKey{stream.packet_queue.top().type,
                                            stream.size, stream.ssrc});
    } else {
      stream.in_prio_queue = false;
    }
    return qp;
  }
  return QueuedPacket{};
}

Timestamp RoundRobinPacketQueue::OldestEnqueueTime() const {
  if (enqueue_times_.empty()) {
    return Timestamp::PlusInfinity();
  }
  return *enqueue_times_.begin();
}

void RoundRobinPacketQueue::UpdateQueueTime(Timestamp now) {
  if (now <= time_last_updated_) {
    return;
  }
  const TimeDelta delta = now - time_last_updated_;
  queue_time_sum_ += delta * static_cast<int64_t>(size_packets_);
  time_last_updated_ = now;
}

TimeDelta RoundRobinPacketQueue::AverageQueueTime() const {
  if (size_packets_ == 0) {
    return TimeDelta::Zero();
  }
  return queue_time_sum_ / static_cast<int64_t>(size_packets_);
}

void RoundRobinPacketQueue::Clear(Timestamp now) {
  streams_.clear();
  enqueue_times_.clear();
  while (!stream_priorities_.empty()) {
    stream_priorities_.pop();
  }
  size_packets_ = 0;
  size_data_ = DataSize::Zero();
  max_size_ = DataSize::Zero();
  queue_time_sum_ = TimeDelta::Zero();
  time_last_updated_ = now;
}

void RoundRobinPacketQueue::PurgeStalePacketsForKeyframe(
    Timestamp now,
    uint32_t keyframe_ssrc,
    uint32_t keyframe_rtp_ts) {
  UpdateQueueTime(now);
  enqueue_times_.clear();
  while (!stream_priorities_.empty()) {
    stream_priorities_.pop();
  }
  size_packets_ = 0;
  size_data_ = DataSize::Zero();
  queue_time_sum_ = TimeDelta::Zero();

  for (auto it = streams_.begin(); it != streams_.end();) {
    Stream& stream = it->second;
    std::vector<QueuedPacket> kept;
    while (!stream.packet_queue.empty()) {
      QueuedPacket qp =
          std::move(const_cast<QueuedPacket&>(stream.packet_queue.top()));
      stream.packet_queue.pop();
      const bool same_keyframe = (qp.packet != nullptr &&
                                  qp.packet->ssrc() == keyframe_ssrc &&
                                  qp.packet->timestamp() == keyframe_rtp_ts);
      const bool recent =
          (now - qp.enqueue_time) <= TimeDelta::Millis(5);
      const bool high_prio_ctrl =
          (qp.type == RtpPacketMediaType::kControlHighPriority);
      if (same_keyframe || recent || high_prio_ctrl) {
        kept.push_back(std::move(qp));
      }
    }
    if (kept.empty()) {
      it = streams_.erase(it);
      continue;
    }
    for (auto& qp : kept) {
      const DataSize pkt_size = DataSize::Bytes(qp.packet->SerializedSize());
      enqueue_times_.insert(qp.enqueue_time);
      queue_time_sum_ += std::max(TimeDelta::Zero(), now - qp.enqueue_time);
      ++size_packets_;
      size_data_ += pkt_size;
      stream.packet_queue.push(std::move(qp));
    }
    stream_priorities_.push(
        StreamPrioKey{stream.packet_queue.top().type, stream.size, stream.ssrc});
    stream.in_prio_queue = true;
    ++it;
  }
  if (size_packets_ == 0) {
    max_size_ = DataSize::Zero();
  }
}

// ======================= PacingController 平滑发送控制器 =======================

PacingController::PacingController(Clock* clock,
                                   PacingPacketSender* packet_sender)
    : clock_(clock),
      packet_sender_(packet_sender),
      last_process_time_(clock->CurrentTime()),
      packet_queue_(last_process_time_) {}

void PacingController::CreateProbeClusters(
    const std::vector<ProbeClusterConfig>& probe_cluster_configs) {
  for (const auto& cfg : probe_cluster_configs) {
    prober_.CreateProbeCluster(cfg);
  }
}

void PacingController::SetPacingRates(DataRate pacing_rate,
                                      DataRate padding_rate) {
  constexpr DataRate kMinPacingRate = DataRate::KilobitsPerSec(50);
  constexpr DataRate kMaxPacingRate = DataRate::KilobitsPerSec(1'000'000);
  pacing_rate_ = std::clamp(
      pacing_rate.IsFinite() ? pacing_rate : kMaxPacingRate, kMinPacingRate,
      kMaxPacingRate);
  padding_rate_ = std::clamp(
      padding_rate.IsFinite() ? padding_rate : kMaxPacingRate,
      DataRate::Zero(), kMaxPacingRate);
  adjusted_media_rate_ = pacing_rate_;

  const int64_t max_media_debt =
      (adjusted_media_rate_ * TimeDelta::Millis(500)).bytes();
  media_debt_bytes_ =
      std::clamp<int64_t>(media_debt_bytes_, -max_media_debt, max_media_debt);
  const DataSize max_pad_debt = padding_rate_ * TimeDelta::Millis(500);
  if (padding_debt_ > max_pad_debt) {
    padding_debt_ = max_pad_debt;
  }
}

void PacingController::SetCongestionWindow(DataSize congestion_window_size) {
  congestion_window_size_ = congestion_window_size;
}

void PacingController::UpdateOutstandingData(DataSize outstanding_data) {
  outstanding_data_ = outstanding_data;
}

bool PacingController::Congested() const {
  return congestion_window_size_.IsFinite() &&
         outstanding_data_ >= congestion_window_size_;
}

TimeDelta PacingController::ExpectedQueueTime() const {
  if (adjusted_media_rate_.bps() <= 0) {
    return TimeDelta::Zero();
  }
  return packet_queue_.SizeData() / adjusted_media_rate_;
}

void PacingController::EnqueuePacket(std::unique_ptr<RtpPacket> packet,
                                     RtpPacketMediaType type) {
  const Timestamp now = clock_->CurrentTime();
  // 拥塞期间若平滑发包队列排队时延已超过 150ms，抑制旧报文 RTX 重传，避免重传风暴挤占实时关键帧带宽。
  if (type == RtpPacketMediaType::kRetransmission &&
      ExpectedQueueTime() > TimeDelta::Millis(150)) {
    return;
  }
  // 当全新的关键帧（IDR）入队且发包队列中积压了超过 180ms 的旧 GOP 报文时，
  // 直接清空已失效的旧 P 帧与 RTX 重传积压，使新关键帧能够零排队延迟立即发出。
  if (type == RtpPacketMediaType::kVideoKeyFrame && !packet_queue_.Empty() &&
      ExpectedQueueTime() > TimeDelta::Millis(180) &&
      (now - packet_queue_.OldestEnqueueTime()) > TimeDelta::Millis(80)) {
    // 仅淘汰早于当前关键帧的陈旧 GOP 积压报文，严禁误删当前正在批量入队的同一关键帧前序分片。
    packet_queue_.PurgeStalePacketsForKeyframe(now, packet->ssrc(),
                                               packet->timestamp());
  }
  if (packet_queue_.Empty() && media_debt_bytes_ <= 0 &&
      last_process_time_ < now) {
    // 当发送债务为零时，防止空闲帧间隔期间残留过期的时间戳。
    media_debt_bytes_ = 0;
    media_debt_subbyte_rem_ = 0;
    last_process_time_ = now;
  }
  prober_.OnIncomingPacket(DataSize::Bytes(packet->SerializedSize()));
  packet_queue_.Push(type, now, std::move(packet));
}

Timestamp PacingController::NextSendTime() const {
  const Timestamp now = clock_->CurrentTime();
  if (prober_.is_probing()) {
    const Timestamp probe_time = prober_.NextProbeTime(now);
    if (!probe_time.IsPlusInfinity()) {
      return probe_time;
    }
  }
  if (Congested()) {
    return packet_queue_.Empty() ? Timestamp::PlusInfinity()
                                 : (last_process_time_ + TimeDelta::Millis(5));
  }
  if (!packet_queue_.Empty()) {
    if (media_debt_bytes_ <= 0) {
      return now;
    }
    const int64_t rate_bps = std::max<int64_t>(1, adjusted_media_rate_.bps());
    const int64_t remaining_bit_us = std::max<int64_t>(
        0, media_debt_bytes_ * 8'000'000 - media_debt_subbyte_rem_);
    const int64_t wait_us = (remaining_bit_us + rate_bps - 1) / rate_bps;
    return last_process_time_ + TimeDelta::Micros(wait_us);
  }
  if (padding_rate_ > DataRate::Zero()) {
    if (padding_debt_ == DataSize::Zero()) {
      return now;
    }
    const int64_t pad_bps = std::max<int64_t>(1, padding_rate_.bps());
    const int64_t remaining_bit_us =
        std::max<int64_t>(0, padding_debt_.bytes() * 8'000'000 -
                                 padding_debt_subbyte_rem_);
    const int64_t wait_us = (remaining_bit_us + pad_bps - 1) / pad_bps;
    return last_process_time_ + TimeDelta::Micros(wait_us);
  }
  return Timestamp::PlusInfinity();
}

TimeDelta PacingController::UpdateTimeAndGetElapsed(Timestamp now) {
  if (now < last_process_time_) {
    return TimeDelta::Zero();
  }
  const TimeDelta elapsed = now - last_process_time_;
  last_process_time_ = now;
  return std::min(elapsed, kMaxElapsedTime);
}

void PacingController::UpdateBudgetWithElapsedTime(TimeDelta delta) {
  const int64_t delta_us =
      std::clamp<int64_t>(delta.us(), 0, kMaxElapsedTime.us());
  if (delta_us <= 0) {
    return;
  }

  if (adjusted_media_rate_.bps() > 0 &&
      (media_debt_bytes_ > 0 || !packet_queue_.Empty())) {
    const int64_t total_bit_us =
        adjusted_media_rate_.bps() * delta_us + media_debt_subbyte_rem_;
    const int64_t paid_bytes = total_bit_us / 8'000'000;
    media_debt_subbyte_rem_ = total_bit_us % 8'000'000;
    media_debt_bytes_ -= paid_bytes;

    if (packet_queue_.Empty()) {
      if (media_debt_bytes_ < 0) {
        media_debt_bytes_ = 0;
        media_debt_subbyte_rem_ = 0;
      }
    } else {
      // 将操作系统定时器唤醒抖动信用上限约束在 5ms 以内（空闲状态下绝不突发积攒）。
      const int64_t max_jitter_credit = std::max<int64_t>(
          1200, (adjusted_media_rate_ * TimeDelta::Millis(5)).bytes());
      if (media_debt_bytes_ < -max_jitter_credit) {
        media_debt_bytes_ = -max_jitter_credit;
        media_debt_subbyte_rem_ = 0;
      }
    }
  }

  if (padding_debt_ > DataSize::Zero() && padding_rate_.bps() > 0) {
    const int64_t total_bit_us =
        padding_rate_.bps() * delta_us + padding_debt_subbyte_rem_;
    const int64_t paid_bytes = total_bit_us / 8'000'000;
    padding_debt_subbyte_rem_ = total_bit_us % 8'000'000;
    if (paid_bytes >= padding_debt_.bytes()) {
      padding_debt_ = DataSize::Zero();
      padding_debt_subbyte_rem_ = 0;
    } else {
      padding_debt_ = DataSize::Bytes(padding_debt_.bytes() - paid_bytes);
    }
  }
}

void PacingController::UpdateBudgetWithSentData(DataSize size) {
  last_send_time_ = clock_->CurrentTime();
  outstanding_data_ += size;
  const int64_t max_media_debt =
      (adjusted_media_rate_ * TimeDelta::Millis(500)).bytes();
  media_debt_bytes_ = std::min(media_debt_bytes_ + size.bytes(), max_media_debt);
  if (padding_rate_ > DataRate::Zero()) {
    const DataSize max_pad_debt = padding_rate_ * TimeDelta::Millis(500);
    padding_debt_ = std::min(padding_debt_ + size, max_pad_debt);
  }
}

void PacingController::ProcessPackets() {
  const Timestamp now = clock_->CurrentTime();
  const TimeDelta elapsed = UpdateTimeAndGetElapsed(now);
  packet_queue_.UpdateQueueTime(now);

  if (drain_large_queues_ && !packet_queue_.Empty()) {
    const TimeDelta avg_wait = packet_queue_.AverageQueueTime();
    const TimeDelta remaining_limit =
        std::max(TimeDelta::Millis(50), queue_time_limit_ - avg_wait);
    const DataRate min_rate_needed = packet_queue_.SizeData() / remaining_limit;
    // 严格限制排空加速倍率为 pacing_rate_ 的 1.35 倍以内，杜绝突发线速洪泛冲垮路由器浅队列。
    adjusted_media_rate_ =
        std::min(pacing_rate_ * 1.35, std::max(pacing_rate_, min_rate_needed));
  } else {
    adjusted_media_rate_ = pacing_rate_;
  }

  if (elapsed > TimeDelta::Zero()) {
    UpdateBudgetWithElapsedTime(elapsed);
  }

  PacedPacketInfo pacing_info;
  DataSize data_sent = DataSize::Zero();

  while (true) {
    const bool is_probing = prober_.is_probing();
    if (is_probing) {
      if (prober_.NextProbeTime(now) > now + kMaxEarlyProbeProcessing) {
        break;
      }
      pacing_info = prober_.CurrentCluster(now).value_or(PacedPacketInfo{});
    } else {
      pacing_info = PacedPacketInfo{};
    }

    std::unique_ptr<RtpPacket> pkt = GetPendingPacket(pacing_info);
    if (!pkt) {
      DataSize padding_to_add = DataSize::Zero();
      if (is_probing &&
          data_sent < DataSize::Bytes(prober_.RecommendedMinProbeSize())) {
        padding_to_add =
            DataSize::Bytes(prober_.RecommendedMinProbeSize()) - data_sent;
      } else if (packet_queue_.Empty() && !Congested() &&
                 padding_rate_ > DataRate::Zero() &&
                 padding_debt_ == DataSize::Zero()) {
        padding_to_add = DataSize::Bytes(224);
      }

      if (padding_to_add > DataSize::Zero()) {
        auto pad_pkts = packet_sender_->GeneratePadding(padding_to_add);
        if (pad_pkts.empty()) {
          if (is_probing && data_sent == DataSize::Zero()) {
            // 当前无法生成填充包且发包队列为空，挂起探测等待真实媒体包到达，杜绝 1ms 定时器空转。
            prober_.PauseUntilIncomingPacket();
          } else if (!is_probing && padding_rate_ > DataRate::Zero()) {
            padding_debt_ = std::max(DataSize::Bytes(32),
                                     padding_rate_ * TimeDelta::Millis(50));
          }
          break;
        }
        DataSize pad_batch = DataSize::Zero();
        for (auto& pad : pad_pkts) {
          const DataSize sz = DataSize::Bytes(pad->SerializedSize());
          packet_sender_->SendPacedPacket(std::move(pad), pacing_info);
          data_sent += sz;
          pad_batch += sz;
          UpdateBudgetWithSentData(sz);
        }
        if (is_probing && pad_batch > DataSize::Zero()) {
          prober_.ProbeSent(now, pad_batch);
        }
        continue;
      }
      break;
    }

    const DataSize pkt_size = DataSize::Bytes(pkt->SerializedSize());
    packet_sender_->SendPacedPacket(std::move(pkt), pacing_info);
    data_sent += pkt_size;
    UpdateBudgetWithSentData(pkt_size);
    if (is_probing) {
      prober_.ProbeSent(now, pkt_size);
    }
  }
  if (packet_queue_.Empty() && media_debt_bytes_ < 0) {
    media_debt_bytes_ = 0;
    media_debt_subbyte_rem_ = 0;
  }
}

std::unique_ptr<RtpPacket> PacingController::GetPendingPacket(
    const PacedPacketInfo& pacing_info) {
  if (packet_queue_.Empty()) {
    return nullptr;
  }
  const bool is_probe =
      (pacing_info.probe_cluster_id != PacedPacketInfo::kNotAProbe);
  if (!is_probe) {
    if (media_debt_bytes_ > 0) {
      return nullptr;
    }
    // 当处于拥塞窗口受限但连续 60ms 未发出任何报文时，放行单包触发接收端返回最新 TWCC 反馈，防止窗口尾部丢包死锁。
    const bool cwnd_keepalive_due =
        last_send_time_.IsFinite() &&
        (clock_->CurrentTime() - last_send_time_) >= TimeDelta::Millis(60);
    if (Congested() && !cwnd_keepalive_due) {
      return nullptr;
    }
  }
  auto popped = packet_queue_.Pop();
  return std::move(popped.packet);
}

// ======================= TaskQueuePacedSender 任务队列平滑发送器 =======================

TaskQueuePacedSender::TaskQueuePacedSender(Clock* clock,
                                           PacingPacketSender* packet_sender,
                                           TaskQueueBoost* pacer_queue)
    : clock_(clock),
      pacer_queue_(pacer_queue),
      pacer_checker_(pacer_queue),
      pacing_controller_(clock, packet_sender),
      process_timer_(pacer_queue->io_context()),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {}

TaskQueuePacedSender::~TaskQueuePacedSender() {
  pacer_queue_->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&pacer_checker_);
    safety_.flag()->SetNotAlive();
    boost::system::error_code ec;
    process_timer_.cancel(ec);
  });
}

void TaskQueuePacedSender::EnsureStarted() {
  pacer_queue_->PostTask(SafeTask(safety_.flag(), [this]() {
    RTC_DCHECK_RUN_ON(&pacer_checker_);
    MaybeProcessPackets(Timestamp::MinusInfinity());
  }));
}

void TaskQueuePacedSender::SetPacingRates(DataRate pacing_rate,
                                          DataRate padding_rate) {
  pacer_queue_->PostTask(
      SafeTask(safety_.flag(), [this, pacing_rate, padding_rate]() {
        RTC_DCHECK_RUN_ON(&pacer_checker_);
        pacing_controller_.SetPacingRates(pacing_rate, padding_rate);
        MaybeProcessPackets(Timestamp::MinusInfinity());
      }));
}

void TaskQueuePacedSender::CreateProbeClusters(
    std::vector<ProbeClusterConfig> clusters) {
  pacer_queue_->PostTask(
      SafeTask(safety_.flag(), [this, clusters = std::move(clusters)]() {
        RTC_DCHECK_RUN_ON(&pacer_checker_);
        pacing_controller_.CreateProbeClusters(clusters);
        MaybeProcessPackets(Timestamp::MinusInfinity());
      }));
}

void TaskQueuePacedSender::SetCongestionWindow(DataSize cwnd) {
  pacer_queue_->PostTask(SafeTask(safety_.flag(), [this, cwnd]() {
    RTC_DCHECK_RUN_ON(&pacer_checker_);
    pacing_controller_.SetCongestionWindow(cwnd);
    MaybeProcessPackets(Timestamp::MinusInfinity());
  }));
}

void TaskQueuePacedSender::UpdateOutstandingData(DataSize in_flight) {
  pacer_queue_->PostTask(SafeTask(safety_.flag(), [this, in_flight]() {
    RTC_DCHECK_RUN_ON(&pacer_checker_);
    pacing_controller_.UpdateOutstandingData(in_flight);
    MaybeProcessPackets(Timestamp::MinusInfinity());
  }));
}

void TaskQueuePacedSender::EnqueuePackets(
    std::vector<std::pair<RtpPacketMediaType, std::unique_ptr<RtpPacket>>>
        packets) {
  pacer_queue_->PostTask(
      SafeTask(safety_.flag(), [this, pkts = std::move(packets)]() mutable {
        RTC_DCHECK_RUN_ON(&pacer_checker_);
        for (auto& item : pkts) {
          if (item.second) {
            pacing_controller_.EnqueuePacket(std::move(item.second),
                                             item.first);
          }
        }
        MaybeProcessPackets(Timestamp::MinusInfinity());
      }));
}

void TaskQueuePacedSender::MaybeProcessPackets(
    Timestamp scheduled_process_time) {
  RTC_DCHECK_RUN_ON(&pacer_checker_);
  if (scheduled_process_time.IsFinite() &&
      scheduled_process_time != next_process_time_) {
    return;
  }

  const Timestamp now = clock_->CurrentTime();
  Timestamp next_send_time = pacing_controller_.NextSendTime();
  int stall_guard = 0;
  while (next_send_time <= now + PacingController::kMinSleepTime / 2) {
    pacing_controller_.ProcessPackets();
    const Timestamp updated_next = pacing_controller_.NextSendTime();
    if (updated_next <= next_send_time && ++stall_guard >= 4) {
      next_send_time = now + PacingController::kMinSleepTime;
      break;
    }
    next_send_time = updated_next;
  }

  if (next_send_time.IsPlusInfinity()) {
    if (next_process_time_.IsFinite()) {
      boost::system::error_code ec;
      process_timer_.cancel(ec);
    }
    next_process_time_ = Timestamp::MinusInfinity();
    return;
  }
  const TimeDelta delay =
      std::max(PacingController::kMinSleepTime, next_send_time - now);
  const Timestamp target_wakeup = now + delay;
  if (next_process_time_.IsMinusInfinity() ||
      target_wakeup < next_process_time_ || scheduled_process_time.IsFinite()) {
    next_process_time_ = target_wakeup;
    boost::system::error_code ec;
    process_timer_.cancel(ec);
    process_timer_.expires_after(std::chrono::microseconds(delay.us()));
    auto flag = safety_.flag();
    TaskQueueBoost* pq = pacer_queue_;
    process_timer_.async_wait(
        [this, flag = std::move(flag), pq,
         target_wakeup](const boost::system::error_code& wait_ec) {
          if (wait_ec || !flag->alive() || pq->IsStopped()) {
            return;
          }
          pq->PostTask(SafeTask(flag, [this, target_wakeup]() {
            MaybeProcessPackets(target_wakeup);
          }));
        });
  }
}

}  // namespace rtc
