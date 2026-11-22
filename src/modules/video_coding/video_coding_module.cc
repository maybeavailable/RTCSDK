#include "modules/video_coding/video_coding_module.h"

#include <algorithm>
#include <cmath>
#include <iterator>

#include "rtc_base/logging.h"

namespace rtc {

namespace {
bool SeqNumLess(uint16_t a, uint16_t b) {
  return a != b && AheadOf<uint16_t>(b, a);
}
}  // namespace

// ======================= 1. PacketBuffer 视频包重组缓冲区 =======================

PacketBuffer::PacketBuffer(VideoCodec codec, size_t start_size, size_t max_size)
    : codec_(codec),
      max_size_(std::max(start_size, max_size)),
      buffer_(start_size) {}

void PacketBuffer::Clear() {
  for (auto& s : buffer_) {
    s = Slot{};
  }
  first_packet_received_ = false;
}

void PacketBuffer::ClearTo(uint16_t seq_num) {
  if (!first_packet_received_) {
    return;
  }
  while (AheadOrAt<uint16_t>(seq_num, first_seq_num_)) {
    const size_t idx = first_seq_num_ % buffer_.size();
    if (buffer_[idx].used && buffer_[idx].seq_num == first_seq_num_) {
      buffer_[idx] = Slot{};
    }
    ++first_seq_num_;
    if (first_seq_num_ == static_cast<uint16_t>(seq_num + 1)) {
      break;
    }
  }
}

void PacketBuffer::ExpandBufferSize() {
  if (buffer_.size() >= max_size_) {
    RTC_LOG(kWarning) << "PacketBuffer reached max_size=" << max_size_
                      << ", flushing stale slots";
    Clear();
    return;
  }
  const size_t new_size = std::min(max_size_, buffer_.size() * 2);
  RTC_LOG(kInfo) << "PacketBuffer expanding from " << buffer_.size() << " to "
                 << new_size << " slots";
  std::vector<Slot> new_buf(new_size);
  for (auto& s : buffer_) {
    if (s.used) {
      new_buf[s.seq_num % new_size] = std::move(s);
    }
  }
  buffer_ = std::move(new_buf);
}

std::vector<AssembledRtpFrame> PacketBuffer::InsertPacket(
    const RtpPacket& packet,
    Timestamp receive_time) {
  std::optional<DepacketizedUnit> depkt =
      (codec_ == VideoCodec::kH264)
          ? H264Depacketizer::ParsePayload(packet.payload())
          : H265Depacketizer::ParsePayload(packet.payload());
  if (!depkt.has_value()) {
    return {};
  }

  const uint16_t seq = packet.sequence_number();
  if (!first_packet_received_) {
    first_seq_num_ = seq;
    first_packet_received_ = true;
  } else if (AheadOf<uint16_t>(first_seq_num_, seq)) {
    return {};
  } else if (static_cast<uint16_t>(seq - first_seq_num_) >=
             buffer_.size() / 2) {
    ClearTo(static_cast<uint16_t>(seq - buffer_.size() / 4));
  }

  size_t idx = seq % buffer_.size();
  if (buffer_[idx].used) {
    if (buffer_[idx].seq_num == seq) {
      return {};
    }
    ExpandBufferSize();
    idx = seq % buffer_.size();
    if (buffer_[idx].used) {
      Clear();
      first_seq_num_ = seq;
      first_packet_received_ = true;
      idx = seq % buffer_.size();
    }
  }

  Slot slot;
  slot.used = true;
  slot.seq_num = seq;
  slot.rtp_ts = packet.timestamp();
  slot.is_first_in_frame =
      packet.dependency_descriptor().has_value()
          ? packet.dependency_descriptor()->is_first_in_frame
          : depkt->is_first_in_frame;
  if (!packet.dependency_descriptor().has_value() && depkt->is_first_in_frame) {
    const uint16_t prev_seq = static_cast<uint16_t>(seq - 1);
    const Slot& prev = buffer_[prev_seq % buffer_.size()];
    if (prev.used && prev.seq_num == prev_seq &&
        prev.rtp_ts == packet.timestamp() && !prev.is_last_in_frame) {
      slot.is_first_in_frame = false;
    }
  }
  slot.is_last_in_frame = packet.marker();
  slot.is_keyframe = packet.dependency_descriptor().has_value()
                         ? packet.dependency_descriptor()->is_keyframe
                         : depkt->is_keyframe;
  slot.receive_time = receive_time;
  slot.playout_delay = packet.playout_delay();
  slot.dep_ext = packet.dependency_descriptor();
  slot.annexb_chunk = std::move(depkt->annexb_bytes);

  buffer_[idx] = std::move(slot);
  return FindFrames(seq);
}

bool PacketBuffer::PotentialNewFrame(uint16_t seq_num) const {
  const size_t index = seq_num % buffer_.size();
  const Slot& cur = buffer_[index];
  if (!cur.used || cur.seq_num != seq_num) {
    return false;
  }
  if (cur.is_first_in_frame) {
    return true;
  }

  const uint16_t prev_seq = static_cast<uint16_t>(seq_num - 1);
  const size_t prev_index = prev_seq % buffer_.size();
  const Slot& prev = buffer_[prev_index];
  if (!prev.used || prev.seq_num != prev_seq) {
    return false;
  }
  if (prev.rtp_ts != cur.rtp_ts) {
    return false;
  }
  return prev.continuous;
}

std::vector<AssembledRtpFrame> PacketBuffer::FindFrames(uint16_t seq_num) {
  std::vector<AssembledRtpFrame> found_frames;
  for (size_t i = 0; i < buffer_.size() && PotentialNewFrame(seq_num); ++i) {
    const size_t index = seq_num % buffer_.size();
    buffer_[index].continuous = true;

    if (buffer_[index].is_last_in_frame) {
      uint16_t start_seq = seq_num;
      Timestamp max_recv_time = buffer_[index].receive_time;
      bool frame_is_key = false;
      size_t total_bytes = 0;

      while (true) {
        const Slot& s = buffer_[start_seq % buffer_.size()];
        total_bytes += s.annexb_chunk.size();
        if (s.receive_time > max_recv_time) {
          max_recv_time = s.receive_time;
        }
        if (s.is_keyframe) {
          frame_is_key = true;
        }
        if (s.is_first_in_frame) {
          break;
        }
        --start_seq;
      }

      AssembledRtpFrame frame;
      frame.first_seq_num = start_seq;
      frame.last_seq_num = seq_num;
      frame.rtp_timestamp = buffer_[index].rtp_ts;
      frame.received_time = max_recv_time;
      frame.codec = codec_;
      frame.is_keyframe = frame_is_key;
      frame.playout_delay = buffer_[start_seq % buffer_.size()].playout_delay;
      frame.dependency_ext = buffer_[start_seq % buffer_.size()].dep_ext;
      frame.annexb_bitstream.reserve(total_bytes);

      for (uint16_t s_num = start_seq;; ++s_num) {
        Slot& s = buffer_[s_num % buffer_.size()];
        frame.annexb_bitstream.insert(frame.annexb_bitstream.end(),
                                      s.annexb_chunk.begin(),
                                      s.annexb_chunk.end());
        s = Slot{};
        if (s_num == seq_num) {
          break;
        }
      }
      if (start_seq == first_seq_num_) {
        first_seq_num_ = static_cast<uint16_t>(seq_num + 1);
      }
      found_frames.push_back(std::move(frame));
    }
    ++seq_num;
  }
  return found_frames;
}

// ======================= 2. NackModule2 丢包重传控制模块 =======================

NackModule2::NackModule2()
    : nack_list_(&SeqNumLess), reordering_histogram_(64, 0) {}

void NackModule2::UpdateRtt(TimeDelta rtt) {
  if (rtt > TimeDelta::Zero()) {
    rtt_ = std::clamp(rtt, TimeDelta::Millis(10), TimeDelta::Millis(1000));
  }
}

void NackModule2::RecordReorderingDistance(uint16_t distance) {
  const size_t bucket =
      std::min<size_t>(distance, reordering_histogram_.size() - 1);
  if (total_reordered_samples_ >= 200) {
    for (int& v : reordering_histogram_) {
      v = (v * 3) / 4;
    }
    total_reordered_samples_ = 0;
    for (int v : reordering_histogram_) {
      total_reordered_samples_ += static_cast<size_t>(v);
    }
  }
  ++reordering_histogram_[bucket];
  ++total_reordered_samples_;
}

uint16_t NackModule2::WaitNumberOfPackets(double probability) const {
  if (total_reordered_samples_ < 10) {
    return 0;
  }
  size_t acc = 0;
  for (size_t i = 0; i < reordering_histogram_.size(); ++i) {
    acc += static_cast<size_t>(reordering_histogram_[i]);
    if (static_cast<double>(acc) >=
        probability * static_cast<double>(total_reordered_samples_)) {
      return static_cast<uint16_t>(i);
    }
  }
  return 0;
}

std::vector<uint16_t> NackModule2::OnReceivedPacket(
    uint16_t seq_num,
    bool is_keyframe,
    bool is_recovered,
    Timestamp now,
    bool* out_keyframe_requested) {
  if (out_keyframe_requested != nullptr) {
    *out_keyframe_requested = false;
  }
  if (!initialized_) {
    initialized_ = true;
    newest_seq_num_ = seq_num;
    if (is_keyframe) {
      keyframe_list_.push_back(seq_num);
    }
    return {};
  }
  if (seq_num == newest_seq_num_) {
    return {};
  }

  if (AheadOf<uint16_t>(newest_seq_num_, seq_num)) {
    const auto it = nack_list_.find(seq_num);
    if (it != nack_list_.end()) {
      if (!is_recovered && it->second.retries == 0) {
        RecordReorderingDistance(
            static_cast<uint16_t>(newest_seq_num_ - seq_num));
      }
      nack_list_.erase(it);
    }
    return {};
  }

  if (is_keyframe) {
    keyframe_list_.push_back(seq_num);
    while (keyframe_list_.size() > 64) {
      keyframe_list_.pop_front();
    }
  }

  const uint16_t wait_packets = WaitNumberOfPackets(0.5);
  for (uint16_t missing = static_cast<uint16_t>(newest_seq_num_ + 1);
       missing != seq_num; ++missing) {
    NackInfo info;
    info.seq_num = missing;
    info.send_at_seq_num =
        static_cast<uint16_t>(missing + wait_packets + 1);
    info.created_time = now;
    nack_list_[missing] = info;
  }
  newest_seq_num_ = seq_num;

  if (nack_list_.size() > kMaxNackPackets) {
    while (nack_list_.size() > kMaxNackPackets && !keyframe_list_.empty()) {
      const uint16_t kf_seq = keyframe_list_.front();
      keyframe_list_.pop_front();
      ClearUpTo(kf_seq);
    }
    if (nack_list_.size() > kMaxNackPackets) {
      RTC_LOG(kWarning)
          << "NackModule2 list overflow (" << nack_list_.size()
          << " packets), clearing and requesting IDR recovery";
      nack_list_.clear();
      if (out_keyframe_requested != nullptr) {
        *out_keyframe_requested = true;
      }
      return {};
    }
  }

  std::vector<uint16_t> immediate_nacks;
  for (auto& [seq, info] : nack_list_) {
    (void)seq;
    if (info.sent_time.IsMinusInfinity() &&
        AheadOrAt<uint16_t>(newest_seq_num_, info.send_at_seq_num)) {
      info.sent_time = now;
      info.retries = 1;
      immediate_nacks.push_back(info.seq_num);
    }
  }
  return immediate_nacks;
}

std::vector<uint16_t> NackModule2::ProcessNacks(Timestamp now,
                                                bool* out_keyframe_requested) {
  if (out_keyframe_requested != nullptr) {
    *out_keyframe_requested = false;
  }
  std::vector<uint16_t> retry_batch;

  for (auto it = nack_list_.begin(); it != nack_list_.end();) {
    NackInfo& info = it->second;
    if (info.retries >= kMaxNackRetries) {
      RTC_LOG(kWarning) << "Packet seq=" << info.seq_num
                        << " exceeded kMaxNackRetries=" << kMaxNackRetries
                        << ", escalating to PLI keyframe request";
      it = nack_list_.erase(it);
      if (out_keyframe_requested != nullptr) {
        *out_keyframe_requested = true;
      }
      continue;
    }
    if (info.sent_time.IsMinusInfinity() || (now - info.sent_time) >= rtt_) {
      info.sent_time = now;
      ++info.retries;
      retry_batch.push_back(info.seq_num);
    }
    ++it;
  }
  return retry_batch;
}

void NackModule2::ClearUpTo(uint16_t seq_num) {
  while (!nack_list_.empty() &&
         SeqNumLess(nack_list_.begin()->first, seq_num)) {
    nack_list_.erase(nack_list_.begin());
  }
}

// ======================= 3. RtpFrameReferenceFinder 帧参考关系解析器 =======================

std::vector<AssembledRtpFrame> RtpFrameReferenceFinder::ManageFrame(
    AssembledRtpFrame frame) {
  std::vector<AssembledRtpFrame> ready;
  const Decision dec = ResolveFrame(&frame);
  if (dec == Decision::kDrop) {
    return ready;
  }
  if (dec == Decision::kStash) {
    stashed_frames_.push_back(std::move(frame));
    while (stashed_frames_.size() > 64) {
      stashed_frames_.pop_front();
    }
    return ready;
  }

  ready.push_back(std::move(frame));
  bool progress = true;
  while (progress && !stashed_frames_.empty()) {
    progress = false;
    for (auto it = stashed_frames_.begin(); it != stashed_frames_.end();) {
      const Decision d = ResolveFrame(&(*it));
      if (d == Decision::kHandOff) {
        ready.push_back(std::move(*it));
        it = stashed_frames_.erase(it);
        progress = true;
      } else if (d == Decision::kDrop) {
        it = stashed_frames_.erase(it);
      } else {
        ++it;
      }
    }
  }
  return ready;
}

RtpFrameReferenceFinder::Decision RtpFrameReferenceFinder::ResolveFrame(
    AssembledRtpFrame* frame) {
  if (frame->dependency_ext.has_value()) {
    const auto& ext = *frame->dependency_ext;
    const int64_t fid = frame_num_unwrapper_.Unwrap(ext.frame_number);
    frame->dep.frame_id = fid;
    frame->dep.picture_id = ext.frame_number;
    frame->dep.spatial_id = ext.spatial_id;
    frame->dep.temporal_id = ext.temporal_id;
    frame->dep.is_keyframe = ext.is_keyframe || frame->is_keyframe;
    frame->dep.discardable = ext.discardable;
    frame->dep.num_references = frame->dep.is_keyframe ? 0 : ext.num_fdiffs;
    for (uint8_t i = 0; i < frame->dep.num_references; ++i) {
      frame->dep.references[i] = fid - static_cast<int64_t>(ext.fdiffs[i]);
    }
    if (frame->dep.is_keyframe) {
      last_keyframe_id_ = fid;
    }
    return Decision::kHandOff;
  }

  if (frame->is_keyframe) {
    const int64_t fid = ++synthetic_frame_id_;
    frame->dep.frame_id = fid;
    frame->dep.is_keyframe = true;
    frame->dep.num_references = 0;
    last_keyframe_id_ = fid;
    last_base_layer_frame_id_ = fid;
    last_unwrapped_seq_end_ = frame->last_seq_num;
    return Decision::kHandOff;
  }

  if (!last_keyframe_id_.has_value() || !last_unwrapped_seq_end_.has_value()) {
    return Decision::kStash;
  }
  if (frame->first_seq_num ==
      static_cast<uint16_t>(*last_unwrapped_seq_end_ + 1)) {
    const int64_t fid = ++synthetic_frame_id_;
    frame->dep.frame_id = fid;
    frame->dep.is_keyframe = false;
    frame->dep.num_references = 1;
    frame->dep.references[0] = *last_base_layer_frame_id_;
    last_base_layer_frame_id_ = fid;
    last_unwrapped_seq_end_ = frame->last_seq_num;
    return Decision::kHandOff;
  }
  if (AheadOf<uint16_t>(*last_unwrapped_seq_end_, frame->last_seq_num)) {
    return Decision::kDrop;
  }
  return Decision::kStash;
}

void RtpFrameReferenceFinder::ClearTo(uint16_t /*seq_num*/) {
  stashed_frames_.clear();
}

// ======================= 4. DecodedFramesHistory 与 FrameBuffer3 帧缓冲区 =======================

DecodedFramesHistory::DecodedFramesHistory(size_t window_size)
    : window_size_(window_size), buffer_(window_size, false) {}

void DecodedFramesHistory::InsertDecoded(int64_t frame_id,
                                         uint32_t rtp_timestamp) {
  if (!last_frame_id_.has_value()) {
    std::fill(buffer_.begin(), buffer_.end(), false);
    buffer_[static_cast<size_t>(frame_id % static_cast<int64_t>(window_size_))] =
        true;
    last_frame_id_ = frame_id;
    last_decoded_timestamp_ = rtp_timestamp;
    return;
  }
  if (frame_id <= *last_frame_id_) {
    const int64_t back = *last_frame_id_ - frame_id;
    if (static_cast<size_t>(back) < window_size_) {
      buffer_[static_cast<size_t>(
          frame_id % static_cast<int64_t>(window_size_))] = true;
    }
    return;
  }
  const int64_t jump = frame_id - *last_frame_id_;
  if (static_cast<size_t>(jump) >= window_size_) {
    std::fill(buffer_.begin(), buffer_.end(), false);
  } else {
    for (int64_t id = *last_frame_id_ + 1; id < frame_id; ++id) {
      buffer_[static_cast<size_t>(id % static_cast<int64_t>(window_size_))] =
          false;
    }
  }
  buffer_[static_cast<size_t>(frame_id % static_cast<int64_t>(window_size_))] =
      true;
  last_frame_id_ = frame_id;
  last_decoded_timestamp_ = rtp_timestamp;
}

bool DecodedFramesHistory::WasDecoded(int64_t frame_id) const {
  if (!last_frame_id_.has_value() || frame_id > *last_frame_id_) {
    return false;
  }
  const int64_t back = *last_frame_id_ - frame_id;
  if (static_cast<size_t>(back) >= window_size_) {
    return false;
  }
  return buffer_[static_cast<size_t>(frame_id %
                                     static_cast<int64_t>(window_size_))];
}

void DecodedFramesHistory::Clear() {
  std::fill(buffer_.begin(), buffer_.end(), false);
  last_frame_id_.reset();
  last_decoded_timestamp_.reset();
}

FrameBuffer3::FrameBuffer3(size_t max_size)
    : max_size_(max_size), decoded_history_(1024) {}

void FrameBuffer3::InsertFrame(AssembledRtpFrame frame) {
  if (frame.dep.frame_id < 0 ||
      decoded_history_.WasDecoded(frame.dep.frame_id)) {
    return;
  }
  frames_[frame.dep.frame_id] = std::move(frame);
  while (frames_.size() > max_size_) {
    frames_.erase(frames_.begin());
  }
}

bool FrameBuffer3::AllReferencesDecoded(const AssembledRtpFrame& f) const {
  if (f.dep.is_keyframe || f.dep.num_references == 0) {
    return true;
  }
  for (size_t i = 0; i < f.dep.num_references; ++i) {
    if (!decoded_history_.WasDecoded(f.dep.references[i])) {
      return false;
    }
  }
  return true;
}

std::optional<uint32_t> FrameBuffer3::NextDecodableRtpTimestamp() const {
  for (const auto& [fid, frame] : frames_) {
    (void)fid;
    if (AllReferencesDecoded(frame)) {
      return frame.rtp_timestamp;
    }
  }
  return std::nullopt;
}

bool FrameBuffer3::HasContinuousKeyframe() const {
  for (const auto& [fid, frame] : frames_) {
    (void)fid;
    if (frame.dep.is_keyframe) {
      return true;
    }
  }
  return false;
}

std::optional<AssembledRtpFrame> FrameBuffer3::ExtractNextDecodableFrame() {
  for (auto it = frames_.begin(); it != frames_.end(); ++it) {
    if (AllReferencesDecoded(it->second)) {
      if (it != frames_.begin()) {
        RTC_LOG(kInfo) << "FrameBuffer3 skipped "
                       << std::distance(frames_.begin(), it)
                       << " broken-reference P-frames to clean IDR frame_id="
                       << it->first;
      }
      AssembledRtpFrame out = std::move(it->second);
      const int64_t decoded_id = out.dep.frame_id;
      frames_.erase(frames_.begin(), std::next(it));
      decoded_history_.InsertDecoded(decoded_id, out.rtp_timestamp);
      oldest_undecodable_since_ = Timestamp::MinusInfinity();
      return out;
    }
  }
  if (!frames_.empty() && oldest_undecodable_since_.IsMinusInfinity()) {
    oldest_undecodable_since_ = frames_.begin()->second.received_time;
  }
  return std::nullopt;
}

bool FrameBuffer3::IsCorruptedOrStalled(Timestamp now,
                                        TimeDelta max_wait) const {
  if (frames_.empty()) {
    return false;
  }
  for (const auto& [fid, frame] : frames_) {
    (void)fid;
    if (AllReferencesDecoded(frame)) {
      return false;
    }
  }
  const Timestamp oldest = frames_.begin()->second.received_time;
  return oldest.IsFinite() && (now - oldest) >= max_wait;
}

void FrameBuffer3::Clear() {
  frames_.clear();
  decoded_history_.Clear();
  oldest_undecodable_since_ = Timestamp::MinusInfinity();
}

// ======================= 5. VCMJitterEstimator 抖动估计与 VCMTiming 时序控制 =======================

VCMJitterEstimator::VCMJitterEstimator() { Reset(); }

void VCMJitterEstimator::Reset() {
  theta_[0] = 1.0 / (512.0e3 / 8.0);
  theta_[1] = 0.0;
  theta_cov_[0][0] = 1e-4;
  theta_cov_[1][1] = 1e2;
  theta_cov_[0][1] = 0.0;
  theta_cov_[1][0] = 0.0;
  q_cov_[0][0] = 2.5e-10;
  q_cov_[1][1] = 1e-10;
  q_cov_[0][1] = 0.0;
  q_cov_[1][0] = 0.0;
  avg_frame_size_bytes_ = 500.0;
  var_frame_size_bytes2_ = 100.0;
  max_frame_size_bytes_ = 500.0;
  avg_noise_ms_ = 0.0;
  var_noise_ms2_ = 4.0;
  startup_count_ = 0;
  nack_count_ = 0;
}

void VCMJitterEstimator::UpdateEstimate(TimeDelta frame_delay_delta,
                                        DataSize frame_size_delta,
                                        DataSize current_frame_size,
                                        bool incomplete_frame) {
  if (incomplete_frame) {
    return;
  }

  const double fs = static_cast<double>(current_frame_size.bytes());
  avg_frame_size_bytes_ = 0.96 * avg_frame_size_bytes_ + 0.04 * fs;
  const double fs_dev = fs - avg_frame_size_bytes_;
  var_frame_size_bytes2_ =
      std::max(0.96 * var_frame_size_bytes2_ + 0.04 * fs_dev * fs_dev, 1.0);
  max_frame_size_bytes_ = std::max(0.999 * max_frame_size_bytes_, fs);

  const double d_t = frame_delay_delta.ms_double();
  const double d_s = static_cast<double>(frame_size_delta.bytes());

  theta_cov_[0][0] += q_cov_[0][0];
  theta_cov_[1][1] += q_cov_[1][1];

  const double residual = d_t - (theta_[0] * d_s + theta_[1]);
  const double m_h[2] = {theta_cov_[0][0] * d_s + theta_cov_[0][1],
                         theta_cov_[1][0] * d_s + theta_cov_[1][1]};
  const double sigma = std::max(300.0, var_noise_ms2_);
  const double denom = d_s * m_h[0] + m_h[1] + sigma;
  if (denom > 1e-9) {
    const double k0 = m_h[0] / denom;
    const double k1 = m_h[1] / denom;
    theta_[0] = std::max(theta_[0] + k0 * residual, 1e-7);
    theta_[1] += k1 * residual;

    const double p00 =
        (1.0 - k0 * d_s) * theta_cov_[0][0] - k0 * theta_cov_[1][0];
    const double p01 =
        (1.0 - k0 * d_s) * theta_cov_[0][1] - k0 * theta_cov_[1][1];
    const double p10 =
        -k1 * d_s * theta_cov_[0][0] + (1.0 - k1) * theta_cov_[1][0];
    const double p11 =
        -k1 * d_s * theta_cov_[0][1] + (1.0 - k1) * theta_cov_[1][1];
    theta_cov_[0][0] = p00;
    theta_cov_[0][1] = p01;
    theta_cov_[1][0] = p10;
    theta_cov_[1][1] = p11;
  }

  const double alpha = (startup_count_ < 30) ? 0.90 : 0.995;
  if (std::fabs(fs_dev) < 2.0 * std::sqrt(var_frame_size_bytes2_)) {
    avg_noise_ms_ = alpha * avg_noise_ms_ + (1.0 - alpha) * residual;
    const double noise_err = residual - avg_noise_ms_;
    var_noise_ms2_ = std::max(
        1.0, alpha * var_noise_ms2_ + (1.0 - alpha) * noise_err * noise_err);
  }
  ++startup_count_;
}

TimeDelta VCMJitterEstimator::GetJitterEstimate(double rtt_multiplier,
                                                TimeDelta rtt) const {
  constexpr double kNoiseStdDevs = 2.33;
  const double channel_transmission_ms =
      theta_[0] * std::max(0.0, max_frame_size_bytes_ - avg_frame_size_bytes_);
  const double noise_jitter_ms = kNoiseStdDevs * std::sqrt(var_noise_ms2_);
  double total_ms = channel_transmission_ms + noise_jitter_ms;
  if (nack_count_ >= 3) {
    total_ms += rtt.ms_double() * rtt_multiplier;
  }
  total_ms = std::clamp(total_ms, 5.0, 2000.0);
  return TimeDelta::Micros(static_cast<int64_t>(total_ms * 1000.0));
}

VCMTiming::VCMTiming(Timestamp start_time, bool zero_playout_delay)
    : ts_extrapolator_(start_time), zero_playout_delay_(zero_playout_delay) {
  if (zero_playout_delay_) {
    min_playout_delay_ = TimeDelta::Zero();
    max_playout_delay_ = TimeDelta::Zero();
  }
}

void VCMTiming::Reset(Timestamp now) { ts_extrapolator_.Reset(now); }

void VCMTiming::SetJitterDelay(TimeDelta jitter_delay) {
  jitter_delay_ = std::max(TimeDelta::Zero(), jitter_delay);
}

void VCMTiming::SetPlayoutDelay(PlayoutDelayLimits limits) {
  min_playout_delay_ = TimeDelta::Millis(limits.min_ms);
  max_playout_delay_ = TimeDelta::Millis(limits.max_ms);
  zero_playout_delay_ = (limits.min_ms == 0 && limits.max_ms == 0);
}

void VCMTiming::IncomingTimestamp(uint32_t rtp_timestamp, Timestamp now) {
  ts_extrapolator_.Update(now, rtp_timestamp);
}

TimeDelta VCMTiming::TargetVideoDelay() const {
  if (zero_playout_delay_ || max_playout_delay_.IsZero()) {
    return TimeDelta::Zero();
  }
  return std::clamp(jitter_delay_ + estimated_decode_time_, min_playout_delay_,
                    max_playout_delay_);
}

Timestamp VCMTiming::RenderTime(uint32_t frame_timestamp, Timestamp now) const {
  if (zero_playout_delay_ || max_playout_delay_.IsZero()) {
    return now;
  }
  const auto estimated_complete =
      ts_extrapolator_.ExtrapolateLocalTime(frame_timestamp);
  if (!estimated_complete.has_value()) {
    return now;
  }
  return *estimated_complete + TargetVideoDelay();
}

TimeDelta VCMTiming::MaxWaitingTime(Timestamp render_time,
                                    Timestamp now) const {
  if (zero_playout_delay_ || max_playout_delay_.IsZero()) {
    return TimeDelta::Zero();
  }
  return render_time - now - estimated_decode_time_;
}

// ======================= 6. SimulcastRateAllocator 多流码率分配器 =======================

SimulcastRateAllocator::SimulcastRateAllocator(
    const SimulcastAllocatorConfig& cfg)
    : cfg_(cfg) {}

VideoBitrateAllocation SimulcastRateAllocator::Allocate(
    DataRate total_target_rate,
    double protection_overhead_ratio) {
  VideoBitrateAllocation alloc{};
  protection_overhead_ratio = std::clamp(protection_overhead_ratio, 0.0, 1.0);

  // 带宽守恒定律：R_wire = R_media * (1 + overhead_ratio) <= R_target。
  const uint32_t media_budget_bps = static_cast<uint32_t>(std::clamp<int64_t>(
      static_cast<int64_t>(static_cast<double>(total_target_rate.bps()) /
                           (1.0 + protection_overhead_ratio)),
      cfg_.min_total_bps, cfg_.max_total_bps));

  if (!cfg_.enable_simulcast) {
    alloc.layers[0] = LayerAllocation{false, 0, 0};
    alloc.layers[1].active = true;
    alloc.layers[1].target_bitrate_bps = media_budget_bps;
    alloc.layers[1].target_fps = (media_budget_bps < 350'000) ? 15 : 30;
    return alloc;
  }

  const uint32_t enable_high_threshold =
      cfg_.low_max_bps + cfg_.high_min_bps +
      (high_was_active_ ? 0 : cfg_.high_hysteresis_bps);
  const uint32_t disable_high_threshold = cfg_.low_min_bps + cfg_.high_min_bps;

  const bool enable_high =
      high_was_active_ ? (media_budget_bps >= disable_high_threshold)
                       : (media_budget_bps >= enable_high_threshold);
  if (enable_high != high_was_active_) {
    RTC_LOG(kInfo) << "Simulcast HIGH spatial layer "
                   << (enable_high ? "ACTIVATED" : "SUSPENDED")
                   << " (media_budget=" << media_budget_bps / 1000 << " kbps)";
  }
  high_was_active_ = enable_high;

  if (!enable_high) {
    alloc.layers[0].active = true;
    alloc.layers[0].target_bitrate_bps =
        std::min(media_budget_bps, cfg_.low_max_bps);
    alloc.layers[0].target_fps = (media_budget_bps < 200'000) ? 15 : 25;
    alloc.layers[1] = LayerAllocation{false, 0, 0};
  } else {
    const uint32_t low_bps =
        std::clamp(media_budget_bps / 5, cfg_.low_min_bps, cfg_.low_max_bps);
    const uint32_t high_bps = media_budget_bps - low_bps;

    alloc.layers[0].active = true;
    alloc.layers[0].target_bitrate_bps = low_bps;
    alloc.layers[0].target_fps = 20;

    alloc.layers[1].active = true;
    alloc.layers[1].target_bitrate_bps = high_bps;
    alloc.layers[1].target_fps = (high_bps < 700'000) ? 20 : 30;
  }
  return alloc;
}

}  // namespace rtc
