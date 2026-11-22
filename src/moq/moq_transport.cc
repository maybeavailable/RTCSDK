#include "moq/moq_transport.h"

#include <algorithm>
#include <atomic>
#include <cstring>

#include "modules/rtp_rtcp/byte_io.h"
#include "moq/asio_quic_transport.h"
#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"

namespace rtc {

// ======================= QuicVarInt 变长整数编解码（RFC 9000 第 16 节） =======================

void QuicVarInt::Append(uint64_t val, std::vector<uint8_t>* dst) {
  if (val <= 63) {
    dst->push_back(static_cast<uint8_t>(val));
  } else if (val <= 16383) {
    uint8_t b[2];
    WriteBigEndian16(b, static_cast<uint16_t>(val) | 0x4000u);
    dst->insert(dst->end(), b, b + 2);
  } else if (val <= 1073741823ULL) {
    uint8_t b[4];
    WriteBigEndian32(b, static_cast<uint32_t>(val) | 0x80000000u);
    dst->insert(dst->end(), b, b + 4);
  } else {
    uint8_t b[8];
    WriteBigEndian32(
        b, static_cast<uint32_t>((val >> 32) & 0x3FFFFFFFULL) | 0xC0000000u);
    WriteBigEndian32(b + 4, static_cast<uint32_t>(val & 0xFFFFFFFFULL));
    dst->insert(dst->end(), b, b + 8);
  }
}

bool QuicVarInt::Read(ArrayView<const uint8_t> data,
                      size_t* offset,
                      uint64_t* out_val) {
  if (*offset >= data.size()) {
    return false;
  }
  const uint8_t first = data[*offset];
  const uint8_t prefix = first >> 6;
  const size_t nbytes = size_t{1} << prefix;
  if (*offset + nbytes > data.size()) {
    return false;
  }

  uint64_t v = first & 0x3Fu;
  for (size_t i = 1; i < nbytes; ++i) {
    v = (v << 8) | data[*offset + i];
  }
  *offset += nbytes;
  *out_val = v;
  return true;
}

void QuicVarInt::AppendString(std::string_view str, std::vector<uint8_t>* dst) {
  Append(str.size(), dst);
  dst->insert(dst->end(), str.begin(), str.end());
}

bool QuicVarInt::ReadString(ArrayView<const uint8_t> data,
                            size_t* offset,
                            std::string* out_str) {
  uint64_t slen = 0;
  if (!Read(data, offset, &slen)) {
    return false;
  }
  if (*offset + slen > data.size()) {
    return false;
  }
  out_str->assign(reinterpret_cast<const char*>(data.data() + *offset),
                  static_cast<size_t>(slen));
  *offset += static_cast<size_t>(slen);
  return true;
}

// ======================= MoqControlMessage 与 MoqSubgroupHeader 控制消息与子组头 =======================

std::vector<uint8_t> MoqControlMessage::Encode() const {
  std::vector<uint8_t> body;
  QuicVarInt::Append(subscribe_id, &body);
  QuicVarInt::Append(track_alias, &body);
  QuicVarInt::AppendString(track_namespace, &body);
  QuicVarInt::AppendString(track_name, &body);
  body.push_back(subscriber_priority);
  QuicVarInt::Append(static_cast<uint64_t>(filter_type), &body);

  std::vector<uint8_t> frame;
  QuicVarInt::Append(static_cast<uint64_t>(type), &frame);
  QuicVarInt::Append(body.size(), &frame);
  frame.insert(frame.end(), body.begin(), body.end());
  return frame;
}

std::optional<MoqControlMessage> MoqControlMessage::Decode(
    ArrayView<const uint8_t> data,
    size_t* consumed) {
  size_t off = 0;
  uint64_t raw_type = 0;
  uint64_t body_len = 0;
  if (!QuicVarInt::Read(data, &off, &raw_type) ||
      !QuicVarInt::Read(data, &off, &body_len) ||
      off + body_len > data.size()) {
    return std::nullopt;
  }

  const ArrayView<const uint8_t> body_slice =
      data.subview(0, off + static_cast<size_t>(body_len));
  MoqControlMessage msg;
  msg.type = static_cast<MoqControlMessageType>(raw_type);
  if (!QuicVarInt::Read(body_slice, &off, &msg.subscribe_id) ||
      !QuicVarInt::Read(body_slice, &off, &msg.track_alias) ||
      !QuicVarInt::ReadString(body_slice, &off, &msg.track_namespace) ||
      !QuicVarInt::ReadString(body_slice, &off, &msg.track_name) ||
      off + 1 > body_slice.size()) {
    return std::nullopt;
  }
  msg.subscriber_priority = body_slice[off++];
  uint64_t ft = 0;
  if (!QuicVarInt::Read(body_slice, &off, &ft)) {
    return std::nullopt;
  }
  msg.filter_type = static_cast<MoqFilterType>(ft);

  *consumed = body_slice.size();
  return msg;
}

std::vector<uint8_t> MoqSubgroupHeader::Encode() const {
  std::vector<uint8_t> out;
  QuicVarInt::Append(0x04, &out);
  QuicVarInt::Append(track_alias, &out);
  QuicVarInt::Append(group_id, &out);
  QuicVarInt::Append(subgroup_id, &out);
  out.push_back(publisher_priority);
  return out;
}

std::optional<MoqSubgroupHeader> MoqSubgroupHeader::Decode(
    ArrayView<const uint8_t> data,
    size_t* consumed) {
  size_t off = 0;
  uint64_t stream_type = 0;
  if (!QuicVarInt::Read(data, &off, &stream_type) || stream_type != 0x04) {
    return std::nullopt;
  }
  MoqSubgroupHeader hdr;
  if (!QuicVarInt::Read(data, &off, &hdr.track_alias) ||
      !QuicVarInt::Read(data, &off, &hdr.group_id) ||
      !QuicVarInt::Read(data, &off, &hdr.subgroup_id) ||
      off + 1 > data.size()) {
    return std::nullopt;
  }
  hdr.publisher_priority = data[off++];
  *consumed = off;
  return hdr;
}

// ======================= MoqDataPackager 通用数据轨道对象封包器 =======================

std::vector<uint8_t> MoqDataPackager::PackObject(const MoqDataObject& obj) {
  std::vector<uint8_t> out;
  out.reserve(32 + obj.sender_peer_id.size() + obj.label.size() +
              obj.protocol.size() + obj.payload.size());
  QuicVarInt::Append(obj.object_id, &out);
  QuicVarInt::AppendString(obj.sender_peer_id, &out);
  QuicVarInt::AppendString(obj.label, &out);
  QuicVarInt::AppendString(obj.protocol, &out);
  QuicVarInt::Append(obj.timestamp_us, &out);
  uint8_t flags = 0;
  if (obj.is_binary) {
    flags |= 0x01u;
  }
  if (obj.ordered) {
    flags |= 0x02u;
  }
  if (obj.is_close) {
    flags |= 0x04u;
  }
  out.push_back(flags);
  QuicVarInt::Append(obj.payload.size(), &out);
  out.insert(out.end(), obj.payload.begin(), obj.payload.end());
  return out;
}

std::optional<MoqDataObject> MoqDataPackager::UnpackObject(
    ArrayView<const uint8_t> data,
    size_t* consumed) {
  size_t off = 0;
  MoqDataObject obj;
  if (!QuicVarInt::Read(data, &off, &obj.object_id) ||
      !QuicVarInt::ReadString(data, &off, &obj.sender_peer_id) ||
      !QuicVarInt::ReadString(data, &off, &obj.label) ||
      !QuicVarInt::ReadString(data, &off, &obj.protocol) ||
      !QuicVarInt::Read(data, &off, &obj.timestamp_us) ||
      off + 1 > data.size()) {
    return std::nullopt;
  }
  const uint8_t flags = data[off++];
  obj.is_binary = (flags & 0x01u) != 0u;
  obj.ordered = (flags & 0x02u) != 0u;
  obj.is_close = (flags & 0x04u) != 0u;

  uint64_t payload_len = 0;
  if (!QuicVarInt::Read(data, &off, &payload_len) ||
      off + payload_len > data.size()) {
    return std::nullopt;
  }
  obj.payload.assign(data.data() + off,
                     data.data() + off + static_cast<size_t>(payload_len));
  off += static_cast<size_t>(payload_len);
  *consumed = off;
  return obj;
}

// ======================= LocFramePackager 低开销容器帧封包器 =======================

std::vector<uint8_t> LocFramePackager::PackObject(
    uint64_t object_id,
    const EncodedVideoFrame& frame) {
  std::vector<uint8_t> meta;
  QuicVarInt::Append(static_cast<uint64_t>(frame.capture_time.us()), &meta);
  QuicVarInt::Append(frame.rtp_timestamp, &meta);
  QuicVarInt::Append(
      static_cast<uint64_t>(frame.dep.frame_id >= 0 ? frame.dep.frame_id : 0),
      &meta);

  uint8_t flags = 0;
  if (frame.dep.is_keyframe) {
    flags |= 0x01;
  }
  if (frame.dep.discardable) {
    flags |= 0x02;
  }
  if (frame.codec == VideoCodec::kH265) {
    flags |= 0x04;
  }
  if (frame.layer == SpatialLayer::kHigh) {
    flags |= 0x08;
  }
  flags |= static_cast<uint8_t>((frame.dep.temporal_id & 0x07) << 4);
  meta.push_back(flags);

  const uint8_t nrefs =
      static_cast<uint8_t>(std::min<size_t>(frame.dep.num_references, 4));
  meta.push_back(nrefs);
  for (uint8_t i = 0; i < nrefs; ++i) {
    const int64_t diff =
        std::max<int64_t>(1, frame.dep.frame_id - frame.dep.references[i]);
    QuicVarInt::Append(static_cast<uint64_t>(diff), &meta);
  }

  std::vector<uint8_t> out;
  out.reserve(16 + meta.size() + frame.data.size());
  QuicVarInt::Append(object_id, &out);
  QuicVarInt::Append(meta.size(), &out);
  out.insert(out.end(), meta.begin(), meta.end());
  QuicVarInt::Append(frame.data.size(), &out);
  out.insert(out.end(), frame.data.begin(), frame.data.end());
  return out;
}

std::optional<EncodedVideoFrame> LocFramePackager::UnpackObject(
    ArrayView<const uint8_t> data,
    size_t* consumed,
    uint64_t* out_object_id) {
  size_t off = 0;
  uint64_t obj_id = 0;
  uint64_t meta_len = 0;
  if (!QuicVarInt::Read(data, &off, &obj_id) ||
      !QuicVarInt::Read(data, &off, &meta_len) ||
      off + meta_len > data.size()) {
    return std::nullopt;
  }

  const ArrayView<const uint8_t> meta_slice =
      data.subview(0, off + static_cast<size_t>(meta_len));
  uint64_t cap_us = 0;
  uint64_t rtp_ts = 0;
  uint64_t frame_id = 0;
  if (!QuicVarInt::Read(meta_slice, &off, &cap_us) ||
      !QuicVarInt::Read(meta_slice, &off, &rtp_ts) ||
      !QuicVarInt::Read(meta_slice, &off, &frame_id) ||
      off + 2 > meta_slice.size()) {
    return std::nullopt;
  }

  const uint8_t flags = meta_slice[off++];
  const uint8_t nrefs = std::min<uint8_t>(meta_slice[off++], 4);

  EncodedVideoFrame frame;
  frame.capture_time = Timestamp::Micros(static_cast<int64_t>(cap_us));
  frame.rtp_timestamp = static_cast<uint32_t>(rtp_ts);
  frame.codec = (flags & 0x04) != 0 ? VideoCodec::kH265 : VideoCodec::kH264;
  frame.layer = (flags & 0x08) != 0 ? SpatialLayer::kHigh : SpatialLayer::kLow;
  frame.dep.frame_id = static_cast<int64_t>(frame_id);
  frame.dep.is_keyframe = (flags & 0x01) != 0;
  frame.dep.discardable = (flags & 0x02) != 0;
  frame.dep.spatial_id = static_cast<uint8_t>(frame.layer);
  frame.dep.temporal_id = (flags >> 4) & 0x07;
  frame.dep.num_references = nrefs;
  for (uint8_t i = 0; i < nrefs; ++i) {
    uint64_t diff = 0;
    if (!QuicVarInt::Read(meta_slice, &off, &diff)) {
      return std::nullopt;
    }
    frame.dep.references[i] = frame.dep.frame_id - static_cast<int64_t>(diff);
  }
  off = meta_slice.size();

  uint64_t payload_len = 0;
  if (!QuicVarInt::Read(data, &off, &payload_len) ||
      off + payload_len > data.size()) {
    return std::nullopt;
  }

  frame.data.assign(data.data() + off,
                    data.data() + off + static_cast<size_t>(payload_len));
  off += static_cast<size_t>(payload_len);
  *consumed = off;
  if (out_object_id != nullptr) {
    *out_object_id = obj_id;
  }
  return frame;
}

// ======================= MoqBweAdapter 带宽估计适配器 =======================

MoqBweAdapter::MoqBweAdapter(DataRate min_bitrate, DataRate max_bitrate)
    : min_bitrate_(min_bitrate), max_bitrate_(max_bitrate) {}

TargetTransferRate MoqBweAdapter::ConvertSnapshot(
    const QuicCongestionSnapshot& snap) const {
  const TimeDelta rtt = std::max(TimeDelta::Millis(2), snap.smoothed_rtt);
  const DataRate cwnd_rate = snap.cwnd / rtt;
  // 优先采用当前可插拔 QUIC 拥塞控制模块的带宽估计值（如 BBRv1/BBRv2 的瓶颈带宽滤波器），
  // 并以 1.0 倍 cwnd/RTT 作为上限，避免流缓冲区膨胀。
  DataRate target = (snap.cc_bandwidth_estimate > DataRate::Zero())
                        ? std::min(snap.cc_bandwidth_estimate, cwnd_rate)
                        : cwnd_rate;
  const bool pipe_saturated =
      (snap.bytes_in_flight.bytes() * 2 >= snap.cwnd.bytes()) ||
      (snap.unsent_stream_bytes > snap.cwnd) ||
      (snap.min_rtt > TimeDelta::Zero() &&
       snap.smoothed_rtt > snap.min_rtt * 1.35 + TimeDelta::Millis(5));
  if (snap.delivery_rate > DataRate::Zero() && pipe_saturated) {
    // 当管道饱和或出现排队时，立即向真实 1-RTT 交付速率收敛，防止 BBR 10 轮最大值窗口在带宽骤降时滞后；
    // 若发送流缓冲区已出现积压或显著驻留排队，则施加 0.90 回推系数加速排空旧队列。
    const bool heavy_queue =
        (snap.unsent_stream_bytes > snap.cwnd) ||
        (snap.min_rtt > TimeDelta::Zero() &&
         snap.smoothed_rtt > snap.min_rtt * 1.60 + TimeDelta::Millis(10));
    const double gain = heavy_queue ? 0.90 : 1.03;
    target = std::min(target, snap.delivery_rate * gain);
    app_limited_probe_rate_ = DataRate::Zero();
    last_probe_step_ = snap.timestamp;
  } else if (!pipe_saturated && snap.unsent_stream_bytes == DataSize::Zero() &&
             snap.recent_loss_ratio < 0.015 && snap.timestamp.IsFinite() &&
             target < cwnd_rate) {
    // 当编码器处于应用受限（如 Simulcast 高清层暂停后仅发送低清层）且管道完全空闲无排队时，
    // 渐进向上试探至 cwnd_rate，以便在物理瓶颈恢复后自动重新唤醒高清层探测真实带宽。
    if (!last_probe_step_.IsFinite()) {
      last_probe_step_ = snap.timestamp;
      app_limited_probe_rate_ = target;
    } else if ((snap.timestamp - last_probe_step_) >= TimeDelta::Millis(200)) {
      last_probe_step_ = snap.timestamp;
      const DataRate base = std::max(target, app_limited_probe_rate_);
      app_limited_probe_rate_ =
          std::min(cwnd_rate, base * 1.25 + DataRate::KilobitsPerSec(60));
    }
    target = std::max(target, std::min(cwnd_rate, app_limited_probe_rate_));
  }
  target = std::clamp(target, min_bitrate_, max_bitrate_);

  TargetTransferRate msg;
  msg.at_time = snap.timestamp;
  msg.target_rate = target;
  msg.stable_target_rate = target * 0.92;
  msg.rtt = rtt;
  msg.loss_rate_ratio = std::clamp(snap.recent_loss_ratio, 0.0, 1.0);
  msg.network_estimate.update_time = snap.timestamp;
  msg.network_estimate.link_capacity = target;
  return msg;
}

// ======================= MoqRelayBackend MoQ 中继会话后端 =======================

namespace {

std::unique_ptr<IQuicCongestionController> MakeInitialMoqCc(
    const EngineConfig& config) {
  if (config.custom_quic_cc_factory) {
    auto custom = config.custom_quic_cc_factory->Create(kQuicMaxDatagramSize);
    if (custom) {
      return custom;
    }
  }
  auto builtin = CreateBuiltinQuicCongestionController(config.quic_cc_algo,
                                                       kQuicMaxDatagramSize);
  if (builtin) {
    return builtin;
  }
  return CreateBuiltinQuicCongestionController(RTC_QUIC_CC_BBR,
                                               kQuicMaxDatagramSize);
}

}  // namespace

MoqRelayBackend::MoqRelayBackend(Clock* clock,
                                 SdkTaskQueues* queues,
                                 const EngineConfig& config,
                                 ISessionBackendObserver* observer,
                                 std::shared_ptr<IMoqQuicEngine> quic_engine)
    : clock_(clock),
      queues_(queues),
      config_(config),
      observer_(observer),
      quic_engine_(quic_engine
                       ? std::move(quic_engine)
                       : std::make_shared<AsioQuicClientEngine>(
                             clock,
                             queues->network(),
                             MakeInitialMoqCc(config))),
      bwe_adapter_(DataRate::BitsPerSec(config.min_bitrate_bps),
                   DataRate::BitsPerSec(config.max_bitrate_bps)),
      work_checker_(queues->worker()),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {
  if (quic_engine_) {
    quic_engine_->SetObserver(this);
  }
}

MoqRelayBackend::~MoqRelayBackend() { StopSession(); }

bool MoqRelayBackend::ParseMoqEndpoint(std::string_view url,
                                       std::string* host,
                                       uint16_t* port) {
  *host = "127.0.0.1";
  *port = 4433;
  if (url.empty()) {
    return true;
  }
  size_t pos = 0;
  const size_t scheme = url.find("://");
  if (scheme != std::string_view::npos) {
    pos = scheme + 3;
  }
  const size_t slash = url.find('/', pos);
  const std::string_view auth =
      (slash == std::string_view::npos) ? url.substr(pos)
                                        : url.substr(pos, slash - pos);
  const size_t colon = auth.rfind(':');
  if (colon != std::string_view::npos) {
    *host = std::string(auth.substr(0, colon));
    uint16_t parsed_port = 4433;
    if (ParseUint16(auth.substr(colon + 1), &parsed_port)) {
      *port = parsed_port;
    }
  } else if (!auth.empty()) {
    *host = std::string(auth);
  }
  return true;
}

std::string MoqRelayBackend::MakeRemoteNamespace(
    std::string_view track_or_peer_id) const {
  const std::string prefix = room_id_ + "/";
  if (track_or_peer_id.size() >= prefix.size() &&
      track_or_peer_id.substr(0, prefix.size()) == prefix) {
    return std::string(track_or_peer_id);
  }
  return prefix + std::string(track_or_peer_id);
}

std::string MoqRelayBackend::ExtractTrackIdFromNamespace(
    std::string_view ns) const {
  const std::string prefix = room_id_ + "/";
  if (ns.size() > prefix.size() && ns.substr(0, prefix.size()) == prefix) {
    return std::string(ns.substr(prefix.size()));
  }
  return std::string(ns);
}

int MoqRelayBackend::StartSession(const std::string& room_id,
                                  const std::string& local_peer_id) {
  if (!quic_engine_) {
    RTC_LOG(kError) << "MoqRelayBackend started without IMoqQuicEngine";
    return RTC_ERR_NOT_INITIALIZED;
  }
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, room_id, local_peer_id]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        room_id_ = room_id;
        local_peer_id_ = local_peer_id;
        last_stats_time_ = clock_->CurrentTime();
        if (observer_ != nullptr) {
          observer_->OnBackendConnectionState(RTC_CONN_STATE_CONNECTING, 0);
        }
        std::string host;
        uint16_t port = 4433;
        ParseMoqEndpoint(config_.signaling_or_moq_url, &host, &port);
        RTC_LOG(kInfo) << "Connecting MoQ QUIC session to " << host << ":"
                       << port << " (room=" << room_id_
                       << ", peer=" << local_peer_id_ << ")";
        quic_engine_->Connect(host, port, "moq-00");
        OnPeriodicMaintenanceTick();
      }));
  return RTC_OK;
}

void MoqRelayBackend::StopSession() {
  if (queues_->worker()->IsStopped()) {
    return;
  }
  queues_->worker()->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    safety_.flag()->SetNotAlive();
    if (quic_engine_) {
      if (connected_) {
        for (const auto& [cid, dch] : data_channels_) {
          (void)cid;
          if (dch.announced && dch.state != RTC_DATA_CHANNEL_CLOSED) {
            MoqControlMessage dc_unann;
            dc_unann.type = MoqControlMessageType::kUnannounce;
            dc_unann.track_namespace = room_id_ + "/" + local_peer_id_;
            dc_unann.track_name = "data/" + dch.config.label;
            SendControlMessage(dc_unann);
          }
        }
        MoqControlMessage unannounce;
        unannounce.type = MoqControlMessageType::kUnannounce;
        unannounce.track_namespace = room_id_ + "/" + local_peer_id_;
        SendControlMessage(unannounce);
      }
      quic_engine_->Close(0);
    }
    connected_ = false;
    subscriptions_.clear();
    alias_to_track_id_.clear();
    inbound_streams_.clear();
    data_channels_.clear();
    label_to_dc_id_.clear();
    notified_remote_dc_peers_.clear();
    ttl_data_streams_.clear();
    {
      std::lock_guard<std::mutex> lock(dc_handles_mu_);
      valid_dc_ids_.clear();
    }
  });
}

void MoqRelayBackend::OnQuicConnected() {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    connected_ = true;
    control_stream_id_ = quic_engine_->OpenBidirectionalStream();

    std::vector<uint8_t> init_ctrl_flight;
    auto append_ctrl = [&init_ctrl_flight](const MoqControlMessage& m) {
      const auto enc = m.Encode();
      init_ctrl_flight.insert(init_ctrl_flight.end(), enc.begin(), enc.end());
    };

    MoqControlMessage setup;
    setup.type = MoqControlMessageType::kClientSetup;
    setup.track_namespace = room_id_ + "/" + local_peer_id_;
    append_ctrl(setup);

    MoqControlMessage announce;
    announce.type = MoqControlMessageType::kAnnounce;
    announce.track_namespace = room_id_ + "/" + local_peer_id_;
    announce.track_name =
        (config_.publish_codec == RTC_CODEC_H265) ? "video/h265" : "video/h264";
    append_ctrl(announce);

    if (config_.enable_datachannel) {
      // 预订阅房间级数据通配轨道，并合并进首包控制帧发送，避免零碎控制小包干扰拥塞窗口探测。
      MoqControlMessage data_sub;
      data_sub.type = MoqControlMessageType::kSubscribe;
      data_sub.subscribe_id = 0;
      data_sub.track_alias = kMoqDownstreamDataTrackAlias;
      data_sub.track_namespace = room_id_ + "/*";
      data_sub.track_name = "data/*";
      data_sub.subscriber_priority = 8;
      data_sub.filter_type = MoqFilterType::kLatestObject;
      append_ctrl(data_sub);

      for (auto& [cid, dch] : data_channels_) {
        if (dch.state == RTC_DATA_CHANNEL_CLOSED) {
          continue;
        }
        if (dch.local_created && !dch.announced) {
          MoqControlMessage dc_ann;
          dc_ann.type = MoqControlMessageType::kAnnounce;
          dc_ann.track_namespace = room_id_ + "/" + local_peer_id_;
          dc_ann.track_name = "data/" + dch.config.label;
          append_ctrl(dc_ann);
          dch.announced = true;
        }
      }
    }
    quic_engine_->WriteStream(control_stream_id_, init_ctrl_flight, false);

    if (config_.enable_datachannel) {
      for (auto& [cid, dch] : data_channels_) {
        if (dch.state == RTC_DATA_CHANNEL_CLOSED) {
          continue;
        }
        dch.state = RTC_DATA_CHANNEL_OPEN;
        if (!dch.local_open_notified && observer_ != nullptr) {
          dch.local_open_notified = true;
          observer_->OnBackendDataChannelState(
              local_peer_id_, cid, dch.config.label, RTC_DATA_CHANNEL_OPEN);
        }
        while (!dch.pending_messages.empty()) {
          PendingMoqDataMsg msg = std::move(dch.pending_messages.front());
          dch.pending_messages.pop_front();
          TransmitMoqDataMessageOnWorker(cid, msg.payload, msg.is_binary,
                                         /*is_close=*/false);
        }
      }
    }

    for (const auto& [tid, sub_ctx] : subscriptions_) {
      (void)tid;
      MoqControlMessage sub;
      sub.type = MoqControlMessageType::kSubscribe;
      sub.subscribe_id = sub_ctx->subscribe_id;
      sub.track_alias = sub_ctx->track_alias;
      sub.track_namespace = sub_ctx->remote_namespace;
      sub.track_name = (sub_ctx->preferred_layer == SpatialLayer::kHigh)
                           ? "video/high"
                           : "video/low";
      sub.filter_type = MoqFilterType::kLatestGroup;
      SendControlMessage(sub);
    }

    RTC_LOG(kInfo) << "MoQ session connected, announced namespace="
                   << announce.track_namespace
                   << " track_name=" << announce.track_name;
    if (observer_ != nullptr) {
      observer_->OnBackendConnectionState(RTC_CONN_STATE_CONNECTED, 0);
    }
  }));
}

void MoqRelayBackend::OnQuicDisconnected(int error_code) {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this, error_code]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    connected_ = false;
    RTC_LOG(kWarning) << "MoQ QUIC session disconnected (code=" << error_code
                      << ")";
    if (observer_ != nullptr) {
      observer_->OnBackendConnectionState(RTC_CONN_STATE_DISCONNECTED,
                                          error_code);
    }
  }));
}

void MoqRelayBackend::SendControlMessage(const MoqControlMessage& msg) {
  if (!connected_ || !quic_engine_) {
    return;
  }
  const auto bytes = msg.Encode();
  quic_engine_->WriteStream(control_stream_id_, bytes, false);
}

void MoqRelayBackend::SetLayerActive(SpatialLayer layer, bool active) {
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, layer, active]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const size_t idx = (layer == SpatialLayer::kHigh) ? 1 : 0;
        const bool was_active = layer_active_[idx];
        layer_active_[idx] = active;
        if (!was_active && active && observer_ != nullptr) {
          observer_->OnBackendForceKeyFrame(layer);
        }
      }));
}

int MoqRelayBackend::SendEncodedFrame(EncodedVideoFrame frame) {
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, f = std::move(frame)]() mutable {
        RTC_DCHECK_RUN_ON(&work_checker_);
        if (!connected_ || !quic_engine_) {
          return;
        }

        const size_t layer_idx = (f.layer == SpatialLayer::kHigh) ? 1 : 0;
        if (config_.enable_simulcast && !layer_active_[layer_idx]) {
          return;
        }
        const Timestamp now = clock_->CurrentTime();

        const int64_t fid = ++next_frame_id_[layer_idx];
        f.dep.frame_id = fid;
        if (f.dep.is_keyframe) {
          f.dep.num_references = 0;
        } else if (fid > 1) {
          f.dep.num_references = 1;
          f.dep.references[0] = fid - 1;
        }

        if (active_group_[layer_idx].has_value()) {
          auto& prev_grp = *active_group_[layer_idx];
          const QuicCongestionSnapshot qsnap =
              quic_engine_->GetCongestionSnapshot();
          const DataRate drain_rate = std::max(
              DataRate::KilobitsPerSec(150),
              qsnap.delivery_rate > DataRate::Zero() ? qsnap.delivery_rate
                                                     : qsnap.pacing_rate);
          const TimeDelta est_delivery_delay =
              qsnap.smoothed_rtt + (qsnap.unsent_stream_bytes / drain_rate);
          // 仅当 GOP 持续时间与实际传输排队时延均超过 moq_delivery_timeout_ms 时才判定为拥塞投递超时，
          // 避免正常长 GOP（如 1s~2s IDR 间隔）在健康链路上被误重置。
          const bool expired =
              (now - prev_grp.started_at) >
                  TimeDelta::Millis(config_.moq_delivery_timeout_ms) &&
              est_delivery_delay >
                  TimeDelta::Millis(config_.moq_delivery_timeout_ms);
          if (f.dep.is_keyframe) {
            for (const auto& [tid, sid] : prev_grp.subgroup_streams) {
              (void)tid;
              if (expired) {
                quic_engine_->ResetStream(sid, 0x01);
                ++streams_reset_on_timeout_;
              } else {
                quic_engine_->WriteStream(sid, ArrayView<const uint8_t>(),
                                          true);
              }
            }
            active_group_[layer_idx].reset();
          } else if (expired) {
            RTC_LOG(kWarning)
                << "MoQ GOP group_id=" << prev_grp.group_id
                << " exceeded delivery_timeout_ms="
                << config_.moq_delivery_timeout_ms
                << ", issuing RESET_STREAM and requesting IDR";
            for (const auto& [tid, sid] : prev_grp.subgroup_streams) {
              (void)tid;
              quic_engine_->ResetStream(sid, 0x01);
              ++streams_reset_on_timeout_;
            }
            active_group_[layer_idx].reset();
            if (observer_ != nullptr) {
              observer_->OnBackendForceKeyFrame(f.layer);
            }
            return;
          }
        }

        if (!active_group_[layer_idx].has_value()) {
          if (!f.dep.is_keyframe) {
            if (observer_ != nullptr) {
              observer_->OnBackendForceKeyFrame(f.layer);
            }
            return;
          }
          ActiveOutboundGroup grp;
          grp.group_id = ++current_group_id_[layer_idx];
          grp.next_object_id = 0;
          grp.started_at = now;
          active_group_[layer_idx] = std::move(grp);
        }

        auto& grp = *active_group_[layer_idx];
        const uint8_t tid = f.dep.temporal_id;
        uint64_t stream_id = 0;
        const auto st_it = grp.subgroup_streams.find(tid);
        if (st_it == grp.subgroup_streams.end()) {
          const uint8_t pub_prio =
              static_cast<uint8_t>((layer_idx == 0 ? 16 : 32) + tid * 8);
          const int64_t send_order =
              static_cast<int64_t>(grp.group_id * 100) +
              (layer_idx == 0 ? 50 : 20) - tid;
          stream_id = quic_engine_->OpenUnidirectionalStream(pub_prio,
                                                             send_order);
          grp.subgroup_streams[tid] = stream_id;

          MoqSubgroupHeader shdr;
          // 上行发布端将低清层（Low）编码为别名 1，高清层（High）编码为别名 2。
          shdr.track_alias = layer_idx + 1;
          shdr.group_id = grp.group_id;
          shdr.subgroup_id = tid;
          shdr.publisher_priority = pub_prio;
          const auto hdr_bytes = shdr.Encode();
          quic_engine_->WriteStream(stream_id, hdr_bytes, false);
        } else {
          stream_id = st_it->second;
        }

        const uint64_t obj_id = grp.next_object_id++;
        const auto loc_bytes = LocFramePackager::PackObject(obj_id, f);
        quic_engine_->WriteStream(stream_id, loc_bytes, false);
      }));
  return RTC_OK;
}

int MoqRelayBackend::SubscribeRemoteTrack(const std::string& track_id,
                                          SpatialLayer preferred_layer) {
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, track_id, preferred_layer]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const std::string canonical_id = ExtractTrackIdFromNamespace(track_id);
        const std::string remote_ns = MakeRemoteNamespace(canonical_id);
        const uint64_t sub_id = next_subscribe_id_++;
        const uint64_t alias = 100 + sub_id;

        auto ctx = std::make_unique<SubscribedTrackContext>(
            clock_->CurrentTime(), config_.zero_playout_delay);
        ctx->track_id = canonical_id;
        ctx->remote_namespace = remote_ns;
        ctx->subscribe_id = sub_id;
        ctx->track_alias = alias;
        ctx->preferred_layer = preferred_layer;
        alias_to_track_id_[alias] = canonical_id;
        subscriptions_[canonical_id] = std::move(ctx);

        MoqControlMessage sub;
        sub.type = MoqControlMessageType::kSubscribe;
        sub.subscribe_id = sub_id;
        sub.track_alias = alias;
        sub.track_namespace = remote_ns;
        sub.track_name =
            (preferred_layer == SpatialLayer::kHigh) ? "video/high"
                                                     : "video/low";
        sub.filter_type = MoqFilterType::kLatestGroup;
        SendControlMessage(sub);
        RTC_LOG(kInfo) << "MoQ subscribed track=" << canonical_id
                       << " namespace=" << remote_ns << " alias=" << alias
                       << " layer=" << sub.track_name;
      }));
  return RTC_OK;
}

int MoqRelayBackend::SwitchSubscribedLayer(const std::string& track_id,
                                           SpatialLayer preferred_layer) {
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, track_id, preferred_layer]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const std::string canonical_id = ExtractTrackIdFromNamespace(track_id);
        const auto it = subscriptions_.find(canonical_id);
        if (it == subscriptions_.end()) {
          return;
        }
        it->second->preferred_layer = preferred_layer;

        MoqControlMessage upd;
        upd.type = MoqControlMessageType::kSubscribeUpdate;
        upd.subscribe_id = it->second->subscribe_id;
        upd.track_alias = it->second->track_alias;
        upd.track_namespace = it->second->remote_namespace;
        upd.track_name =
            (preferred_layer == SpatialLayer::kHigh) ? "video/high"
                                                     : "video/low";
        SendControlMessage(upd);
        RTC_LOG(kInfo) << "MoQ requested layer switch on track=" << canonical_id
                       << " -> " << upd.track_name;
      }));
  return RTC_OK;
}

int MoqRelayBackend::UnsubscribeRemoteTrack(const std::string& track_id) {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this, track_id]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    const std::string canonical_id = ExtractTrackIdFromNamespace(track_id);
    const auto it = subscriptions_.find(canonical_id);
    if (it == subscriptions_.end()) {
      return;
    }
    MoqControlMessage unsub;
    unsub.type = MoqControlMessageType::kUnsubscribe;
    unsub.subscribe_id = it->second->subscribe_id;
    unsub.track_namespace = it->second->remote_namespace;
    SendControlMessage(unsub);
    alias_to_track_id_.erase(it->second->track_alias);
    subscriptions_.erase(it);
  }));
  return RTC_OK;
}

int MoqRelayBackend::RequestRemoteKeyFrame(const std::string& track_id) {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this, track_id]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    const std::string canonical_id = ExtractTrackIdFromNamespace(track_id);
    MoqControlMessage kf;
    kf.type = MoqControlMessageType::kKeyframeRequest;
    kf.track_namespace = MakeRemoteNamespace(canonical_id);
    const auto sub_it = subscriptions_.find(canonical_id);
    if (sub_it != subscriptions_.end()) {
      kf.track_name = (sub_it->second->preferred_layer == SpatialLayer::kLow)
                          ? "video/low"
                          : "video/high";
    } else {
      kf.track_name = "video";
    }
    ++keyframe_requests_sent_;
    SendControlMessage(kf);
  }));
  return RTC_OK;
}

int MoqRelayBackend::EnsureDataChannelForLabelOnWorker(
    const std::string& label,
    const DataChannelConfig* explicit_cfg) {
  RTC_DCHECK_RUN_ON(&work_checker_);
  const std::string norm_label = label.empty() ? "data" : label;
  const auto existing_it = label_to_dc_id_.find(norm_label);
  if (existing_it != label_to_dc_id_.end()) {
    const int cid = existing_it->second;
    auto& st = data_channels_[cid];
    if (explicit_cfg != nullptr) {
      st.config = *explicit_cfg;
      st.config.label = norm_label;
      st.local_created = true;
    }
    if (st.state == RTC_DATA_CHANNEL_CLOSED) {
      st.state = connected_ ? RTC_DATA_CHANNEL_OPEN
                            : RTC_DATA_CHANNEL_CONNECTING;
      st.local_open_notified = false;
      std::lock_guard<std::mutex> lock(dc_handles_mu_);
      valid_dc_ids_.insert(cid);
    }
    return cid;
  }

  int cid = next_dc_id_++;
  if (explicit_cfg != nullptr && explicit_cfg->negotiated &&
      explicit_cfg->id >= 0 &&
      data_channels_.find(explicit_cfg->id) == data_channels_.end()) {
    cid = explicit_cfg->id;
    next_dc_id_ = std::max(next_dc_id_, cid + 1);
  }

  MoqDataChannelState st;
  st.channel_id = cid;
  if (explicit_cfg != nullptr) {
    st.config = *explicit_cfg;
    st.local_created = true;
  }
  st.config.label = norm_label;
  st.state =
      connected_ ? RTC_DATA_CHANNEL_OPEN : RTC_DATA_CHANNEL_CONNECTING;
  data_channels_.emplace(cid, std::move(st));
  label_to_dc_id_[norm_label] = cid;
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    valid_dc_ids_.insert(cid);
  }
  return cid;
}

void MoqRelayBackend::TransmitMoqDataMessageOnWorker(
    int channel_id,
    ArrayView<const uint8_t> payload,
    bool is_binary,
    bool is_close) {
  RTC_DCHECK_RUN_ON(&work_checker_);
  const auto it = data_channels_.find(channel_id);
  if (it == data_channels_.end() || !connected_ || !quic_engine_) {
    return;
  }
  MoqDataChannelState& dch = it->second;
  if (!dch.announced && !is_close) {
    MoqControlMessage dc_ann;
    dc_ann.type = MoqControlMessageType::kAnnounce;
    dc_ann.track_namespace = room_id_ + "/" + local_peer_id_;
    dc_ann.track_name = "data/" + dch.config.label;
    SendControlMessage(dc_ann);
    dch.announced = true;
  }

  const Timestamp now = clock_->CurrentTime();
  MoqDataObject obj;
  obj.object_id = dch.next_object_id++;
  obj.sender_peer_id = local_peer_id_;
  obj.label = dch.config.label;
  obj.protocol = dch.config.protocol;
  obj.timestamp_us = static_cast<uint64_t>(now.us());
  obj.is_binary = is_binary;
  obj.ordered = dch.config.ordered;
  obj.is_close = is_close;
  obj.payload.assign(payload.begin(), payload.end());
  const auto obj_bytes = MoqDataPackager::PackObject(obj);

  const bool persistent_ordered =
      dch.config.ordered && dch.config.max_packet_lifetime_ms < 0 &&
      dch.config.max_retransmits < 0 && !is_close;

  if (persistent_ordered) {
    if (!dch.ordered_stream_id.has_value()) {
      const int64_t send_order =
          (int64_t{1} << 50) - static_cast<int64_t>(channel_id);
      const uint64_t sid =
          quic_engine_->OpenUnidirectionalStream(/*publisher_priority=*/8,
                                                 send_order);
      dch.ordered_stream_id = sid;
      MoqSubgroupHeader shdr;
      shdr.track_alias = kMoqUpstreamDataTrackAlias;
      shdr.group_id = static_cast<uint64_t>(channel_id + 1);
      shdr.subgroup_id = 0;
      shdr.publisher_priority = 8;
      const auto hdr_bytes = shdr.Encode();
      quic_engine_->WriteStream(sid, hdr_bytes, false);
    }
    quic_engine_->WriteStream(*dch.ordered_stream_id, obj_bytes, false);
  } else {
    const int64_t send_order =
        (int64_t{1} << 48) + static_cast<int64_t>(obj.object_id);
    const uint64_t sid =
        quic_engine_->OpenUnidirectionalStream(/*publisher_priority=*/10,
                                               send_order);
    MoqSubgroupHeader shdr;
    shdr.track_alias = kMoqUpstreamDataTrackAlias;
    shdr.group_id = static_cast<uint64_t>(channel_id + 1);
    shdr.subgroup_id = obj.object_id + 1;
    shdr.publisher_priority = 10;
    std::vector<uint8_t> combined = shdr.Encode();
    combined.insert(combined.end(), obj_bytes.begin(), obj_bytes.end());
    quic_engine_->WriteStream(sid, combined, /*fin=*/true);

    if (!is_close && (dch.config.max_packet_lifetime_ms >= 0 ||
                      dch.config.max_retransmits >= 0)) {
      const auto snap = quic_engine_->GetCongestionSnapshot();
      const int64_t ttl_ms =
          (dch.config.max_packet_lifetime_ms >= 0)
              ? dch.config.max_packet_lifetime_ms
              : std::max<int64_t>(
                    25, snap.smoothed_rtt.ms() * (1 + dch.config.max_retransmits));
      ttl_data_streams_.emplace_back(sid, now + TimeDelta::Millis(ttl_ms));
    }
  }
}

int MoqRelayBackend::CreateDataChannel(const DataChannelConfig& config) {
  if (!config_.enable_datachannel) {
    return RTC_ERR_PROTOCOL;
  }
  if (config.negotiated && config.id < 0) {
    return RTC_ERR_INVALID_ARG;
  }
  int cid = RTC_ERR_INTERNAL;
  queues_->worker()->Invoke([this, &config, &cid]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    cid = EnsureDataChannelForLabelOnWorker(config.label, &config);
    auto& dch = data_channels_[cid];
    if (connected_ && quic_engine_) {
      if (!dch.announced) {
        MoqControlMessage dc_ann;
        dc_ann.type = MoqControlMessageType::kAnnounce;
        dc_ann.track_namespace = room_id_ + "/" + local_peer_id_;
        dc_ann.track_name = "data/" + dch.config.label;
        SendControlMessage(dc_ann);
        dch.announced = true;
      }
      dch.state = RTC_DATA_CHANNEL_OPEN;
      if (!dch.local_open_notified && observer_ != nullptr) {
        dch.local_open_notified = true;
        observer_->OnBackendDataChannelState(
            local_peer_id_, cid, dch.config.label, RTC_DATA_CHANNEL_OPEN);
      }
    }
  });
  return cid;
}

int MoqRelayBackend::SendData(int channel_id,
                              ArrayView<const uint8_t> payload,
                              bool is_binary) {
  if (!config_.enable_datachannel) {
    return RTC_ERR_PROTOCOL;
  }
  if (channel_id < 0 || (payload.size() > 0 && payload.data() == nullptr)) {
    return RTC_ERR_INVALID_ARG;
  }
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    if (valid_dc_ids_.find(channel_id) == valid_dc_ids_.end()) {
      return RTC_ERR_INVALID_ARG;
    }
  }
  std::vector<uint8_t> copy(payload.begin(), payload.end());
  queues_->worker()->PostTask(SafeTask(
      safety_.flag(),
      [this, channel_id, buf = std::move(copy), is_binary]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const auto it = data_channels_.find(channel_id);
        if (it == data_channels_.end() ||
            it->second.state == RTC_DATA_CHANNEL_CLOSED) {
          return;
        }
        if (!connected_ || !quic_engine_) {
          if (it->second.pending_messages.size() < 512) {
            it->second.pending_messages.push_back(
                PendingMoqDataMsg{std::move(buf), is_binary});
          }
          return;
        }
        TransmitMoqDataMessageOnWorker(channel_id, buf, is_binary,
                                       /*is_close=*/false);
      }));
  return RTC_OK;
}

int MoqRelayBackend::CloseDataChannel(int channel_id) {
  if (!config_.enable_datachannel) {
    return RTC_ERR_PROTOCOL;
  }
  if (channel_id < 0) {
    return RTC_ERR_INVALID_ARG;
  }
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    if (valid_dc_ids_.find(channel_id) == valid_dc_ids_.end()) {
      return RTC_ERR_INVALID_ARG;
    }
    valid_dc_ids_.erase(channel_id);
  }
  queues_->worker()->Invoke([this, channel_id]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    const auto it = data_channels_.find(channel_id);
    if (it == data_channels_.end() ||
        it->second.state == RTC_DATA_CHANNEL_CLOSED) {
      return;
    }
    MoqDataChannelState& dch = it->second;
    if (connected_ && quic_engine_) {
      TransmitMoqDataMessageOnWorker(channel_id, ArrayView<const uint8_t>(),
                                     /*is_binary=*/true, /*is_close=*/true);
      if (dch.ordered_stream_id.has_value()) {
        quic_engine_->WriteStream(*dch.ordered_stream_id,
                                  ArrayView<const uint8_t>(), /*fin=*/true);
        dch.ordered_stream_id.reset();
      }
      if (dch.announced) {
        MoqControlMessage dc_unann;
        dc_unann.type = MoqControlMessageType::kUnannounce;
        dc_unann.track_namespace = room_id_ + "/" + local_peer_id_;
        dc_unann.track_name = "data/" + dch.config.label;
        SendControlMessage(dc_unann);
        dch.announced = false;
      }
    }
    dch.pending_messages.clear();
    dch.state = RTC_DATA_CHANNEL_CLOSED;
    if (observer_ != nullptr) {
      observer_->OnBackendDataChannelState(
          local_peer_id_, channel_id, dch.config.label,
          RTC_DATA_CHANNEL_CLOSED);
    }
  });
  return RTC_OK;
}

int MoqRelayBackend::SetQuicCongestionControl(rtc_quic_cc_algo_e algo) {
  if (!quic_engine_) {
    return RTC_ERR_NOT_INITIALIZED;
  }
  auto cc = CreateBuiltinQuicCongestionController(algo, kQuicMaxDatagramSize);
  if (!cc) {
    return RTC_ERR_INVALID_ARG;
  }
  return quic_engine_->SetCongestionController(std::move(cc));
}

int MoqRelayBackend::SetCustomQuicCongestionController(
    std::shared_ptr<IQuicCongestionControllerFactory> factory) {
  if (!factory) {
    return RTC_ERR_INVALID_ARG;
  }
  if (!quic_engine_) {
    return RTC_ERR_NOT_INITIALIZED;
  }
  auto cc = factory->Create(kQuicMaxDatagramSize);
  if (!cc) {
    return RTC_ERR_INVALID_ARG;
  }
  return quic_engine_->SetCongestionController(std::move(cc));
}

void MoqRelayBackend::OnStreamOpened(uint64_t stream_id, bool unidirectional) {
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, stream_id, unidirectional]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        if (!unidirectional) {
          control_stream_id_ = stream_id;
        } else {
          inbound_streams_[stream_id] = InboundStreamState{};
        }
      }));
}

void MoqRelayBackend::OnStreamData(uint64_t stream_id,
                                   ArrayView<const uint8_t> data,
                                   bool fin) {
  std::vector<uint8_t> copy(data.begin(), data.end());
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(),
               [this, stream_id, buf = std::move(copy), fin]() {
                 RTC_DCHECK_RUN_ON(&work_checker_);
                 const bool is_bidi = (stream_id & 0x02u) == 0;
                 if (is_bidi) {
                   HandleControlStreamBytes(buf);
                 } else {
                   HandleInboundUnidirectionalData(stream_id, buf, fin);
                 }
               }));
}

void MoqRelayBackend::OnStreamReset(uint64_t stream_id,
                                    uint64_t /*app_error_code*/) {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this, stream_id]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    inbound_streams_.erase(stream_id);
  }));
}

void MoqRelayBackend::HandleControlStreamBytes(ArrayView<const uint8_t> data) {
  ctrl_rx_buf_.insert(ctrl_rx_buf_.end(), data.begin(), data.end());
  while (!ctrl_rx_buf_.empty()) {
    size_t consumed = 0;
    auto msg = MoqControlMessage::Decode(ctrl_rx_buf_, &consumed);
    if (!msg.has_value()) {
      break;
    }
    ctrl_rx_buf_.erase(
        ctrl_rx_buf_.begin(),
        ctrl_rx_buf_.begin() + static_cast<ptrdiff_t>(consumed));

    switch (msg->type) {
      case MoqControlMessageType::kAnnounce: {
        const std::string self_ns = room_id_ + "/" + local_peer_id_;
        if (msg->track_namespace == self_ns) {
          break;
        }
        MoqControlMessage ok = *msg;
        ok.type = MoqControlMessageType::kAnnounceOk;
        SendControlMessage(ok);
        const std::string remote_id =
            ExtractTrackIdFromNamespace(msg->track_namespace);
        if (msg->track_name.rfind("data/", 0) == 0) {
          if (config_.enable_datachannel) {
            const std::string label = msg->track_name.substr(5);
            const int cid = EnsureDataChannelForLabelOnWorker(label, nullptr);
            if (notified_remote_dc_peers_.emplace(remote_id, cid).second &&
                observer_ != nullptr) {
              observer_->OnBackendDataChannelState(remote_id, cid, label,
                                                   RTC_DATA_CHANNEL_OPEN);
            }
          }
          break;
        }
        if (observer_ != nullptr) {
          VideoCodec codec = static_cast<VideoCodec>(config_.publish_codec);
          if (msg->track_name.find("h265") != std::string::npos) {
            codec = VideoCodec::kH265;
          } else if (msg->track_name.find("h264") != std::string::npos) {
            codec = VideoCodec::kH264;
          }
          observer_->OnBackendRemoteTrackPublished(remote_id, remote_id, codec);
        }
        break;
      }
      case MoqControlMessageType::kUnannounce: {
        const std::string remote_id =
            ExtractTrackIdFromNamespace(msg->track_namespace);
        if (msg->track_name.rfind("data/", 0) == 0) {
          const std::string label = msg->track_name.substr(5);
          const auto dc_it = label_to_dc_id_.find(label);
          if (dc_it != label_to_dc_id_.end()) {
            const int cid = dc_it->second;
            if (notified_remote_dc_peers_.erase({remote_id, cid}) > 0 &&
                observer_ != nullptr) {
              observer_->OnBackendDataChannelState(remote_id, cid, label,
                                                   RTC_DATA_CHANNEL_CLOSED);
            }
          }
          break;
        }
        if (observer_ != nullptr) {
          observer_->OnBackendRemoteTrackUnpublished(remote_id, remote_id);
        }
        break;
      }
      case MoqControlMessageType::kSubscribe: {
        MoqControlMessage ok = *msg;
        ok.type = MoqControlMessageType::kSubscribeOk;
        SendControlMessage(ok);
        if (msg->track_name.rfind("data/", 0) == 0) {
          break;
        }
        if (observer_ != nullptr) {
          const SpatialLayer req_layer =
              (msg->track_name == "video/low") ? SpatialLayer::kLow
                                               : SpatialLayer::kHigh;
          observer_->OnBackendForceKeyFrame(req_layer);
        }
        break;
      }
      case MoqControlMessageType::kKeyframeRequest: {
        if (observer_ != nullptr) {
          if (msg->track_name == "video/low") {
            observer_->OnBackendForceKeyFrame(SpatialLayer::kLow);
          } else if (msg->track_name == "video/high") {
            observer_->OnBackendForceKeyFrame(SpatialLayer::kHigh);
          } else {
            observer_->OnBackendForceKeyFrame(SpatialLayer::kHigh);
            if (config_.enable_simulcast) {
              observer_->OnBackendForceKeyFrame(SpatialLayer::kLow);
            }
          }
        }
        break;
      }
      default:
        break;
    }
  }
}

void MoqRelayBackend::HandleInboundUnidirectionalData(
    uint64_t stream_id,
    ArrayView<const uint8_t> data,
    bool fin) {
  auto& st = inbound_streams_[stream_id];
  if (!data.empty()) {
    st.buffer.insert(st.buffer.end(), data.begin(), data.end());
  }

  if (!st.header_parsed) {
    size_t hdr_consumed = 0;
    auto hdr = MoqSubgroupHeader::Decode(st.buffer, &hdr_consumed);
    if (!hdr.has_value()) {
      return;
    }
    st.header = *hdr;
    st.header_parsed = true;
    st.buffer.erase(st.buffer.begin(),
                    st.buffer.begin() + static_cast<ptrdiff_t>(hdr_consumed));
  }

  if (st.header.track_alias == kMoqUpstreamDataTrackAlias ||
      st.header.track_alias == kMoqDownstreamDataTrackAlias) {
    HandleInboundDataStreamObjects(&st);
    if (fin) {
      inbound_streams_.erase(stream_id);
    }
    return;
  }

  const Timestamp now = clock_->CurrentTime();
  while (!st.buffer.empty()) {
    size_t obj_consumed = 0;
    uint64_t obj_id = 0;
    auto frame =
        LocFramePackager::UnpackObject(st.buffer, &obj_consumed, &obj_id);
    if (!frame.has_value()) {
      break;
    }
    st.buffer.erase(st.buffer.begin(),
                    st.buffer.begin() + static_cast<ptrdiff_t>(obj_consumed));

    SubscribedTrackContext* sub_ctx = nullptr;
    const auto alias_it = alias_to_track_id_.find(st.header.track_alias);
    if (alias_it != alias_to_track_id_.end()) {
      const auto sub_it = subscriptions_.find(alias_it->second);
      if (sub_it != subscriptions_.end()) {
        sub_ctx = sub_it->second.get();
      }
    } else if ((st.header.track_alias == 1 || st.header.track_alias == 2) &&
               subscriptions_.size() == 1) {
      // 当未经过中间 Relay 重写上行轨道别名（1/2）而直接端到端连接时的回退匹配逻辑。
      sub_ctx = subscriptions_.begin()->second.get();
    }
    if (sub_ctx == nullptr) {
      continue;
    }

    const DataSize fsize = DataSize::Bytes(frame->data.size());
    if (sub_ctx->prev_recv_time.has_value() &&
        sub_ctx->prev_frame_size.has_value()) {
      sub_ctx->jitter_estimator.UpdateEstimate(
          now - *sub_ctx->prev_recv_time, fsize - *sub_ctx->prev_frame_size,
          fsize, false);
    }
    sub_ctx->prev_recv_time = now;
    sub_ctx->prev_frame_size = fsize;
    sub_ctx->vcm_timing.IncomingTimestamp(frame->rtp_timestamp, now);

    // 当订阅流在 Simulcast 高低空间层之间于关键帧边界发生切换时，清空旧层的帧参考历史，
    // 避免不同空间层独立递增的 frame_id 在回切时被误判为已解码重复帧。
    if (frame->dep.is_keyframe && sub_ctx->current_spatial_id.has_value() &&
        *sub_ctx->current_spatial_id != frame->dep.spatial_id) {
      sub_ctx->frame_buffer.Clear();
    }
    sub_ctx->current_spatial_id = frame->dep.spatial_id;

    AssembledRtpFrame rtp_frame;
    rtp_frame.rtp_timestamp = frame->rtp_timestamp;
    rtp_frame.received_time = now;
    rtp_frame.codec = frame->codec;
    rtp_frame.is_keyframe = frame->dep.is_keyframe;
    rtp_frame.dep = frame->dep;
    rtp_frame.annexb_bitstream = std::move(frame->data);

    sub_ctx->frame_buffer.InsertFrame(std::move(rtp_frame));
    DrainDecodableFrames(sub_ctx);
  }

  if (fin) {
    inbound_streams_.erase(stream_id);
  }
}

void MoqRelayBackend::HandleInboundDataStreamObjects(InboundStreamState* st) {
  if (st == nullptr || !config_.enable_datachannel) {
    return;
  }
  while (!st->buffer.empty()) {
    size_t obj_consumed = 0;
    auto obj = MoqDataPackager::UnpackObject(st->buffer, &obj_consumed);
    if (!obj.has_value()) {
      break;
    }
    st->buffer.erase(st->buffer.begin(),
                     st->buffer.begin() + static_cast<ptrdiff_t>(obj_consumed));
    if (obj->sender_peer_id == local_peer_id_) {
      continue;
    }

    const int cid = EnsureDataChannelForLabelOnWorker(obj->label, nullptr);
    const std::string peer =
        obj->sender_peer_id.empty() ? "remote_peer" : obj->sender_peer_id;
    if (obj->is_close) {
      if (notified_remote_dc_peers_.erase({peer, cid}) > 0 &&
          observer_ != nullptr) {
        observer_->OnBackendDataChannelState(peer, cid, obj->label,
                                             RTC_DATA_CHANNEL_CLOSED);
      }
      continue;
    }

    if (notified_remote_dc_peers_.emplace(peer, cid).second &&
        observer_ != nullptr) {
      observer_->OnBackendDataChannelState(peer, cid, obj->label,
                                           RTC_DATA_CHANNEL_OPEN);
    }
    if (observer_ != nullptr) {
      observer_->OnBackendDataChannelMessage(peer, cid, obj->is_binary,
                                             std::move(obj->payload));
    }
  }
}

void MoqRelayBackend::DrainDecodableFrames(SubscribedTrackContext* sub) {
  while (auto dec = sub->frame_buffer.ExtractNextDecodableFrame()) {
    ++frames_decoded_;
    EncodedVideoFrame out;
    out.data = std::move(dec->annexb_bitstream);
    out.capture_time = dec->received_time;
    out.rtp_timestamp = dec->rtp_timestamp;
    out.codec = dec->codec;
    out.layer = static_cast<SpatialLayer>(dec->dep.spatial_id);
    out.dep = dec->dep;
    if (observer_ != nullptr) {
      observer_->OnBackendDecodableFrame(sub->track_id, sub->track_id,
                                         std::move(out));
    }
  }
}

void MoqRelayBackend::OnPeriodicMaintenanceTick() {
  RTC_DCHECK_RUN_ON(&work_checker_);
  if (connected_ && quic_engine_) {
    const QuicCongestionSnapshot snap = quic_engine_->GetCongestionSnapshot();
    const TargetTransferRate rate = bwe_adapter_.ConvertSnapshot(snap);
    last_target_bps_ = static_cast<uint32_t>(rate.target_rate.bps());
    if (observer_ != nullptr) {
      observer_->OnBackendTargetTransferRate(rate);
    }

    const Timestamp now = clock_->CurrentTime();
    if (!ttl_data_streams_.empty()) {
      for (auto it = ttl_data_streams_.begin();
           it != ttl_data_streams_.end();) {
        if (now >= it->second) {
          if (snap.unsent_stream_bytes > DataSize::Zero()) {
            quic_engine_->ResetStream(it->first, 0x02);
          }
          it = ttl_data_streams_.erase(it);
        } else {
          ++it;
        }
      }
    }
    for (auto& [track_id, sub] : subscriptions_) {
      if (sub->frame_buffer.IsCorruptedOrStalled(now, TimeDelta::Millis(250))) {
        RequestRemoteKeyFrame(track_id);
      }
    }

    if (last_stats_time_.IsFinite() &&
        (now - last_stats_time_) >= TimeDelta::Millis(500)) {
      rtc_network_stats_t stats{};
      stats.rtt_ms = snap.smoothed_rtt.ms();
      stats.target_bitrate_bps = last_target_bps_;
      stats.pacing_bitrate_bps =
          static_cast<uint32_t>(snap.pacing_rate.bps());
      stats.uplink_packet_loss = static_cast<float>(rate.loss_rate_ratio);
      stats.packets_sent = snap.packets_sent;
      stats.frames_decoded = frames_decoded_;
      stats.keyframe_requests_sent = keyframe_requests_sent_;
      last_stats_time_ = now;
      if (observer_ != nullptr) {
        observer_->OnBackendStatsSnapshot(stats);
      }
    }
  }
  queues_->worker()->PostDelayedTask(
      SafeTask(safety_.flag(), [this]() { OnPeriodicMaintenanceTick(); }),
      TimeDelta::Millis(50));
}

// ======================= InMemoryMoqQuicPair 内存回环 QUIC 测试对 =======================

namespace {
class LoopbackQuicEndpoint final
    : public IMoqQuicEngine,
      public std::enable_shared_from_this<LoopbackQuicEndpoint> {
 public:
  LoopbackQuicEndpoint(TaskQueueBoost* net_q,
                       bool is_client,
                       DataRate bw,
                       TimeDelta rtt)
      : net_q_(net_q),
        next_bidi_id_(is_client ? 0 : 1),
        next_uni_id_(is_client ? 2 : 3),
        bw_(bw),
        rtt_(rtt) {}

  void BindPeer(std::weak_ptr<LoopbackQuicEndpoint> peer) {
    peer_ = std::move(peer);
  }

  void SetObserver(IMoqQuicEngineObserver* obs) override { observer_ = obs; }

  int Connect(const std::string& /*host*/,
              uint16_t /*port*/,
              const std::string& /*alpn*/) override {
    auto self = shared_from_this();
    net_q_->PostTask([self]() {
      if (self->observer_ != nullptr) {
        self->observer_->OnQuicConnected();
      }
      if (auto p = self->peer_.lock()) {
        if (p->observer_ != nullptr) {
          p->observer_->OnQuicConnected();
        }
      }
    });
    return 0;
  }

  void Close(uint64_t code) override {
    auto self = shared_from_this();
    net_q_->PostTask([self, code]() {
      if (self->observer_ != nullptr) {
        self->observer_->OnQuicDisconnected(static_cast<int>(code));
      }
    });
  }

  uint64_t OpenBidirectionalStream() override {
    const uint64_t id = next_bidi_id_.fetch_add(4);
    if (auto peer = peer_.lock()) {
      net_q_->PostTask([peer, id]() {
        if (peer->observer_ != nullptr) {
          peer->observer_->OnStreamOpened(id, false);
        }
      });
    }
    return id;
  }

  uint64_t OpenUnidirectionalStream(uint8_t /*prio*/,
                                    int64_t /*send_order*/) override {
    const uint64_t id = next_uni_id_.fetch_add(4);
    if (auto peer = peer_.lock()) {
      net_q_->PostTask([peer, id]() {
        if (peer->observer_ != nullptr) {
          peer->observer_->OnStreamOpened(id, true);
        }
      });
    }
    return id;
  }

  int WriteStream(uint64_t stream_id,
                  ArrayView<const uint8_t> data,
                  bool fin) override {
    auto peer = peer_.lock();
    if (!peer) {
      return -1;
    }
    std::vector<uint8_t> buf(data.begin(), data.end());
    pkts_sent_.fetch_add(1);
    net_q_->PostTask([peer, stream_id, b = std::move(buf), fin]() {
      if (peer->observer_ != nullptr) {
        peer->observer_->OnStreamData(stream_id, b, fin);
      }
    });
    return static_cast<int>(data.size());
  }

  void ResetStream(uint64_t stream_id, uint64_t app_error_code) override {
    if (auto peer = peer_.lock()) {
      net_q_->PostTask([peer, stream_id, app_error_code]() {
        if (peer->observer_ != nullptr) {
          peer->observer_->OnStreamReset(stream_id, app_error_code);
        }
      });
    }
  }

  QuicCongestionSnapshot GetCongestionSnapshot() const override {
    QuicCongestionSnapshot s;
    s.timestamp = Clock::GetRealTimeClock()->CurrentTime();
    s.smoothed_rtt = rtt_;
    s.min_rtt = rtt_;
    s.pacing_rate = bw_;
    s.cwnd = bw_ * (rtt_ * 2);
    s.packets_sent = pkts_sent_.load();
    return s;
  }

 private:
  TaskQueueBoost* net_q_;
  IMoqQuicEngineObserver* observer_ = nullptr;
  std::weak_ptr<LoopbackQuicEndpoint> peer_;
  std::atomic<uint64_t> next_bidi_id_;
  std::atomic<uint64_t> next_uni_id_;
  DataRate bw_;
  TimeDelta rtt_;
  std::atomic<uint64_t> pkts_sent_{0};
};
}  // namespace

std::pair<std::shared_ptr<IMoqQuicEngine>, std::shared_ptr<IMoqQuicEngine>>
InMemoryMoqQuicPair::CreateConnectedPair(TaskQueueBoost* network_queue,
                                         DataRate simulated_bandwidth,
                                         TimeDelta simulated_rtt) {
  auto a = std::make_shared<LoopbackQuicEndpoint>(
      network_queue, true, simulated_bandwidth, simulated_rtt);
  auto b = std::make_shared<LoopbackQuicEndpoint>(
      network_queue, false, simulated_bandwidth, simulated_rtt);
  a->BindPeer(b);
  b->BindPeer(a);
  return {a, b};
}

}  // namespace rtc