#ifndef SRC_API_NETWORK_TYPES_H_
#define SRC_API_NETWORK_TYPES_H_

// 1:1 参照 libwebrtc/api/transport/network_types.h 建模设计。

#include <cstdint>
#include <optional>
#include <vector>

#include "api/units.h"

namespace rtc {

enum class BandwidthUsage {
  kBwNormal = 0,
  kBwUnderusing = 1,
  kBwOverusing = 2,
};

enum class RtpPacketMediaType : uint8_t {
  kControlHighPriority = 0,
  kRetransmission = 1,
  kVideoKeyFrame = 2,
  kVideoDelta = 3,
  kForwardErrorCorrection = 4,
  kPadding = 5,
};

struct PacedPacketInfo {
  static constexpr int kNotAProbe = -1;

  int probe_cluster_id = kNotAProbe;
  int probe_cluster_min_probes = -1;
  int probe_cluster_min_bytes = -1;
  DataRate send_bitrate = DataRate::Zero();

  bool operator==(const PacedPacketInfo& o) const {
    return probe_cluster_id == o.probe_cluster_id;
  }
};

struct SentPacket {
  Timestamp send_time = Timestamp::MinusInfinity();
  DataSize size = DataSize::Zero();
  DataSize prior_unacked_data = DataSize::Zero();
  PacedPacketInfo pacing_info;
  int64_t sequence_number = -1;
  DataSize data_in_flight = DataSize::Zero();
  bool is_retransmission = false;
};

struct PacketResult {
  SentPacket sent_packet;
  Timestamp receive_time = Timestamp::PlusInfinity();  // PlusInfinity 表示数据包丢失

  bool IsReceived() const { return receive_time.IsFinite(); }
};

struct TransportPacketsFeedback {
  Timestamp feedback_time = Timestamp::MinusInfinity();
  Timestamp first_unacked_send_time = Timestamp::MinusInfinity();
  DataSize data_in_flight = DataSize::Zero();
  DataSize prior_in_flight = DataSize::Zero();
  std::vector<PacketResult> packet_feedbacks;

  std::vector<PacketResult> ReceivedWithSendInfo() const {
    std::vector<PacketResult> res;
    res.reserve(packet_feedbacks.size());
    for (const auto& pkt : packet_feedbacks) {
      if (pkt.IsReceived() && pkt.sent_packet.send_time.IsFinite()) {
        res.push_back(pkt);
      }
    }
    return res;
  }
};

struct NetworkStateEstimate {
  Timestamp update_time = Timestamp::MinusInfinity();
  DataRate link_capacity = DataRate::Zero();
  DataRate link_capacity_lower = DataRate::Zero();
  DataRate link_capacity_upper = DataRate::Zero();
  TimeDelta pre_link_buffer_delay = TimeDelta::Zero();
  double cross_traffic_ratio = 0.0;
};

struct TargetTransferRate {
  Timestamp at_time = Timestamp::MinusInfinity();
  NetworkStateEstimate network_estimate;
  DataRate target_rate = DataRate::Zero();
  DataRate stable_target_rate = DataRate::Zero();
  TimeDelta rtt = TimeDelta::Millis(50);
  double loss_rate_ratio = 0.0;
};

struct PacerConfig {
  Timestamp at_time = Timestamp::MinusInfinity();
  TimeDelta time_window = TimeDelta::Seconds(1);
  DataSize data_window = DataSize::Zero();
  DataSize pad_window = DataSize::Zero();

  DataRate data_rate() const { return data_window / time_window; }
  DataRate pad_rate() const { return pad_window / time_window; }
};

struct ProbeClusterConfig {
  Timestamp at_time = Timestamp::MinusInfinity();
  DataRate target_data_rate = DataRate::Zero();
  TimeDelta target_duration = TimeDelta::Millis(15);
  int32_t target_probe_count = 5;
  int32_t id = 0;
};

struct NetworkControlUpdate {
  std::optional<DataSize> congestion_window;
  std::optional<PacerConfig> pacer_config;
  std::vector<ProbeClusterConfig> probe_cluster_configs;
  std::optional<TargetTransferRate> target_rate;

  bool has_updates() const {
    return congestion_window.has_value() || pacer_config.has_value() ||
           !probe_cluster_configs.empty() || target_rate.has_value();
  }
};

}  // namespace rtc

#endif  // SRC_API_NETWORK_TYPES_H_
