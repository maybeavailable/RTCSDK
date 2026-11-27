#ifndef SRC_MODULES_RTP_RTCP_RTCP_PACKETS_H_
#define SRC_MODULES_RTP_RTCP_RTCP_PACKETS_H_

// 1:1 对标 libwebrtc/modules/rtp_rtcp/source/rtcp_packet/* 实现。
// 实现了 RFC 3550（SR/RR）、RFC 4585（通用 NACK PID+BLP、PLI）、
// RFC 5104（FIR）以及 TWCC TransportFeedback（FMT=15）。

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "api/array_view.h"
#include "api/units.h"

namespace rtc {

namespace rtcp_type {
constexpr uint8_t kSenderReport = 200;
constexpr uint8_t kReceiverReport = 201;
constexpr uint8_t kRtpfb = 205;
constexpr uint8_t kPsfb = 206;
}  // namespace rtcp_type

struct RtcpReportBlock {
  uint32_t source_ssrc = 0;
  uint8_t fraction_lost = 0;
  int32_t cumulative_lost = 0;
  uint32_t extended_high_seq_num = 0;
  uint32_t jitter = 0;
  uint32_t last_sr = 0;
  uint32_t delay_since_last_sr = 0;
};

class RtcpSenderReport {
 public:
  uint32_t sender_ssrc = 0;
  uint32_t ntp_seconds = 0;
  uint32_t ntp_fractions = 0;
  uint32_t rtp_timestamp = 0;
  uint32_t sender_packet_count = 0;
  uint32_t sender_octet_count = 0;
  std::vector<RtcpReportBlock> report_blocks;

  std::vector<uint8_t> Build() const;
  static std::optional<RtcpSenderReport> Parse(ArrayView<const uint8_t> payload,
                                               uint8_t report_count);

  constexpr uint32_t CompactNtp() const {
    return ((ntp_seconds & 0xFFFFu) << 16) | ((ntp_fractions >> 16) & 0xFFFFu);
  }
  static constexpr uint32_t CompactNtpFromTimestamp(Timestamp t) {
    const uint64_t us = static_cast<uint64_t>(t.us() >= 0 ? t.us() : 0);
    const uint32_t sec = static_cast<uint32_t>((us / 1'000'000ULL) & 0xFFFFULL);
    const uint32_t frac = static_cast<uint32_t>(
        ((us % 1'000'000ULL) * 65536ULL) / 1'000'000ULL);
    return (sec << 16) | (frac & 0xFFFFu);
  }
};

class RtcpReceiverReport {
 public:
  uint32_t sender_ssrc = 0;
  std::vector<RtcpReportBlock> report_blocks;

  std::vector<uint8_t> Build() const;
  static std::optional<RtcpReceiverReport> Parse(
      ArrayView<const uint8_t> payload,
      uint8_t report_count);
};

class RtcpNack {
 public:
  uint32_t sender_ssrc = 0;
  uint32_t media_ssrc = 0;
  std::vector<uint16_t> packet_ids;

  std::vector<uint8_t> Build() const;
  static std::optional<RtcpNack> Parse(ArrayView<const uint8_t> payload);
};

class RtcpPli {
 public:
  uint32_t sender_ssrc = 0;
  uint32_t media_ssrc = 0;

  std::vector<uint8_t> Build() const;
  static std::optional<RtcpPli> Parse(ArrayView<const uint8_t> payload);
};

class RtcpFir {
 public:
  struct Request {
    uint32_t ssrc = 0;
    uint8_t command_seq_num = 0;
  };

  uint32_t sender_ssrc = 0;
  uint32_t media_ssrc = 0;
  uint8_t command_seq_num = 0;
  std::vector<Request> requests;

  std::vector<uint8_t> Build() const;
  static std::optional<RtcpFir> Parse(ArrayView<const uint8_t> payload);
};

class RtcpTransportFeedback {
 public:
  struct ReceivedPacket {
    uint16_t sequence_number = 0;
    Timestamp receive_time = Timestamp::MinusInfinity();
  };

  struct PacketStatus {
    uint16_t sequence_number = 0;
    Timestamp receive_time = Timestamp::PlusInfinity();
  };

  uint32_t sender_ssrc = 0;
  uint32_t media_ssrc = 0;
  uint8_t feedback_seq = 0;

  void SetBase(uint16_t base_sequence, Timestamp ref_timestamp);
  bool AddReceivedPacket(uint16_t sequence_number, Timestamp timestamp);

  uint16_t base_seq_no() const { return base_seq_no_; }
  uint16_t num_seq_no() const { return num_seq_no_; }
  Timestamp BaseTime() const;
  const std::vector<ReceivedPacket>& received_packets() const {
    return received_packets_;
  }
  std::vector<PacketStatus> AllPacketStatuses() const;

  std::vector<uint8_t> Build() const;
  static std::optional<RtcpTransportFeedback> Parse(
      ArrayView<const uint8_t> payload);

 private:
  uint16_t base_seq_no_ = 0;
  uint16_t num_seq_no_ = 0;
  int32_t base_time_ticks_ = 0;
  int64_t full_base_ticks_ = 0;
  bool has_base_ = false;
  std::vector<ReceivedPacket> received_packets_;
};

struct ParsedCompoundRtcp {
  std::vector<RtcpSenderReport> sender_reports;
  std::vector<RtcpReceiverReport> receiver_reports;
  std::vector<RtcpNack> nacks;
  std::vector<RtcpPli> plis;
  std::vector<RtcpFir> firs;
  std::vector<RtcpTransportFeedback> transport_feedbacks;
};

ParsedCompoundRtcp ParseCompoundRtcp(ArrayView<const uint8_t> data);

}  // namespace rtc

#endif  // SRC_MODULES_RTP_RTCP_RTCP_PACKETS_H_
