#ifndef SRC_MODULES_RTP_RTCP_RTP_PACKET_HISTORY_H_
#define SRC_MODULES_RTP_RTCP_RTP_PACKET_HISTORY_H_

// 1:1 对标 libwebrtc/modules/rtp_rtcp/source/rtp_packet_history.h 与
// RFC 4588 独立 SSRC 的 RTX 重传封装格式。

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>

#include "api/units.h"
#include "modules/rtp_rtcp/rtp_packet.h"
#include "rtc_base/seq_num_unwrapper.h"

namespace rtc {

class RtpPacketHistory {
 public:
  static constexpr size_t kMaxCapacity = 4096;

  explicit RtpPacketHistory(size_t number_to_store = 1024);

  RtpPacketHistory(const RtpPacketHistory&) = delete;
  RtpPacketHistory& operator=(const RtpPacketHistory&) = delete;
  RtpPacketHistory(RtpPacketHistory&&) noexcept = default;
  RtpPacketHistory& operator=(RtpPacketHistory&&) noexcept = default;

  void SetRtt(TimeDelta rtt);
  void PutRtpPacket(const RtpPacket& packet, Timestamp send_time);

  std::optional<RtpPacket> GetPacketAndMarkAsSent(uint16_t sequence_number,
                                                  Timestamp now);

  std::optional<RtpPacket> GetPayloadPaddingPacket(Timestamp now);

  void Clear();
  size_t Size() const { return packets_.size(); }

 private:
  struct StoredPacket {
    RtpPacket packet;
    int64_t unwrapped_seq = 0;
    Timestamp insert_time = Timestamp::MinusInfinity();
    Timestamp last_send_time = Timestamp::MinusInfinity();
    size_t times_retransmitted = 0;
  };

  void CullOldPackets(Timestamp now);

  size_t max_to_store_;
  TimeDelta rtt_ = TimeDelta::Millis(60);
  RtpSeqUnwrapper unwrapper_;
  std::deque<StoredPacket> packets_;
};

class RtxCodec {
 public:
  static RtpPacket BuildRtxPacket(const RtpPacket& original_media_packet,
                                  uint32_t rtx_ssrc,
                                  uint8_t rtx_payload_type,
                                  uint16_t rtx_sequence_number);

  static std::optional<RtpPacket> ParseRtxPacket(
      const RtpPacket& rtx_packet,
      uint32_t original_media_ssrc,
      uint8_t original_media_payload_type);
};

}  // namespace rtc

#endif  // SRC_MODULES_RTP_RTCP_RTP_PACKET_HISTORY_H_
