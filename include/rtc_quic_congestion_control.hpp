#ifndef INCLUDE_RTC_QUIC_CONGESTION_CONTROL_HPP_
#define INCLUDE_RTC_QUIC_CONGESTION_CONTROL_HPP_

// 支持热插拔的 QUIC v1 拥塞控制模块接口。
// 内置算法实现（均支持运行时无损状态迁移的热切换）：
//   - BBRv1   （RTC_QUIC_CC_BBR，BBRv1 拥塞控制）
//   - BBRv2   （RTC_QUIC_CC_BBR2，BBRv2 拥塞控制）
//   - CUBIC   （RTC_QUIC_CC_CUBIC，符合 RFC 9438 与 RFC 9406 HyStart++ 标准）
//   - Copa    （RTC_QUIC_CC_COPA，以延迟为目标的实时视频拥塞控制）
//   - NewReno （RTC_QUIC_CC_NEWRENO，符合 RFC 9002 第 7 节标准）
// 外部自定义拥塞控制器同样可通过实现 `IQuicCongestionController` 与
// `IQuicCongestionControllerFactory` 接口接入。

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "rtc_video_types.hpp"

namespace rtc {

struct QuicAckedPacket {
  uint64_t packet_number = 0;
  size_t bytes = 0;
  int64_t sent_time_us = 0;
  size_t prior_in_flight_bytes = 0;
  uint64_t delivered_bytes_at_send = 0;
  int64_t delivered_time_us_at_send = 0;
  int64_t first_sent_time_us_at_send = 0;
  bool is_app_limited = false;
};

struct QuicLostPacket {
  uint64_t packet_number = 0;
  size_t bytes = 0;
  int64_t sent_time_us = 0;
};

struct QuicRttSample {
  int64_t latest_rtt_us = 30'000;
  int64_t smoothed_rtt_us = 30'000;
  int64_t min_rtt_us = 30'000;
  int64_t rttvar_us = 15'000;
};

// 与传输层解耦的拥塞状态快照，用于在通话过程中热切换 QUIC 拥塞控制模块时
// 无缝迁移拥塞控制状态。
struct QuicCcMigrationState {
  size_t cwnd_bytes = 12'000;
  size_t ssthresh_bytes = 1024 * 1024;
  int64_t pacing_rate_bps = 0;
  int64_t bandwidth_estimate_bps = 0;
  int64_t min_rtt_us = 0;
  int64_t smoothed_rtt_us = 0;
  size_t bytes_in_flight = 0;
};

class RTC_SDK_API IQuicCongestionController {
 public:
  IQuicCongestionController() = default;
  virtual ~IQuicCongestionController() = default;

  IQuicCongestionController(const IQuicCongestionController&) = delete;
  IQuicCongestionController& operator=(const IQuicCongestionController&) =
      delete;

  virtual std::string_view Name() const = 0;

  virtual void OnPacketSent(int64_t now_us,
                            uint64_t packet_number,
                            size_t bytes,
                            bool in_flight,
                            size_t prior_in_flight_bytes) = 0;

  virtual void OnCongestionEvent(
      int64_t now_us,
      size_t prior_in_flight_bytes,
      size_t bytes_in_flight,
      const QuicRttSample& rtt,
      const std::vector<QuicAckedPacket>& acked_packets,
      const std::vector<QuicLostPacket>& lost_packets) = 0;

  virtual void OnPersistentCongestion(int64_t now_us) = 0;

  virtual size_t GetCongestionWindowBytes() const = 0;
  virtual int64_t GetPacingRateBps(int64_t smoothed_rtt_us) const = 0;
  virtual int64_t GetBandwidthEstimateBps() const = 0;
  virtual size_t GetSlowStartThresholdBytes() const = 0;

  virtual QuicCcMigrationState ExportMigrationState() const = 0;
  virtual void ImportMigrationState(const QuicCcMigrationState& state,
                                    int64_t now_us) = 0;
};

class RTC_SDK_API IQuicCongestionControllerFactory {
 public:
  IQuicCongestionControllerFactory() = default;
  virtual ~IQuicCongestionControllerFactory() = default;

  IQuicCongestionControllerFactory(const IQuicCongestionControllerFactory&) =
      delete;
  IQuicCongestionControllerFactory& operator=(
      const IQuicCongestionControllerFactory&) = delete;

  virtual std::unique_ptr<IQuicCongestionController> Create(
      size_t max_datagram_size) = 0;
};

RTC_SDK_API std::unique_ptr<IQuicCongestionController>
CreateBuiltinQuicCongestionController(rtc_quic_cc_algo_e algo,
                                      size_t max_datagram_size = 1200);

RTC_SDK_API std::shared_ptr<IQuicCongestionControllerFactory>
CreateBuiltinQuicCcFactory(rtc_quic_cc_algo_e algo);

}  // namespace rtc

#endif  // INCLUDE_RTC_QUIC_CONGESTION_CONTROL_HPP_
