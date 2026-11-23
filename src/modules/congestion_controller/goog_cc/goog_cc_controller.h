#ifndef SRC_MODULES_CONGESTION_CONTROLLER_GOOG_CC_GOOG_CC_CONTROLLER_H_
#define SRC_MODULES_CONGESTION_CONTROLLER_GOOG_CC_GOOG_CC_CONTROLLER_H_

// 1:1 对标 libwebrtc/modules/congestion_controller/goog_cc/ 实现：
//   1. InterArrivalDelta（包组到达间隔差值计算器）
//   2. TrendlineEstimator + 自适应过载检测器（Adaptive OveruseDetector）
//   3. AckedBitrateEstimator（已确认码率估计器）+ AlrDetector（应用受限区域检测器）
//   4. AimdRateControl（AIMD 码率控制器）
//   5. SendSideBandwidthEstimation（发送端带宽估计）
//   6. ProbeController（带宽探测控制器）
//   7. TransportFeedbackAdapter（传输反馈适配器）+ GoogCcNetworkController（GoogCC 网络控制器）

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <vector>

#include "api/network_types.h"
#include "api/units.h"
#include "modules/pacing/pacing_module.h"
#include "modules/rtp_rtcp/rtcp_packets.h"
#include "rtc_base/seq_num_unwrapper.h"

namespace rtc {

class InterArrivalDelta {
 public:
  explicit InterArrivalDelta(
      TimeDelta send_time_group_length = TimeDelta::Millis(5));

  bool ComputeDeltas(Timestamp send_time,
                     Timestamp arrival_time,
                     Timestamp system_time,
                     size_t packet_size,
                     TimeDelta* send_time_delta,
                     TimeDelta* arrival_time_delta,
                     int* packet_size_delta);
  void Reset();

 private:
  struct SendTimeGroup {
    size_t size = 0;
    Timestamp first_send_time = Timestamp::MinusInfinity();
    Timestamp send_time = Timestamp::MinusInfinity();
    Timestamp first_arrival = Timestamp::MinusInfinity();
    Timestamp complete_time = Timestamp::MinusInfinity();
    Timestamp last_system_time = Timestamp::MinusInfinity();
  };

  bool NewTimestampGroup(Timestamp arrival_time, Timestamp send_time) const;
  bool BelongsToBurst(Timestamp arrival_time, Timestamp send_time) const;

  const TimeDelta send_time_group_length_;
  SendTimeGroup current_timestamp_group_;
  SendTimeGroup prev_timestamp_group_;
  int num_consecutive_reordered_packets_ = 0;
};

class TrendlineEstimator {
 public:
  explicit TrendlineEstimator(size_t window_size = 20,
                              double smoothing_coef = 0.9,
                              double threshold_gain = 4.0);

  void Update(TimeDelta recv_delta,
              TimeDelta send_delta,
              Timestamp send_time,
              Timestamp arrival_time,
              size_t packet_size,
              bool calculated_deltas);

  BandwidthUsage State() const { return hypothesis_; }
  double prev_modified_trend() const { return prev_trend_ * threshold_gain_; }
  double threshold() const { return threshold_; }

 private:
  struct PacketTiming {
    double arrival_time_ms;
    double smoothed_delay_ms;
    double raw_delay_ms;
  };

  std::optional<double> LinearFitSlope(
      const std::deque<PacketTiming>& packets) const;
  void Detect(double trend, double ts_delta, Timestamp now);
  void UpdateThreshold(double modified_trend, Timestamp now);

  const size_t window_size_;
  const double smoothing_coef_;
  const double threshold_gain_;

  int num_of_deltas_ = 0;
  Timestamp first_arrival_time_ = Timestamp::MinusInfinity();
  double accumulated_delay_ms_ = 0.0;
  double smoothed_delay_ms_ = 0.0;
  std::deque<PacketTiming> delay_hist_;

  double k_up_ = 0.0087;
  double k_down_ = 0.039;
  double overusing_time_threshold_ms_ = 10.0;
  double threshold_ = 12.5;
  Timestamp last_update_time_ = Timestamp::MinusInfinity();
  double prev_trend_ = 0.0;
  double time_over_using_ms_ = -1.0;
  int overuse_counter_ = 0;
  BandwidthUsage hypothesis_ = BandwidthUsage::kBwNormal;
};

class AckedBitrateEstimator {
 public:
  AckedBitrateEstimator() = default;

  void IncomingPacketFeedbackVector(
      const std::vector<PacketResult>& packet_feedback_vector);
  std::optional<DataRate> bitrate() const;
  std::optional<DataRate> PeekRate() const;
  void set_alr_ended_time(Timestamp alr_ended_time) {
    alr_ended_time_ = alr_ended_time;
  }
  void set_alr(bool in_alr) { in_alr_ = in_alr; }

 private:
  void UpdateWindow(Timestamp now, DataSize bytes, int rate_window_ms);

  Timestamp alr_ended_time_ = Timestamp::MinusInfinity();
  bool in_alr_ = false;
  int sum_bytes_ = 0;
  Timestamp current_window_ = Timestamp::MinusInfinity();
  Timestamp prev_time_ = Timestamp::MinusInfinity();
  float bitrate_estimate_kbps_ = -1.0f;
  float bitrate_estimate_var_ = 50.0f;
};

class AlrDetector {
 public:
  AlrDetector();

  void OnBytesSent(size_t bytes_sent, Timestamp send_time);
  void SetEstimatedBitrate(DataRate bitrate);
  std::optional<Timestamp> GetApplicationLimitedRegionStartTime() const {
    return alr_started_time_;
  }

 private:
  IntervalBudget alr_budget_;
  Timestamp last_send_time_ = Timestamp::MinusInfinity();
  std::optional<Timestamp> alr_started_time_;
};

class AimdRateControl {
 public:
  AimdRateControl(DataRate min_bitrate,
                  DataRate max_bitrate,
                  DataRate start_bitrate);

  void SetStartBitrate(DataRate start_bitrate);
  void SetEstimate(DataRate bitrate, Timestamp at_time);
  void SetCapacityEstimate(DataRate link_capacity);
  void SetMinMaxBitrate(DataRate min_bitrate, DataRate max_bitrate);
  void set_rtt(TimeDelta rtt) { rtt_ = rtt; }

  bool TimeToReduceFurther(Timestamp at_time,
                           DataRate estimated_throughput) const;
  Timestamp LastDecreaseTime() const { return time_last_bitrate_decrease_; }
  DataRate LatestEstimate() const { return current_bitrate_; }

  DataRate Update(BandwidthUsage bw_state,
                  std::optional<DataRate> estimated_throughput,
                  Timestamp at_time);

 private:
  enum class RateControlState { kRcHold, kRcIncrease, kRcDecrease };

  DataRate MultiplicativeRateIncrease(Timestamp at_time,
                                      Timestamp last_time,
                                      DataRate current_bitrate) const;
  DataRate AdditiveRateIncrease(Timestamp at_time, Timestamp last_time) const;
  void ChangeState(BandwidthUsage bw_state, Timestamp at_time);

  DataRate min_configured_bitrate_;
  DataRate max_configured_bitrate_;
  DataRate current_bitrate_;
  std::optional<DataRate> link_capacity_estimate_kbps_;
  double var_max_bitrate_kbps_ = 0.4;
  RateControlState rate_control_state_ = RateControlState::kRcHold;
  Timestamp time_last_bitrate_change_ = Timestamp::MinusInfinity();
  Timestamp time_last_bitrate_decrease_ = Timestamp::MinusInfinity();
  Timestamp time_first_throughput_estimate_ = Timestamp::MinusInfinity();
  bool bitrate_is_initialized_ = false;
  double beta_ = 0.85;
  TimeDelta rtt_ = TimeDelta::Millis(60);
};

class SendSideBandwidthEstimation {
 public:
  SendSideBandwidthEstimation(DataRate min_bitrate,
                              DataRate max_bitrate,
                              DataRate start_bitrate);

  void UpdateReceiverReport(Timestamp at_time,
                            uint8_t fraction_lost,
                            TimeDelta rtt);
  void UpdatePacketsLost(int64_t packets_lost,
                         int64_t number_of_packets,
                         Timestamp at_time);
  void UpdateDelayBasedEstimate(Timestamp at_time, DataRate bitrate);
  void ApplyProbeBitrate(Timestamp at_time, DataRate bitrate);
  void SetAcknowledgedRate(std::optional<DataRate> acked_rate,
                           Timestamp at_time);
  void UpdateEstimate(Timestamp at_time);

  DataRate target_rate() const { return current_target_; }
  uint8_t fraction_loss() const { return last_fraction_loss_; }
  double loss_ratio() const {
    return static_cast<double>(last_fraction_loss_) / 256.0;
  }
  TimeDelta rtt() const { return last_rtt_; }

 private:
  DataRate min_bitrate_;
  DataRate max_bitrate_;
  DataRate current_target_;
  DataRate delay_based_limit_ = DataRate::Infinity();
  std::optional<DataRate> acknowledged_rate_;

  uint8_t last_fraction_loss_ = 0;
  bool is_loss_limited_ = false;
  TimeDelta last_rtt_ = TimeDelta::Millis(50);
  Timestamp last_loss_feedback_ = Timestamp::MinusInfinity();
  Timestamp last_loss_packet_report_ = Timestamp::MinusInfinity();
  Timestamp time_last_decrease_ = Timestamp::MinusInfinity();
  Timestamp time_last_loss_ramp_ = Timestamp::MinusInfinity();
  int64_t lost_packets_since_last_loss_update_ = 0;
  int64_t expected_packets_since_last_loss_update_ = 0;
};

class ProbeBitrateEstimator {
 public:
  ProbeBitrateEstimator() = default;

  std::optional<DataRate> HandleProbeAndEstimateBitrate(
      const PacketResult& packet_feedback);
  std::optional<DataRate> FetchAndResetLastEstimatedBitrate();
  bool last_probe_saturated() const { return last_probe_saturated_; }

 private:
  struct AggregatedCluster {
    int num_probes = 0;
    Timestamp first_send = Timestamp::PlusInfinity();
    Timestamp last_send = Timestamp::MinusInfinity();
    Timestamp first_receive = Timestamp::PlusInfinity();
    Timestamp last_receive = Timestamp::MinusInfinity();
    DataSize size_last_send = DataSize::Zero();
    DataSize size_first_receive = DataSize::Zero();
    DataSize size_total = DataSize::Zero();
  };

  void EraseOldClusters(Timestamp timestamp);

  std::map<int, AggregatedCluster> clusters_;
  std::optional<DataRate> estimated_data_rate_;
  bool last_probe_saturated_ = false;
};

class ProbeController {
 public:
  ProbeController() = default;

  std::vector<ProbeClusterConfig> SetBitrates(DataRate min_bitrate,
                                              DataRate start_bitrate,
                                              DataRate max_bitrate,
                                              Timestamp at_time);
  std::vector<ProbeClusterConfig> SetEstimatedBitrate(
      DataRate bitrate,
      bool bwe_limited_due_to_packet_loss,
      Timestamp at_time);
  std::vector<ProbeClusterConfig> RequestProbe(Timestamp at_time);
  void set_alr_start_time(std::optional<Timestamp> alr_start_time) {
    alr_start_time_ = alr_start_time;
  }
  std::vector<ProbeClusterConfig> Process(Timestamp at_time);

 private:
  enum class State {
    kInit,
    kWaitingForProbingResult,
    kProbingComplete,
  };

  std::vector<ProbeClusterConfig> InitiateProbing(
      Timestamp now,
      std::vector<DataRate> bitrates_to_probe,
      bool probe_further);

  State state_ = State::kInit;
  DataRate start_bitrate_ = DataRate::Zero();
  DataRate max_bitrate_ = DataRate::Infinity();
  DataRate estimated_bitrate_ = DataRate::Zero();
  DataRate min_bitrate_to_probe_further_ = DataRate::Infinity();
  Timestamp time_last_probing_initiated_ = Timestamp::MinusInfinity();
  std::optional<Timestamp> alr_start_time_;
  int32_t next_probe_cluster_id_ = 1;
};

class TransportFeedbackAdapter {
 public:
  void AddPacket(uint16_t transport_seq_num,
                 DataSize packet_size,
                 const PacedPacketInfo& pacing_info,
                 Timestamp creation_time);
  std::optional<SentPacket> ProcessSentPacket(uint16_t transport_seq_num,
                                              Timestamp send_time);
  std::optional<TransportPacketsFeedback> ProcessTransportFeedback(
      const RtcpTransportFeedback& feedback,
      Timestamp feedback_receive_time);
  void CullExpiredInFlight(Timestamp now);

  DataSize outstanding_data() const { return in_flight_bytes_; }

 private:
  struct PacketFeedbackRecord {
    SentPacket sent;
    bool has_been_acked = false;
  };

  RtpSeqUnwrapper seq_unwrapper_;
  std::optional<int64_t> last_unwrapped_ref_ticks_;
  int64_t last_ack_seq_num_ = -1;
  std::map<int64_t, PacketFeedbackRecord> history_;
  DataSize in_flight_bytes_ = DataSize::Zero();
};

struct GoogCcConfig {
  DataRate min_bitrate = DataRate::KilobitsPerSec(150);
  DataRate start_bitrate = DataRate::KilobitsPerSec(1500);
  DataRate max_bitrate = DataRate::KilobitsPerSec(6000);
  double pacing_factor = 1.1;
};

class GoogCcNetworkController {
 public:
  explicit GoogCcNetworkController(const GoogCcConfig& config);

  GoogCcNetworkController(const GoogCcNetworkController&) = delete;
  GoogCcNetworkController& operator=(const GoogCcNetworkController&) = delete;

  NetworkControlUpdate OnNetworkAvailability(Timestamp at_time,
                                             bool network_available);
  NetworkControlUpdate OnSentPacket(const SentPacket& sent_packet);
  NetworkControlUpdate OnTransportPacketsFeedback(
      const TransportPacketsFeedback& report);
  NetworkControlUpdate OnReceiverReport(Timestamp at_time,
                                        uint8_t fraction_lost,
                                        TimeDelta rtt);
  NetworkControlUpdate OnProcessInterval(Timestamp at_time);

  DataRate TargetRate() const { return bandwidth_estimation_.target_rate(); }
  BandwidthUsage DetectorState() const { return trendline_estimator_.State(); }

 private:
  void MaybeTriggerOnNetworkChanged(NetworkControlUpdate* update,
                                    Timestamp at_time);
  PacerConfig GetPacerRates(Timestamp at_time) const;

  GoogCcConfig config_;
  InterArrivalDelta inter_arrival_delta_;
  TrendlineEstimator trendline_estimator_;
  AckedBitrateEstimator acked_bitrate_estimator_;
  AlrDetector alr_detector_;
  AimdRateControl delay_based_bwe_;
  SendSideBandwidthEstimation bandwidth_estimation_;
  ProbeBitrateEstimator probe_bitrate_estimator_;
  ProbeController probe_controller_;

  bool previously_in_alr_ = false;
  BandwidthUsage prev_detector_state_ = BandwidthUsage::kBwNormal;
  Timestamp last_probe_result_time_ = Timestamp::MinusInfinity();
  DataRate last_reported_target_rate_ = DataRate::Zero();
  uint8_t last_reported_fraction_loss_ = 0;
  TimeDelta last_reported_rtt_ = TimeDelta::Zero();
};

}  // namespace rtc

#endif  // SRC_MODULES_CONGESTION_CONTROLLER_GOOG_CC_GOOG_CC_CONTROLLER_H_
