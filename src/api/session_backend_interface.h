#ifndef SRC_API_SESSION_BACKEND_INTERFACE_H_
#define SRC_API_SESSION_BACKEND_INTERFACE_H_

// 双模多态抽象层，将视频帧与 QoS 编排逻辑同底层传输协议
// （WebRtcP2pBackend 与 MoqRelayBackend）解耦。

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "api/array_view.h"
#include "api/network_types.h"
#include "api/video_types.h"
#include "rtc_video_engine.hpp"

namespace rtc {

class IMoqQuicEngineObserver {
 public:
  virtual ~IMoqQuicEngineObserver() = default;

  virtual void OnQuicConnected() = 0;
  virtual void OnQuicDisconnected(int error_code) = 0;
  virtual void OnStreamOpened(uint64_t stream_id, bool unidirectional) = 0;
  virtual void OnStreamData(uint64_t stream_id,
                            ArrayView<const uint8_t> data,
                            bool fin) = 0;
  virtual void OnStreamReset(uint64_t stream_id, uint64_t app_error_code) = 0;
};

struct QuicCongestionSnapshot {
  Timestamp timestamp = Timestamp::MinusInfinity();
  TimeDelta smoothed_rtt = TimeDelta::Millis(40);
  TimeDelta min_rtt = TimeDelta::Millis(30);
  DataSize cwnd = DataSize::Bytes(64 * 1024);
  DataSize bytes_in_flight = DataSize::Zero();
  DataSize unsent_stream_bytes = DataSize::Zero();
  DataRate pacing_rate = DataRate::KilobitsPerSec(1500);
  DataRate delivery_rate = DataRate::Zero();
  DataRate cc_bandwidth_estimate = DataRate::Zero();
  std::string_view active_cc_name = "BBRv1";
  double recent_loss_ratio = 0.0;
  uint64_t packets_sent = 0;
  uint64_t packets_lost = 0;
};

class IMoqQuicEngine {
 public:
  IMoqQuicEngine() = default;
  virtual ~IMoqQuicEngine() = default;

  IMoqQuicEngine(const IMoqQuicEngine&) = delete;
  IMoqQuicEngine& operator=(const IMoqQuicEngine&) = delete;

  virtual void SetObserver(IMoqQuicEngineObserver* observer) = 0;
  virtual int Connect(const std::string& host,
                      uint16_t port,
                      const std::string& alpn) = 0;
  virtual void Close(uint64_t app_error_code) = 0;

  virtual uint64_t OpenBidirectionalStream() = 0;
  virtual uint64_t OpenUnidirectionalStream(uint8_t publisher_priority,
                                            int64_t send_order) = 0;

  virtual int WriteStream(uint64_t stream_id,
                          ArrayView<const uint8_t> data,
                          bool fin) = 0;

  virtual void ResetStream(uint64_t stream_id, uint64_t app_error_code) = 0;

  virtual QuicCongestionSnapshot GetCongestionSnapshot() const = 0;

  virtual int SetCongestionController(
      std::unique_ptr<IQuicCongestionController> controller) {
    (void)controller;
    return RTC_OK;
  }
};

class ISessionBackendObserver {
 public:
  virtual ~ISessionBackendObserver() = default;

  virtual void OnBackendConnectionState(rtc_connection_state_e state,
                                        int reason_code) = 0;
  virtual void OnBackendTargetTransferRate(const TargetTransferRate& rate) = 0;
  virtual void OnBackendForceKeyFrame(SpatialLayer layer) = 0;

  virtual void OnBackendRemoteTrackPublished(const std::string& peer_id,
                                             const std::string& track_id,
                                             VideoCodec codec) = 0;
  virtual void OnBackendRemoteTrackUnpublished(const std::string& peer_id,
                                               const std::string& track_id) = 0;

  virtual void OnBackendDecodableFrame(const std::string& peer_id,
                                       const std::string& track_id,
                                       EncodedVideoFrame frame) = 0;

  virtual void OnBackendStatsSnapshot(const rtc_network_stats_t& stats) = 0;

  virtual void OnBackendLocalIceCandidate(const std::string& /*sdp_mid*/,
                                          int /*sdp_mline_index*/,
                                          const std::string& /*candidate*/) {}
};

class ISessionBackend {
 public:
  ISessionBackend() = default;
  virtual ~ISessionBackend() = default;

  ISessionBackend(const ISessionBackend&) = delete;
  ISessionBackend& operator=(const ISessionBackend&) = delete;

  virtual int StartSession(const std::string& room_id,
                           const std::string& local_peer_id) = 0;
  virtual void StopSession() = 0;

  virtual int SendEncodedFrame(EncodedVideoFrame frame) = 0;
  virtual void SetLayerActive(SpatialLayer /*layer*/, bool /*active*/) {}

  virtual int SubscribeRemoteTrack(const std::string& track_id,
                                   SpatialLayer preferred_layer) = 0;
  virtual int SwitchSubscribedLayer(const std::string& track_id,
                                    SpatialLayer preferred_layer) = 0;
  virtual int UnsubscribeRemoteTrack(const std::string& track_id) = 0;
  virtual int RequestRemoteKeyFrame(const std::string& track_id) = 0;

  virtual int SetQuicCongestionControl(rtc_quic_cc_algo_e /*algo*/) {
    return RTC_ERR_PROTOCOL;
  }
  virtual int SetCustomQuicCongestionController(
      std::shared_ptr<IQuicCongestionControllerFactory> /*factory*/) {
    return RTC_ERR_PROTOCOL;
  }

  virtual int CreateLocalOffer(std::string* /*out_sdp*/) {
    return RTC_ERR_PROTOCOL;
  }
  virtual int SetRemoteDescription(std::string_view /*sdp_type*/,
                                   std::string_view /*remote_sdp*/,
                                   std::string* /*out_answer_sdp*/) {
    return RTC_ERR_PROTOCOL;
  }
  virtual int AddRemoteIceCandidate(std::string_view /*candidate_sdp*/) {
    return RTC_ERR_PROTOCOL;
  }
};

}  // namespace rtc

#endif  // SRC_API_SESSION_BACKEND_INTERFACE_H_