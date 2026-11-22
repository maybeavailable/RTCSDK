#ifndef SRC_CALL_WEBRTC_P2P_BACKEND_H_
#define SRC_CALL_WEBRTC_P2P_BACKEND_H_

// 纯一对一 WebRTC P2P 会话后端（兼容 W3C 浏览器 RTCPeerConnection 标准），整合了：
//   - 完整 ICE（Host / STUN srflx / TURN relay / prflx）+ Trickle ICE
//   - 临时 ECDSA P-256 DTLS-SRTP 安全传输（`actpass` / `active` / `passive`）
//   - 兼容浏览器的 RFC 3264 / RFC 8829 Unified Plan SDP Offer/Answer 协商
//   - GoogCcNetworkController 拥塞控制 + TaskQueuePacedSender 平滑发送 + RTX 重传 + FlexFEC-03 前向纠错
//   - PacketBuffer -> NackModule2 -> ReferenceFinder -> FrameBuffer3 接收重组流水线

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "api/session_backend_interface.h"
#include "modules/congestion_controller/goog_cc/goog_cc_controller.h"
#include "modules/pacing/pacing_module.h"
#include "modules/rtp_rtcp/flexfec_codec.h"
#include "modules/rtp_rtcp/rtcp_packets.h"
#include "modules/rtp_rtcp/rtp_packet_history.h"
#include "modules/rtp_rtcp/rtp_video_packetizer.h"
#include "modules/video_coding/video_coding_module.h"
#include "p2p/stun_turn_ice.h"
#include "pc/dtls_srtp_transport.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"
#include "signaling/wss_signaling_client.h"

namespace rtc {

class WebRtcP2pBackend final : public ISessionBackend,
                               public DtlsSrtpObserver,
                               public PacingPacketSender,
                               public RtpPacketSinkInterface {
 public:
  WebRtcP2pBackend(Clock* clock,
                   SdkTaskQueues* queues,
                   const EngineConfig& config,
                   ISessionBackendObserver* observer);
  ~WebRtcP2pBackend() override;

  WebRtcP2pBackend(const WebRtcP2pBackend&) = delete;
  WebRtcP2pBackend& operator=(const WebRtcP2pBackend&) = delete;

  // ISessionBackend 接口重写：
  int StartSession(const std::string& room_id,
                   const std::string& local_peer_id) override;
  void StopSession() override;

  int SendEncodedFrame(EncodedVideoFrame frame) override;
  int SubscribeRemoteTrack(const std::string& track_id,
                           SpatialLayer preferred_layer) override;
  int SwitchSubscribedLayer(const std::string& track_id,
                            SpatialLayer preferred_layer) override;
  int UnsubscribeRemoteTrack(const std::string& track_id) override;
  int RequestRemoteKeyFrame(const std::string& track_id) override;

  int CreateLocalOffer(std::string* out_sdp) override;
  int SetRemoteDescription(std::string_view sdp_type,
                           std::string_view remote_sdp,
                           std::string* out_answer_sdp) override;
  int AddRemoteIceCandidate(std::string_view candidate_sdp) override;

  // 用于弱网环境下 P2P UDP 丢包仿真的测试钩子。
  void SetSimulatedRxDropRate(double drop_probability);

  // DtlsSrtpObserver 接口重写（在 `network` 队列上回调执行）：
  void OnDtlsSrtpHandshakeComplete() override;
  void OnDtlsSrtpError(std::string_view reason) override;
  void OnDecryptedRtpPacket(const RtpPacket& packet,
                            Timestamp receive_time) override;
  void OnDecryptedRtcpPacket(ArrayView<const uint8_t> compound_rtcp,
                             Timestamp receive_time) override;

  // PacingPacketSender 接口重写（在 `pacer` 队列上回调执行）：
  void SendPacedPacket(std::unique_ptr<RtpPacket> packet,
                       const PacedPacketInfo& cluster_info) override;
  std::vector<std::unique_ptr<RtpPacket>> GeneratePadding(
      DataSize target_size) override;

  // RtpPacketSinkInterface 接口重写（在 `worker` 队列上回调执行）：
  void OnRtpPacket(const RtpPacket& packet, Timestamp receive_time) override;

 private:
  struct OutboundStreamState {
    uint32_t media_ssrc = 0;
    uint32_t rtx_ssrc = 0;
    uint32_t flexfec_ssrc = 0;
    uint16_t next_rtp_seq = 1000;
    uint16_t next_rtx_seq = 20000;
    H264Packetizer h264_packetizer{1150};
    H265Packetizer h265_packetizer{1150};
    RtpPacketHistory history{2048};
    std::unique_ptr<FlexfecSender> flexfec;
  };

  struct InboundStreamState {
    std::string remote_peer_id = "remote_peer";
    std::string remote_track_id = "remote_video0";
    VideoCodec codec = VideoCodec::kH264;
    uint32_t media_ssrc = 0;
    uint32_t rtx_ssrc = 0;
    bool track_announced = false;

    PacketBuffer packet_buffer;
    NackModule2 nack_module;
    RtpFrameReferenceFinder ref_finder;
    FrameBuffer3 frame_buffer{256};
    VCMJitterEstimator jitter_estimator;
    VCMTiming vcm_timing;
    std::unique_ptr<FlexfecReceiver> flexfec_rx;

    uint32_t highest_seq_received = 0;
    uint64_t packets_received = 0;
    std::optional<Timestamp> prev_frame_arrival;
    std::optional<DataSize> prev_frame_size;
    Timestamp last_pli_sent = Timestamp::MinusInfinity();

    InboundStreamState(VideoCodec codec_in, Timestamp now, bool zero_playout)
        : codec(codec_in),
          packet_buffer(codec_in, 512),
          vcm_timing(now, zero_playout) {}
  };

  static std::string GenerateRandomToken(size_t length);
  static bool ParseIceServerUri(const IceServerConfig& cfg,
                                TurnServerSpec* out_spec);

  bool EnsureTransportInitializedOnSigQueue();
  PureVideoSdpDescription BuildLocalSdpOnSigQueue(
      const std::string& session_type,
      const std::string& dtls_setup,
      bool direction_send,
      bool direction_recv) const;
  bool ApplyRemoteSdpOnSigQueue(const PureVideoSdpDescription& remote_desc,
                                bool remote_is_offer,
                                std::string* out_answer_sdp);

  void OnSignalingConnected();
  void OnSignalingMessage(const std::string& json_text);
  void OnSignalingClosed(int code, const std::string& reason);

  void ApplyNetworkControlUpdate(const NetworkControlUpdate& update);
  void HandleMediaRtpPacketOnWorker(const RtpPacket& media_pkt,
                                    Timestamp receive_time,
                                    bool is_recovered = false);
  void OnWorkerPeriodicTick();
  void SendCompoundRtcpFeedback(Timestamp now);
  void SendPliForRemoteStream(Timestamp now);

  Clock* const clock_;
  SdkTaskQueues* const queues_;
  const EngineConfig config_;
  ISessionBackendObserver* const observer_;

  SequenceChecker sig_checker_;
  SequenceChecker work_checker_;

  std::string room_id_ = "p2p";
  std::string local_peer_id_ = "local_peer";
  std::string remote_peer_id_ = "remote_peer";
  bool transport_initialized_ = false;
  bool signaling_joined_ = false;
  bool offer_sent_ = false;
  std::atomic<bool> media_ready_{false};

  std::shared_ptr<DtlsCertificate> local_cert_;
  std::unique_ptr<IceTransportChannel> ice_;
  std::unique_ptr<DtlsSrtpTransport> dtls_srtp_;
  std::unique_ptr<BoostBeastSignalingClient> signaling_;

  // 已协商的 SDP 参数（通过 PostTask 从 signaling 队列同步至 worker 队列）。
  std::string negotiated_mid_ = "0";
  VideoCodec negotiated_codec_ = VideoCodec::kH264;
  uint8_t negotiated_video_pt_ = 96;
  uint8_t negotiated_rtx_pt_ = 97;
  uint8_t negotiated_flexfec_pt_ = 118;
  bool negotiated_has_rtx_ = true;
  bool negotiated_has_flexfec_ = true;
  RtpHeaderExtensionMap negotiated_ext_map_ =
      RtpHeaderExtensionMap::BrowserDefault();

  GoogCcNetworkController goog_cc_;
  TransportFeedbackAdapter twcc_adapter_;
  FecControllerDefault fec_controller_;
  std::unique_ptr<TaskQueuePacedSender> paced_sender_;

  OutboundStreamState outbound_;
  std::unique_ptr<InboundStreamState> inbound_;
  RtpDemuxer demuxer_;
  uint16_t next_twcc_seq_ = 1;

  std::vector<std::pair<uint16_t, Timestamp>> rx_twcc_records_;
  std::optional<uint16_t> next_expected_twcc_seq_;
  uint8_t twcc_fb_pkt_count_ = 0;
  Timestamp last_twcc_sent_ = Timestamp::MinusInfinity();
  Timestamp last_sr_rr_sent_ = Timestamp::MinusInfinity();

  std::atomic<uint64_t> stat_pkts_sent_{0};
  std::atomic<uint64_t> stat_pkts_rtx_{0};
  std::atomic<uint64_t> stat_fec_sent_{0};
  std::atomic<uint64_t> stat_frames_decoded_{0};
  std::atomic<uint64_t> stat_pli_sent_{0};
  DataRate latest_target_rate_ = DataRate::Zero();
  DataRate latest_pacing_rate_ = DataRate::Zero();
  double latest_uplink_loss_ = 0.0;

  ScopedTaskSafety sig_safety_;
  ScopedTaskSafety work_safety_;
  ScopedTaskSafety net_safety_;
};

}  // namespace rtc

#endif  // SRC_CALL_WEBRTC_P2P_BACKEND_H_