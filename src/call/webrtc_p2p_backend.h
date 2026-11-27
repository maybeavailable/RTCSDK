#ifndef SRC_CALL_WEBRTC_P2P_BACKEND_H_
#define SRC_CALL_WEBRTC_P2P_BACKEND_H_

// 纯一对一 WebRTC P2P 会话后端（兼容 W3C 浏览器 RTCPeerConnection 标准），整合了：
//   - 完整 ICE（Host / STUN srflx / TURN relay / prflx）+ Trickle ICE
//   - 临时 ECDSA P-256 DTLS-SRTP 安全传输（`actpass` / `active` / `passive`）
//   - 兼容浏览器的 RFC 3264 / RFC 8829 Unified Plan SDP Offer/Answer 协商
//   - GoogCcNetworkController 拥塞控制 + TaskQueuePacedSender 平滑发送 + RTX 重传 + RFC 8627 FlexFEC 前向纠错
//   - PacketBuffer -> NackModule2 -> ReferenceFinder -> FrameBuffer3 接收重组流水线

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
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
#include "pc/sctp_data_channel.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"
#include "signaling/wss_signaling_client.h"

namespace rtc {

class WebRtcP2pBackend final : public ISessionBackend,
                               public DtlsSrtpObserver,
                               public SctpDataChannelObserver,
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

  int CreateDataChannel(const DataChannelConfig& config) override;
  int SendData(int channel_id,
               ArrayView<const uint8_t> payload,
               bool is_binary) override;
  int CloseDataChannel(int channel_id) override;

  // 用于弱网环境下 P2P UDP 丢包仿真的测试钩子。
  void SetSimulatedRxDropRate(double drop_probability);

  // DtlsSrtpObserver 接口重写（在 `network` 队列上回调执行）：
  void OnDtlsSrtpHandshakeComplete() override;
  void OnDtlsSrtpError(std::string_view reason) override;
  void OnIceTransportState(IceTransportState state) override;
  void OnDecryptedRtpPacket(const RtpPacket& packet,
                            Timestamp receive_time) override;
  void OnDecryptedRtcpPacket(ArrayView<const uint8_t> compound_rtcp,
                             Timestamp receive_time) override;
  void OnDtlsApplicationData(ArrayView<const uint8_t> payload,
                             Timestamp receive_time) override;

  // SctpDataChannelObserver 接口重写（在 `worker` 队列上回调执行）：
  bool SendSctpPacketOverDtls(ArrayView<const uint8_t> packet) override;
  void OnSctpDataChannelState(int channel_id,
                              const std::string& label,
                              rtc_data_channel_state_e state) override;
  void OnSctpDataChannelMessage(int channel_id,
                                bool is_binary,
                                std::vector<uint8_t> payload) override;

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
    std::atomic<uint16_t> next_rtx_seq{20000};
    H264Packetizer h264_packetizer{1150};
    H265Packetizer h265_packetizer{1150};
    RtpPacketHistory history{2048};
    std::unique_ptr<FlexfecSender> flexfec;
    std::string flexfec_mid = "0";
  };

  struct InboundStreamState {
    static constexpr size_t kPaddingSeqRingSize = 512;

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

    std::array<std::pair<bool, uint16_t>, kPaddingSeqRingSize>
        padding_seq_ring{};
    std::optional<uint16_t> last_continuous_seq_end;
    std::deque<AssembledRtpFrame> pending_assembled_frames;

    RtpTimestampUnwrapper rtp_ts_unwrapper;
    std::optional<int64_t> base_unwrapped_rtp_ts;
    Timestamp base_capture_time = Timestamp::MinusInfinity();
    int64_t last_emitted_capture_us = 0;

    uint32_t highest_seq_received = 0;
    uint64_t packets_received = 0;
    uint64_t wire_media_packets_received = 0;
    RtpSeqUnwrapper wire_seq_unwrapper;
    std::optional<int64_t> max_wire_unwrapped_seq;
    int64_t prev_rr_max_seq = -1;
    uint64_t prev_rr_pkts = 0;
    float latest_downlink_loss = 0.0f;
    std::optional<Timestamp> prev_frame_arrival;
    std::optional<DataSize> prev_frame_size;
    Timestamp last_pli_sent = Timestamp::MinusInfinity();

    InboundStreamState(VideoCodec codec_in, Timestamp now, bool zero_playout)
        : codec(codec_in),
          packet_buffer(codec_in, 512),
          vcm_timing(now, zero_playout) {}

    bool IsPaddingSeq(uint16_t seq) const {
      const auto& slot = padding_seq_ring[seq % kPaddingSeqRingSize];
      return slot.first && slot.second == seq;
    }

    void MarkPaddingSeq(uint16_t seq) {
      padding_seq_ring[seq % kPaddingSeqRingSize] = {true, seq};
    }

    void ClearPaddingSeq(uint16_t seq) {
      auto& slot = padding_seq_ring[seq % kPaddingSeqRingSize];
      if (slot.first && slot.second == seq) {
        slot = {false, 0};
      }
    }
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

  void ConnectSignalingOnSigQueue();
  void OnSignalingConnected();
  void OnSignalingMessage(const std::string& json_text);
  void OnSignalingClosed(int code, const std::string& reason);

  void ApplyNetworkControlUpdate(const NetworkControlUpdate& update);
  void HandleMediaPaddingPacketOnWorker(uint16_t seq_num,
                                        uint32_t ssrc,
                                        Timestamp receive_time,
                                        bool is_recovered);
  void DrainPendingAssembledFramesOnWorker();
  void DrainDecodableFramesOnWorker();
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
  std::string negotiated_remote_track_id_;
  bool has_paired_remote_peer_ = false;
  bool session_active_ = false;
  bool transport_initialized_ = false;
  bool signaling_joined_ = false;
  bool offer_sent_ = false;
  uint32_t sig_reconnect_attempts_ = 0;
  uint64_t sig_conn_gen_ = 0;
  Timestamp sig_connected_at_ = Timestamp::MinusInfinity();
  std::atomic<bool> media_ready_{false};
  std::atomic<bool> video_muted_{false};

  std::shared_ptr<DtlsCertificate> local_cert_;
  std::unique_ptr<IceTransportChannel> ice_;
  std::unique_ptr<DtlsSrtpTransport> dtls_srtp_;
  std::unique_ptr<BoostBeastSignalingClient> signaling_;

  // 已协商的 SDP 参数（signaling 队列归属，通过 PostTask/原子变量同步至 worker 与 pacer 队列）。
  std::string negotiated_mid_ = "0";
  std::string negotiated_data_mid_ = "1";
  bool negotiated_has_video_ = true;
  bool negotiated_has_datachannel_ = true;
  uint16_t local_sctp_port_ = 5000;
  uint16_t remote_sctp_port_ = 5000;
  std::vector<SdpMediaKind> negotiated_m_order_;
  std::vector<RejectedMediaDesc> negotiated_rejected_m_;
  VideoCodec negotiated_codec_ = VideoCodec::kH264;
  std::string negotiated_h264_profile_level_id_ = "42e01f";
  DtlsRole negotiated_dtls_role_ = DtlsRole::kClient;
  std::string negotiated_remote_fp_;
  std::atomic<uint8_t> negotiated_video_pt_{96};
  std::atomic<uint8_t> negotiated_rtx_pt_{97};
  std::atomic<bool> pacer_has_rtx_{true};
  std::atomic<int64_t> cached_ice_rtt_us_{30'000};
  uint8_t negotiated_flexfec_pt_ = 118;
  bool negotiated_has_rtx_ = true;
  bool negotiated_has_flexfec_ = true;
  std::string negotiated_flexfec_subtype_ = "flexfec";
  uint32_t negotiated_flexfec_rw_us_ = 10'000'000;
  RtpHeaderExtensionMap negotiated_ext_map_ =
      RtpHeaderExtensionMap::BrowserDefault();
  mutable std::mutex pacer_ext_mu_;
  RtpHeaderExtensionMap pacer_ext_map_ =
      RtpHeaderExtensionMap::BrowserDefault();

  // worker 队列专属协商状态副本（消除与 signaling 队列的跨线程读写竞争）。
  VideoCodec worker_codec_ = VideoCodec::kH264;
  bool worker_codec_negotiated_ = false;
  bool worker_has_video_ = true;
  std::string worker_mid_ = "0";
  RtpHeaderExtensionMap worker_ext_map_ =
      RtpHeaderExtensionMap::BrowserDefault();
  bool worker_has_rtx_ = true;
  bool worker_has_flexfec_ = true;
  uint8_t worker_flexfec_pt_ = 118;
  uint32_t worker_flexfec_rw_us_ = 10'000'000;
  std::string worker_remote_peer_id_ = "remote_peer";

  DtlsRole worker_dtls_role_ = DtlsRole::kClient;
  bool worker_has_datachannel_ = false;
  uint16_t worker_remote_sctp_port_ = 5000;
  SctpDataChannelManager sctp_dc_;
  mutable std::mutex dc_handles_mu_;
  std::set<int> valid_dc_ids_;

  std::unique_ptr<GoogCcNetworkController> goog_cc_;
  TransportFeedbackAdapter twcc_adapter_;
  FecControllerDefault fec_controller_;
  std::unique_ptr<TaskQueuePacedSender> paced_sender_;

  OutboundStreamState outbound_;
  std::unique_ptr<InboundStreamState> inbound_;
  RtpDemuxer demuxer_;
  uint16_t next_twcc_seq_ = 1;

  std::vector<std::pair<uint16_t, Timestamp>> rx_twcc_records_;
  std::optional<uint16_t> next_expected_twcc_seq_;
  std::vector<uint8_t> pending_rr_wire_;
  std::deque<std::pair<Timestamp, TimeDelta>> twcc_rtt_samples_;
  std::map<uint32_t, uint8_t> last_fir_seq_by_ssrc_;
  Timestamp last_idr_forced_at_ = Timestamp::MinusInfinity();
  uint8_t twcc_fb_pkt_count_ = 0;
  bool has_received_twcc_ = false;
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
