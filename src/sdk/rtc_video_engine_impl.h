#ifndef SRC_SDK_RTC_VIDEO_ENGINE_IMPL_H_
#define SRC_SDK_RTC_VIDEO_ENGINE_IMPL_H_

#include <atomic>
#include <memory>
#include <string>
#include <string_view>

#include "api/session_backend_interface.h"
#include "modules/video_coding/video_coding_module.h"
#include "rtc_base/packet_slab_pool.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"
#include "rtc_base/time_utils.h"
#include "rtc_video_engine.hpp"

namespace rtc {

class RtcVideoEngineImpl final : public RtcVideoEngine,
                                 public ISessionBackendObserver {
 public:
  RtcVideoEngineImpl(
      const EngineConfig& config,
      IRtcEventObserver* observer,
      std::shared_ptr<IMoqQuicEngine> custom_moq_quic_engine = nullptr);
  ~RtcVideoEngineImpl() override;

  int JoinRoom(const std::string& room_id,
               const std::string& local_peer_id) override;
  int LeaveRoom() override;
  int PushVideoFrame(const rtc_encoded_frame_t& frame) override;
  int SubscribeTrack(const std::string& remote_track_id,
                     rtc_stream_layer_e preferred_layer) override;
  int SwitchSubscribedLayer(const std::string& remote_track_id,
                            rtc_stream_layer_e preferred_layer) override;
  int UnsubscribeTrack(const std::string& remote_track_id) override;
  int RequestRemoteIdr(const std::string& remote_track_id) override;
  int SetQuicCongestionControl(rtc_quic_cc_algo_e algo) override;
  int SetCustomQuicCongestionController(
      std::shared_ptr<IQuicCongestionControllerFactory> factory) override;

  int CreateLocalOffer(std::string* out_sdp) override;
  int SetRemoteDescription(std::string_view sdp_type,
                           std::string_view remote_sdp,
                           std::string* out_answer_sdp = nullptr) override;
  int AddRemoteIceCandidate(std::string_view candidate_sdp) override;

  int CreateDataChannel(const DataChannelConfig& config) override;
  int SendData(int channel_id,
               const uint8_t* data,
               size_t size,
               bool is_binary = true) override;
  int CloseDataChannel(int channel_id) override;

  void OnBackendConnectionState(rtc_connection_state_e state,
                                int reason_code) override;
  void OnBackendTargetTransferRate(const TargetTransferRate& rate) override;
  void OnBackendForceKeyFrame(SpatialLayer layer) override;
  void OnBackendRemoteTrackPublished(const std::string& peer_id,
                                     const std::string& track_id,
                                     VideoCodec codec) override;
  void OnBackendRemoteTrackUnpublished(const std::string& peer_id,
                                       const std::string& track_id) override;
  void OnBackendDecodableFrame(const std::string& peer_id,
                               const std::string& track_id,
                               EncodedVideoFrame frame) override;
  void OnBackendStatsSnapshot(const rtc_network_stats_t& stats) override;
  void OnBackendLocalIceCandidate(const std::string& sdp_mid,
                                  int sdp_mline_index,
                                  const std::string& candidate) override;
  void OnBackendDataChannelState(const std::string& peer_id,
                                 int channel_id,
                                 const std::string& label,
                                 rtc_data_channel_state_e state) override;
  void OnBackendDataChannelMessage(const std::string& peer_id,
                                   int channel_id,
                                   bool is_binary,
                                   std::vector<uint8_t> payload) override;

  SdkTaskQueues* task_queues() { return queues_.get(); }

 private:
  Clock* const clock_;
  const EngineConfig config_;
  const bool use_simulcast_;
  IRtcEventObserver* const observer_;

  std::unique_ptr<SdkTaskQueues> queues_;
  std::shared_ptr<PacketSlabPool> slab_pool_;
  SimulcastRateAllocator rate_allocator_;
  VideoBitrateAllocation last_allocation_{};
  bool has_last_allocation_ = false;

  std::unique_ptr<ISessionBackend> backend_;
  std::atomic<bool> joined_{false};
  SequenceChecker cb_checker_;
  ScopedTaskSafety cb_safety_;
};

}  // namespace rtc

#endif  // SRC_SDK_RTC_VIDEO_ENGINE_IMPL_H_