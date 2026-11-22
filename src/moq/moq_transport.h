#ifndef SRC_MOQ_MOQ_TRANSPORT_H_
#define SRC_MOQ_MOQ_TRANSPORT_H_

// 原生 IETF Media over QUIC（moq-transport 协议与低开销容器 LOC）实现：
//   - QuicVarInt：变长整数编解码（RFC 9000 第 16 节）
//   - MoqControlMessage 与 MoqSubgroupHeader：控制消息与子组流头部
//   - LocFramePackager：LOC 媒体帧封包与解包器
//   - MoqBweAdapter 与 MoqRelayBackend：带宽估计适配器与会话后端（ISessionBackend）

#include <cstddef>
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

#include "api/array_view.h"
#include "api/session_backend_interface.h"
#include "modules/video_coding/video_coding_module.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"
#include "rtc_base/time_utils.h"

namespace rtc {

class QuicVarInt {
 public:
  static void Append(uint64_t val, std::vector<uint8_t>* dst);
  static bool Read(ArrayView<const uint8_t> data,
                   size_t* offset,
                   uint64_t* out_val);
  static void AppendString(std::string_view str, std::vector<uint8_t>* dst);
  static bool ReadString(ArrayView<const uint8_t> data,
                         size_t* offset,
                         std::string* out_str);
};

enum class MoqControlMessageType : uint64_t {
  kSubscribeUpdate = 0x02,
  kSubscribe = 0x03,
  kSubscribeOk = 0x04,
  kAnnounce = 0x06,
  kAnnounceOk = 0x07,
  kUnannounce = 0x09,
  kUnsubscribe = 0x0A,
  kClientSetup = 0x40,
  kServerSetup = 0x41,
  kKeyframeRequest = 0x50,
};

enum class MoqFilterType : uint64_t {
  kLatestGroup = 0x01,
  kLatestObject = 0x02,
};

struct MoqControlMessage {
  MoqControlMessageType type = MoqControlMessageType::kClientSetup;
  uint64_t subscribe_id = 0;
  uint64_t track_alias = 0;
  std::string track_namespace;
  std::string track_name;
  uint8_t subscriber_priority = 128;
  MoqFilterType filter_type = MoqFilterType::kLatestGroup;

  std::vector<uint8_t> Encode() const;
  static std::optional<MoqControlMessage> Decode(ArrayView<const uint8_t> data,
                                                 size_t* consumed);
};

struct MoqSubgroupHeader {
  uint64_t track_alias = 0;
  uint64_t group_id = 0;
  uint64_t subgroup_id = 0;
  uint8_t publisher_priority = 64;

  std::vector<uint8_t> Encode() const;
  static std::optional<MoqSubgroupHeader> Decode(ArrayView<const uint8_t> data,
                                                 size_t* consumed);
};

// MoQ 数据轨道固定轨道别名约定（与视频低清层=1、高清层=2 隔离解复用）。
inline constexpr uint64_t kMoqUpstreamDataTrackAlias = 3;
inline constexpr uint64_t kMoqDownstreamDataTrackAlias = 50;

// IETF MoQ 通用数据通道对象容器（承载二进制或 UTF-8 消息及通道元数据）。
struct MoqDataObject {
  uint64_t object_id = 0;
  std::string sender_peer_id;
  std::string label;
  std::string protocol;
  uint64_t timestamp_us = 0;
  bool is_binary = true;
  bool ordered = true;
  bool is_close = false;
  std::vector<uint8_t> payload;
};

class MoqDataPackager {
 public:
  static std::vector<uint8_t> PackObject(const MoqDataObject& obj);
  static std::optional<MoqDataObject> UnpackObject(
      ArrayView<const uint8_t> data,
      size_t* consumed);
};

class LocFramePackager {
 public:
  static std::vector<uint8_t> PackObject(uint64_t object_id,
                                         const EncodedVideoFrame& frame);
  static std::optional<EncodedVideoFrame> UnpackObject(
      ArrayView<const uint8_t> data,
      size_t* consumed,
      uint64_t* out_object_id);
};

class MoqBweAdapter {
 public:
  MoqBweAdapter(DataRate min_bitrate, DataRate max_bitrate);

  TargetTransferRate ConvertSnapshot(const QuicCongestionSnapshot& snap) const;

 private:
  DataRate min_bitrate_;
  DataRate max_bitrate_;
  mutable DataRate app_limited_probe_rate_ = DataRate::Zero();
  mutable Timestamp last_probe_step_ = Timestamp::MinusInfinity();
};

class MoqRelayBackend final : public ISessionBackend,
                              public IMoqQuicEngineObserver {
 public:
  MoqRelayBackend(Clock* clock,
                  SdkTaskQueues* queues,
                  const EngineConfig& config,
                  ISessionBackendObserver* observer,
                  std::shared_ptr<IMoqQuicEngine> quic_engine = nullptr);
  ~MoqRelayBackend() override;

  int StartSession(const std::string& room_id,
                   const std::string& local_peer_id) override;
  void StopSession() override;
  int SendEncodedFrame(EncodedVideoFrame frame) override;
  void SetLayerActive(SpatialLayer layer, bool active) override;
  int SubscribeRemoteTrack(const std::string& track_id,
                           SpatialLayer preferred_layer) override;
  int SwitchSubscribedLayer(const std::string& track_id,
                            SpatialLayer preferred_layer) override;
  int UnsubscribeRemoteTrack(const std::string& track_id) override;
  int RequestRemoteKeyFrame(const std::string& track_id) override;
  int CreateDataChannel(const DataChannelConfig& config) override;
  int SendData(int channel_id,
               ArrayView<const uint8_t> payload,
               bool is_binary) override;
  int CloseDataChannel(int channel_id) override;
  int SetQuicCongestionControl(rtc_quic_cc_algo_e algo) override;
  int SetCustomQuicCongestionController(
      std::shared_ptr<IQuicCongestionControllerFactory> factory) override;

  void OnQuicConnected() override;
  void OnQuicDisconnected(int error_code) override;
  void OnStreamOpened(uint64_t stream_id, bool unidirectional) override;
  void OnStreamData(uint64_t stream_id,
                    ArrayView<const uint8_t> data,
                    bool fin) override;
  void OnStreamReset(uint64_t stream_id, uint64_t app_error_code) override;

 private:
  struct ActiveOutboundGroup {
    uint64_t group_id = 0;
    uint64_t next_object_id = 0;
    Timestamp started_at = Timestamp::MinusInfinity();
    std::map<uint8_t, uint64_t> subgroup_streams;
  };

  struct InboundStreamState {
    bool header_parsed = false;
    MoqSubgroupHeader header;
    std::vector<uint8_t> buffer;
  };

  struct SubscribedTrackContext {
    std::string track_id;
    std::string remote_namespace;
    uint64_t subscribe_id = 0;
    uint64_t track_alias = 0;
    SpatialLayer preferred_layer = SpatialLayer::kHigh;
    std::optional<uint8_t> current_spatial_id;
    FrameBuffer3 frame_buffer;
    VCMJitterEstimator jitter_estimator;
    VCMTiming vcm_timing;
    std::optional<Timestamp> prev_recv_time;
    std::optional<DataSize> prev_frame_size;

    SubscribedTrackContext(Timestamp now, bool zero_delay)
        : frame_buffer(256), vcm_timing(now, zero_delay) {}
  };

  static bool ParseMoqEndpoint(std::string_view url,
                               std::string* host,
                               uint16_t* port);
  std::string MakeRemoteNamespace(std::string_view track_or_peer_id) const;
  std::string ExtractTrackIdFromNamespace(std::string_view ns) const;
  void SendControlMessage(const MoqControlMessage& msg);
  void HandleControlStreamBytes(ArrayView<const uint8_t> data);
  void HandleInboundUnidirectionalData(uint64_t stream_id,
                                       ArrayView<const uint8_t> data,
                                       bool fin);
  void HandleInboundDataStreamObjects(InboundStreamState* st);
  int EnsureDataChannelForLabelOnWorker(const std::string& label,
                                        const DataChannelConfig* explicit_cfg);
  void TransmitMoqDataMessageOnWorker(int channel_id,
                                      ArrayView<const uint8_t> payload,
                                      bool is_binary,
                                      bool is_close);
  void OnPeriodicMaintenanceTick();
  void DrainDecodableFrames(SubscribedTrackContext* sub);

  struct PendingMoqDataMsg {
    std::vector<uint8_t> payload;
    bool is_binary = true;
  };

  struct MoqDataChannelState {
    int channel_id = 0;
    DataChannelConfig config;
    rtc_data_channel_state_e state = RTC_DATA_CHANNEL_CONNECTING;
    bool local_created = false;
    bool announced = false;
    bool local_open_notified = false;
    std::optional<uint64_t> ordered_stream_id;
    uint64_t next_object_id = 0;
    std::deque<PendingMoqDataMsg> pending_messages;
  };

  Clock* const clock_;
  SdkTaskQueues* const queues_;
  const EngineConfig config_;
  ISessionBackendObserver* const observer_;
  std::shared_ptr<IMoqQuicEngine> quic_engine_;
  MoqBweAdapter bwe_adapter_;

  SequenceChecker work_checker_;
  std::string room_id_;
  std::string local_peer_id_;
  bool connected_ = false;
  uint64_t control_stream_id_ = 0;
  std::vector<uint8_t> ctrl_rx_buf_;

  bool layer_active_[2]{true, true};
  uint64_t current_group_id_[2]{0, 0};
  int64_t next_frame_id_[2]{0, 0};
  std::optional<ActiveOutboundGroup> active_group_[2];
  uint64_t streams_reset_on_timeout_ = 0;

  uint64_t next_subscribe_id_ = 1;
  std::map<std::string, std::unique_ptr<SubscribedTrackContext>> subscriptions_;
  std::map<uint64_t, std::string> alias_to_track_id_;
  std::map<uint64_t, InboundStreamState> inbound_streams_;

  // MoQ 数据轨道通道状态表与句柄校验集。
  int next_dc_id_ = 0;
  std::map<int, MoqDataChannelState> data_channels_;
  std::map<std::string, int> label_to_dc_id_;
  std::set<std::pair<std::string, int>> notified_remote_dc_peers_;
  std::vector<std::pair<uint64_t, Timestamp>> ttl_data_streams_;
  mutable std::mutex dc_handles_mu_;
  std::set<int> valid_dc_ids_;

  // 用于 OnBackendStatsSnapshot 回调的遥测统计计数器。
  Timestamp last_stats_time_ = Timestamp::MinusInfinity();
  uint64_t frames_decoded_ = 0;
  uint64_t keyframe_requests_sent_ = 0;
  uint32_t last_target_bps_ = 0;

  ScopedTaskSafety safety_;
};

class InMemoryMoqQuicPair {
 public:
  static std::pair<std::shared_ptr<IMoqQuicEngine>,
                   std::shared_ptr<IMoqQuicEngine>>
  CreateConnectedPair(
      TaskQueueBoost* network_queue,
      DataRate simulated_bandwidth = DataRate::KilobitsPerSec(3000),
      TimeDelta simulated_rtt = TimeDelta::Millis(25));
};

}  // namespace rtc

#endif  // SRC_MOQ_MOQ_TRANSPORT_H_