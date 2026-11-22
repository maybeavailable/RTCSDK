#ifndef SRC_SERVER_EMBEDDED_MOQ_RELAY_H_
#define SRC_SERVER_EMBEDDED_MOQ_RELAY_H_

// 基于 Boost.Asio QUIC v1（`AsioQuicServer`）与 `TaskQueueBoost` 构建的
// 多发布者 / 多订阅者 IETF MoQ（Media over QUIC）中继服务器：
//   - 房间命名空间发现（`CLIENT_SETUP`、`ANNOUNCE`、`UNANNOUNCE`）
//   - 带优先级的零转码 Subgroup 单向流扇出转发
//   - GOP 边界对齐的 Simulcast 空间层平滑切换（`SUBSCRIBE_UPDATE`）
//   - 端到端 `RESET_STREAM` 与 `KEYFRAME_REQUEST` 信令透传

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "api/video_types.h"
#include "moq/asio_quic_transport.h"
#include "moq/moq_transport.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"
#include "rtc_base/time_utils.h"

namespace rtc {

class EmbeddedMoqRelayServer final : public IQuicServerVisitor {
 public:
  explicit EmbeddedMoqRelayServer(std::string bind_ip = "0.0.0.0");
  ~EmbeddedMoqRelayServer() override;

  EmbeddedMoqRelayServer(const EmbeddedMoqRelayServer&) = delete;
  EmbeddedMoqRelayServer& operator=(const EmbeddedMoqRelayServer&) = delete;

  bool Start(uint16_t udp_port = 0);
  void Stop();

  uint16_t udp_port() const {
    return quic_server_ ? quic_server_->local_port() : 0;
  }

  void SetSimulatedDropRates(double rx_drop_prob, double tx_drop_prob);
  void SetQuicCongestionControl(rtc_quic_cc_algo_e algo);
  void SetCustomQuicCongestionController(
      std::shared_ptr<IQuicCongestionControllerFactory> factory);

  // IQuicServerVisitor 接口重写（在 `net_queue_` 队列上回调执行）：
  void OnServerSessionConnected(
      std::shared_ptr<QuicServerSessionHandle> session) override;
  void OnServerSessionDisconnected(uint64_t session_id,
                                   int error_code) override;
  void OnServerStreamOpened(uint64_t session_id,
                            uint64_t stream_id,
                            bool unidirectional) override;
  void OnServerStreamData(uint64_t session_id,
                          uint64_t stream_id,
                          ArrayView<const uint8_t> data,
                          bool fin) override;
  void OnServerStreamReset(uint64_t session_id,
                           uint64_t stream_id,
                           uint64_t app_error_code) override;

 private:
  struct DownstreamSubscription {
    uint64_t subscribe_id = 0;
    uint64_t downstream_track_alias = 0;
    std::string target_namespace;
    SpatialLayer target_layer = SpatialLayer::kHigh;
    SpatialLayer active_layer = SpatialLayer::kHigh;
    bool waiting_for_group_switch = false;
    uint64_t active_group_id = 0;
  };

  struct UpstreamSubgroupFanout {
    bool header_parsed = false;
    MoqSubgroupHeader header;
    std::vector<uint8_t> header_buf;
    std::vector<std::pair<uint64_t, uint64_t>> downstream_targets;
  };

  struct PeerSession {
    uint64_t session_id = 0;
    std::shared_ptr<QuicServerSessionHandle> quic;
    uint64_t control_stream_id = 0;
    bool has_control_stream = false;
    std::vector<uint8_t> ctrl_rx_buf;

    std::string room_id;
    std::string peer_id;
    std::string announced_namespace;
    std::string announced_track_name;
    bool is_announced = false;
    std::set<std::string> announced_data_tracks;
    bool has_data_subscription = false;
    uint64_t data_downstream_alias = kMoqDownstreamDataTrackAlias;
    bool has_low_layer = false;
    bool has_high_layer = false;
    Timestamp first_media_time = Timestamp::MinusInfinity();
    Timestamp last_low_time = Timestamp::MinusInfinity();
    Timestamp last_high_time = Timestamp::MinusInfinity();
    Timestamp last_kf_req_time = Timestamp::MinusInfinity();

    std::map<uint64_t, DownstreamSubscription> subscriptions;
    std::map<uint64_t, UpstreamSubgroupFanout> inbound_uni_streams;
  };

  static void SplitRoomAndPeer(std::string_view ns,
                               std::string* out_room,
                               std::string* out_peer);
  void SendControlToPeer(PeerSession* peer, const MoqControlMessage& msg);
  void HandleControlBytes(PeerSession* peer, ArrayView<const uint8_t> data);
  void HandleUnidirectionalBytes(PeerSession* publisher,
                                 uint64_t stream_id,
                                 ArrayView<const uint8_t> data,
                                 bool fin);
  void ForwardKeyframeRequest(const std::string& target_namespace,
                              const std::string& track_name);

  Clock* const clock_;
  std::string bind_ip_;
  std::unique_ptr<TaskQueueBoost> net_queue_;
  SequenceChecker net_checker_;
  std::unique_ptr<AsioQuicServer> quic_server_;
  std::map<uint64_t, std::unique_ptr<PeerSession>> sessions_;
  std::atomic<bool> stopped_{true};
  ScopedTaskSafety safety_;
};

}  // namespace rtc

#endif  // SRC_SERVER_EMBEDDED_MOQ_RELAY_H_