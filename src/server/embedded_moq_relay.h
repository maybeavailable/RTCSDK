#ifndef SRC_SERVER_EMBEDDED_MOQ_RELAY_H_
#define SRC_SERVER_EMBEDDED_MOQ_RELAY_H_

// 基于 Boost.Asio QUIC v1（`AsioQuicServer`）与 HTTP/3 WebTransport（`Http3ServerConnection`）构建的
// 多发布者 / 多订阅者 IETF MoQ（draft-ietf-moq-transport-17）双栈中继服务器：
//   - 单 UDP 端口同时承载原生 QUIC（ALPN "moqt-17"）与 HTTP/3 + WebTransport（ALPN "h3"）
//   - 严格遵循 draft-17 控制流（SETUP 0x2F00 / GOAWAY 0x10）与双向请求流架构
//   - 房间命名空间发现（PUBLISH_NAMESPACE / SUBSCRIBE_NAMESPACE / NAMESPACE / NAMESPACE_DONE）
//   - 带优先级的零转码 SUBGROUP_HEADER 单向流与 OBJECT_DATAGRAM 扇出转发
//   - 基于 REQUEST_UPDATE(FORWARD / NEW_GROUP_REQUEST) 的 GOP 对齐 Simulcast 平滑切层

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "api/video_types.h"
#include "moq/asio_quic_transport.h"
#include "moq/http3_webtransport.h"
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
  std::array<uint8_t, 32> certificate_sha256() const {
    return quic_server_ ? quic_server_->certificate_sha256()
                        : std::array<uint8_t, 32>{};
  }
  std::string certificate_sha256_hex() const {
    return quic_server_ ? quic_server_->certificate_sha256_hex()
                        : std::string{};
  }

  void SetHttp3RequestHandler(
      Http3ServerConnection::Http3RequestHandler handler);
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
  void OnServerStreamStopSending(uint64_t session_id,
                                 uint64_t stream_id,
                                 uint64_t app_error_code) override;
  void OnServerDatagramReceived(uint64_t session_id,
                                ArrayView<const uint8_t> data) override;

 private:
  struct LayerSubStreamInfo {
    uint64_t bidi_stream_id = 0;
    uint64_t downstream_track_alias = 0;
    SpatialLayer layer = SpatialLayer::kHigh;
    uint8_t forward = 1;
  };

  struct DownstreamTrackGroup {
    MoqtTrackNamespace target_peer_ns;
    SpatialLayer target_layer = SpatialLayer::kHigh;
    SpatialLayer active_layer = SpatialLayer::kHigh;
    bool waiting_for_group_switch = false;
    uint64_t active_group_id = 0;
    std::optional<LayerSubStreamInfo> low_sub;
    std::optional<LayerSubStreamInfo> high_sub;
  };

  struct UpstreamSubgroupFanout {
    enum class Kind : uint8_t {
      kUnknown,
      kControl,
      kSubgroup,
    };
    Kind kind = Kind::kUnknown;
    MoqSubgroupHeader header;
    std::vector<uint8_t> header_buf;
    std::vector<std::pair<uint64_t, uint64_t>> downstream_targets;
  };

  struct ClientRequestStreamState {
    enum class Role : uint8_t {
      kUnparsed,
      kSubscribeNamespace,
      kPublishNamespace,
      kSubscribeVideo,
      kSubscribeData,
    };
    Role role = Role::kUnparsed;
    MoqtTrackNamespace ns;
    std::string track_name;
    SpatialLayer video_layer = SpatialLayer::kHigh;
    std::vector<uint8_t> rx_buf;
  };

  struct PeerSession {
    uint64_t session_id = 0;
    bool is_webtransport = false;
    std::shared_ptr<QuicServerSessionHandle> quic;
    uint64_t server_control_stream_id = 0;
    bool peer_setup_received = false;
    uint64_t next_server_request_id = 1;  // 服务端使用奇数 Request ID：1, 3, 5, ...
    uint64_t next_track_alias = 100;

    std::string room_id;
    std::string peer_id;
    MoqtTrackNamespace video_peer_namespace;
    bool is_video_publisher = false;
    std::optional<uint64_t> upstream_low_sub_sid;
    std::optional<uint64_t> upstream_high_sub_sid;
    std::map<uint64_t, std::vector<uint8_t>> upstream_sub_rx_bufs;

    // 双向流映射：stream_id -> 已发布的完整命名空间 / 已订阅的命名空间前缀。
    std::map<uint64_t, MoqtTrackNamespace> published_namespaces;
    std::map<uint64_t, MoqtTrackNamespace> subscribed_ns_prefixes;

    bool has_data_subscription = false;
    uint64_t data_downstream_alias = kMoqDownstreamDataTrackAlias;

    bool has_low_layer = false;
    bool has_high_layer = false;
    uint64_t largest_group[2]{0, 0};
    Timestamp first_media_time = Timestamp::MinusInfinity();
    Timestamp last_low_time = Timestamp::MinusInfinity();
    Timestamp last_high_time = Timestamp::MinusInfinity();
    Timestamp last_kf_req_time = Timestamp::MinusInfinity();

    // target_peer_ns -> 下行 Simulcast 组订阅状态。
    std::map<MoqtTrackNamespace, DownstreamTrackGroup> video_subscriptions;
    std::map<uint64_t, ClientRequestStreamState> client_request_streams;
    std::map<uint64_t, UpstreamSubgroupFanout> inbound_uni_streams;
  };

  static uint64_t AllocateServerRequestId(PeerSession* peer);
  void BroadcastNamespaceChange(uint64_t origin_session_id,
                                const MoqtTrackNamespace& full_ns,
                                bool is_done);
  void OpenUpstreamSubscriptionsToPublisher(PeerSession* pub_peer);
  void ForwardNewGroupRequest(const MoqtTrackNamespace& target_peer_ns,
                              SpatialLayer layer);
  void HandleControlBytes(PeerSession* peer, std::vector<uint8_t>* buf);
  void HandleClientRequestBytes(PeerSession* peer,
                                uint64_t stream_id,
                                ArrayView<const uint8_t> data,
                                bool fin);
  void HandleUpstreamSubResponseBytes(PeerSession* peer,
                                      uint64_t stream_id,
                                      ArrayView<const uint8_t> data);
  void RemoveClientRequestStream(PeerSession* peer, uint64_t stream_id);
  void HandleUnidirectionalBytes(PeerSession* publisher,
                                 uint64_t stream_id,
                                 ArrayView<const uint8_t> data,
                                 bool fin);

  Clock* const clock_;
  std::string bind_ip_;
  std::unique_ptr<TaskQueueBoost> net_queue_;
  SequenceChecker net_checker_;
  std::unique_ptr<AsioQuicServer> quic_server_;
  Http3ServerConnection::Http3RequestHandler custom_h3_handler_;
  uint64_t next_wt_virtual_id_base_ = 1'000'000;
  std::map<uint64_t, std::shared_ptr<Http3ServerConnection>> h3_conns_;
  std::map<uint64_t, std::unique_ptr<PeerSession>> sessions_;
  std::atomic<bool> stopped_{true};
  ScopedTaskSafety safety_;
};

}  // namespace rtc

#endif  // SRC_SERVER_EMBEDDED_MOQ_RELAY_H_
