#ifndef SRC_SERVER_STUN_TURN_RELAY_SERVER_H_
#define SRC_SERVER_STUN_TURN_RELAY_SERVER_H_

// 对标 coturn 构建的轻量级、高性能嵌入式 STUN / TURN 中继转发服务（纯 Boost.Asio + OpenSSL 实现）：
//   - 完整支持 RFC 5389 STUN Binding（`srflx` 公网地址反射发现）
//   - 完整支持 RFC 5766 TURN（`Allocate`、`Refresh`、`CreatePermission`、`ChannelBind`、
//     `Send/Data Indication` 以及 4 字节零拷贝低开销 `ChannelData` 双向转发）
//   - 支持静态长期凭证（`lt-cred-mech`）与 coturn 兼容的动态时效 HMAC-SHA1 `TURN REST API` 鉴权
//   - 支持 `--external-ip` 云主机弹性公网 IP 映射与同机双对称型 NAT 内存级发卡弯（Hairpinning）直通
//   - 内置中继端口池管理、对端 IP 权限校验、防环回 SSRF 开关与空闲超时自动回收

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <boost/asio/ip/udp.hpp>

#include "api/array_view.h"
#include "p2p/stun_turn_ice.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"
#include "rtc_base/time_utils.h"

namespace rtc {

struct StunTurnServerConfig {
  std::string bind_ip = "0.0.0.0";
  uint16_t port = 3478;
  std::string relay_bind_ip = "0.0.0.0";
  // 云服务器公网弹性 IP（非空时写入 XOR-RELAYED-ADDRESS 并启用内部 Hairpinning 路由）。
  std::string external_ip;
  std::string realm = "rtc.local";
  // 静态长期鉴权用户名与密码表（username -> password）。
  std::map<std::string, std::string> static_users;
  // 兼容 coturn `static-auth-secret` 的 TURN REST API 共享密钥（支持 `<unix_ts>:<id>` 动态账号）。
  std::string rest_api_secret;
  uint16_t min_relay_port = 49152;
  uint16_t max_relay_port = 65535;
  uint32_t default_lifetime_sec = 600;
  uint32_t max_lifetime_sec = 3600;
  uint32_t max_allocations = 2048;
  // 公网生产环境可关闭环回对端转发以防止 SSRF 攻击；本地自测保持开启。
  bool allow_loopback_peers = true;
};

struct StunTurnStatsSnapshot {
  uint64_t stun_binding_requests = 0;
  uint64_t active_allocations = 0;
  uint64_t total_allocations = 0;
  uint64_t relayed_packets = 0;
  uint64_t relayed_bytes = 0;
  uint64_t auth_failures = 0;
};

class StunTurnRelayServer {
 public:
  explicit StunTurnRelayServer(StunTurnServerConfig config = {});
  ~StunTurnRelayServer();

  StunTurnRelayServer(const StunTurnRelayServer&) = delete;
  StunTurnRelayServer& operator=(const StunTurnRelayServer&) = delete;

  bool Start();
  void Stop();

  uint16_t port() const { return bound_port_; }
  StunTurnStatsSnapshot GetStatsSnapshot() const;

  // 生成兼容 coturn TURN REST API 的 `<expiry_ts>:<user_id>` 临时密码（Base64(HMAC-SHA1)）。
  static std::string ComputeRestApiPassword(std::string_view rest_secret,
                                            std::string_view timed_username);

 private:
  struct TurnAllocation;

  void DoControlReceive();
  void ScheduleSweepTimer();
  void OnSweepExpiredAllocations();
  void HandleControlDatagram(ArrayView<const uint8_t> datagram,
                             const boost::asio::ip::udp::endpoint& from);
  void HandleStunOrTurnPacket(ArrayView<const uint8_t> datagram,
                              const boost::asio::ip::udp::endpoint& from);

  bool AuthenticateTurnRequest(ArrayView<const uint8_t> raw_datagram,
                               const boost::asio::ip::udp::endpoint& from,
                               StunMessageType error_resp_type,
                               StunMessage* out_verified_msg,
                               std::string* out_username,
                               std::string* out_integrity_key);
  std::optional<std::string> LookupUserPassword(std::string_view username,
                                                int64_t unix_now_sec) const;
  std::string GenerateNonce(int64_t unix_now_sec) const;
  bool VerifyNonce(std::string_view nonce, int64_t unix_now_sec) const;
  void SendErrorResponse(StunMessageType error_type,
                         const StunTransactionId& tx_id,
                         int code,
                         std::string_view reason,
                         bool include_challenge,
                         const boost::asio::ip::udp::endpoint& to);

  bool IsAllowedPeerEndpoint(const boost::asio::ip::udp::endpoint& peer_ep) const;
  boost::asio::ip::address_v4 DetermineAdvertisedAddress(
      const boost::asio::ip::udp::endpoint& client_ep) const;
  std::shared_ptr<TurnAllocation> FindHairpinTarget(
      const boost::asio::ip::udp::endpoint& target_ep) const;
  void ForwardClientPayloadToPeer(
      const std::shared_ptr<TurnAllocation>& sender_alloc,
      const boost::asio::ip::udp::endpoint& peer_ep,
      ArrayView<const uint8_t> payload,
      Timestamp now);
  void DeliverPeerPayloadToClient(
      const std::shared_ptr<TurnAllocation>& target_alloc,
      const boost::asio::ip::udp::endpoint& peer_ep,
      ArrayView<const uint8_t> payload,
      Timestamp now);
  void StartRelayReceiveLoop(const std::shared_ptr<TurnAllocation>& alloc);
  void DestroyAllocation(const boost::asio::ip::udp::endpoint& client_ep);

  Clock* const clock_;
  StunTurnServerConfig config_;
  std::optional<boost::asio::ip::address_v4> parsed_external_ipv4_;
  std::array<uint8_t, 16> nonce_secret_{};

  mutable TaskQueueBoost queue_;
  SequenceChecker checker_;
  boost::asio::ip::udp::socket control_socket_;
  std::array<uint8_t, 2048> rx_buf_{};
  boost::asio::ip::udp::endpoint sender_ep_;
  uint16_t bound_port_ = 0;
  uint16_t next_relay_port_cursor_ = 49152;

  std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<TurnAllocation>>
      allocations_by_client_;
  std::map<uint16_t, std::shared_ptr<TurnAllocation>> allocations_by_port_;

  uint64_t stat_stun_bindings_ = 0;
  uint64_t stat_total_allocs_ = 0;
  uint64_t stat_relayed_pkts_ = 0;
  uint64_t stat_relayed_bytes_ = 0;
  uint64_t stat_auth_failures_ = 0;

  std::atomic<bool> stopped_{true};
  ScopedTaskSafety safety_;
};

}  // namespace rtc

#endif  // SRC_SERVER_STUN_TURN_RELAY_SERVER_H_
