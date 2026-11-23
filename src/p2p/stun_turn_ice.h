#ifndef SRC_P2P_STUN_TURN_ICE_H_
#define SRC_P2P_STUN_TURN_ICE_H_

// 1:1 对标 libwebrtc/p2p/base/ 实现：
//   - StunMessage 报文编解码（RFC 5389 / RFC 8489 + OpenSSL HMAC-SHA1 完整性 + Boost.CRC32 指纹）
//   - TurnChannelDataCodec（RFC 5766 4 字节 ChannelData 帧封装）
//   - IceTransportChannel（RFC 8445 候选地址收集、候选对优先级计算、
//     连通性检查、ICE-Lite 快速提名、Trickle ICE 与 ICE 重启）

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio/ip/udp.hpp>

#include "api/array_view.h"
#include "api/units.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"
#include "rtc_base/time_utils.h"

namespace rtc {

constexpr uint32_t kStunMagicCookie = 0x2112A442u;

enum class StunMessageType : uint16_t {
  kBindingRequest = 0x0001,
  kBindingResponse = 0x0101,
  kBindingErrorResponse = 0x0111,
  kAllocateRequest = 0x0003,
  kAllocateResponse = 0x0103,
  kAllocateErrorResponse = 0x0113,
  kRefreshRequest = 0x0004,
  kRefreshResponse = 0x0104,
  kRefreshErrorResponse = 0x0114,
  kSendIndication = 0x0016,
  kDataIndication = 0x0017,
  kCreatePermissionRequest = 0x0008,
  kCreatePermissionResponse = 0x0108,
  kCreatePermissionErrorResponse = 0x0118,
  kChannelBindRequest = 0x0009,
  kChannelBindResponse = 0x0109,
  kChannelBindErrorResponse = 0x0119,
};

namespace stun_attr_type {
constexpr uint16_t kUsername = 0x0006;
constexpr uint16_t kMessageIntegrity = 0x0008;
constexpr uint16_t kErrorCode = 0x0009;
constexpr uint16_t kChannelNumber = 0x000C;
constexpr uint16_t kLifetime = 0x000D;
constexpr uint16_t kXorPeerAddress = 0x0012;
constexpr uint16_t kData = 0x0013;
constexpr uint16_t kRealm = 0x0014;
constexpr uint16_t kNonce = 0x0015;
constexpr uint16_t kXorRelayedAddress = 0x0016;
constexpr uint16_t kRequestedTransport = 0x0019;
constexpr uint16_t kXorMappedAddress = 0x0020;
constexpr uint16_t kPriority = 0x0024;
constexpr uint16_t kUseCandidate = 0x0025;
constexpr uint16_t kSoftware = 0x8022;
constexpr uint16_t kFingerprint = 0x8028;
constexpr uint16_t kIceControlled = 0x8029;
constexpr uint16_t kIceControlling = 0x802A;
}  // namespace stun_attr_type

using StunTransactionId = std::array<uint8_t, 12>;

class StunMessage {
 public:
  StunMessage() = default;
  explicit StunMessage(StunMessageType type);

  static bool IsStunPacket(ArrayView<const uint8_t> packet);
  static StunTransactionId GenerateTransactionId();

  StunMessageType type() const { return type_; }
  void set_type(StunMessageType t) { type_ = t; }

  const StunTransactionId& transaction_id() const { return tx_id_; }
  void set_transaction_id(const StunTransactionId& id) { tx_id_ = id; }

  void set_username(std::string u) { username_ = std::move(u); }
  const std::optional<std::string>& username() const { return username_; }

  void set_realm(std::string r) { realm_ = std::move(r); }
  const std::optional<std::string>& realm() const { return realm_; }

  void set_nonce(std::string n) { nonce_ = std::move(n); }
  const std::optional<std::string>& nonce() const { return nonce_; }

  void set_priority(uint32_t prio) { priority_ = prio; }
  std::optional<uint32_t> priority() const { return priority_; }

  void set_use_candidate(bool use) { use_candidate_ = use; }
  bool use_candidate() const { return use_candidate_; }

  void set_ice_controlling(uint64_t tie_breaker) {
    ice_controlling_ = tie_breaker;
  }
  std::optional<uint64_t> ice_controlling() const { return ice_controlling_; }

  void set_ice_controlled(uint64_t tie_breaker) {
    ice_controlled_ = tie_breaker;
  }
  std::optional<uint64_t> ice_controlled() const { return ice_controlled_; }

  void set_channel_number(uint16_t ch) { channel_number_ = ch; }
  std::optional<uint16_t> channel_number() const { return channel_number_; }

  void set_lifetime(uint32_t seconds) { lifetime_ = seconds; }
  std::optional<uint32_t> lifetime() const { return lifetime_; }

  void set_requested_transport(uint8_t proto) { requested_transport_ = proto; }
  std::optional<uint8_t> requested_transport() const {
    return requested_transport_;
  }

  void set_data(ArrayView<const uint8_t> payload) {
    data_.emplace(payload.begin(), payload.end());
  }
  const std::optional<std::vector<uint8_t>>& data() const { return data_; }

  void set_software(std::string s) { software_ = std::move(s); }
  const std::optional<std::string>& software() const { return software_; }

  void set_error_code(int code, std::string reason = {}) {
    error_code_ = code;
    error_reason_ = std::move(reason);
  }
  std::optional<int> error_code() const { return error_code_; }
  const std::string& error_reason() const { return error_reason_; }

  bool has_message_integrity() const { return has_message_integrity_; }

  void set_xor_mapped_address(const boost::asio::ip::udp::endpoint& ep) {
    xor_mapped_ = ep;
  }
  std::optional<boost::asio::ip::udp::endpoint> xor_mapped_address() const {
    return xor_mapped_;
  }

  void set_xor_relayed_address(const boost::asio::ip::udp::endpoint& ep) {
    xor_relayed_ = ep;
  }
  std::optional<boost::asio::ip::udp::endpoint> xor_relayed_address() const {
    return xor_relayed_;
  }

  void set_xor_peer_address(const boost::asio::ip::udp::endpoint& ep) {
    xor_peers_.clear();
    xor_peers_.push_back(ep);
  }
  void add_xor_peer_address(const boost::asio::ip::udp::endpoint& ep) {
    xor_peers_.push_back(ep);
  }
  std::optional<boost::asio::ip::udp::endpoint> xor_peer_address() const {
    if (xor_peers_.empty()) {
      return std::nullopt;
    }
    return xor_peers_.front();
  }
  const std::vector<boost::asio::ip::udp::endpoint>& xor_peer_addresses()
      const {
    return xor_peers_;
  }

  std::vector<uint8_t> Serialize(std::string_view integrity_key = "",
                                 bool add_fingerprint = true) const;

  static std::optional<StunMessage> Parse(
      ArrayView<const uint8_t> packet,
      std::string_view verify_integrity_key = "");

  static std::string ComputeLongTermKey(std::string_view username,
                                        std::string_view realm,
                                        std::string_view password);

 private:
  StunMessageType type_ = StunMessageType::kBindingRequest;
  StunTransactionId tx_id_{};
  std::optional<std::string> username_;
  std::optional<std::string> realm_;
  std::optional<std::string> nonce_;
  std::optional<uint32_t> priority_;
  bool use_candidate_ = false;
  std::optional<uint64_t> ice_controlling_;
  std::optional<uint64_t> ice_controlled_;
  std::optional<uint16_t> channel_number_;
  std::optional<uint32_t> lifetime_;
  std::optional<uint8_t> requested_transport_;
  std::optional<std::vector<uint8_t>> data_;
  std::optional<std::string> software_;
  std::optional<int> error_code_;
  std::string error_reason_;
  bool has_message_integrity_ = false;
  std::optional<boost::asio::ip::udp::endpoint> xor_mapped_;
  std::optional<boost::asio::ip::udp::endpoint> xor_relayed_;
  std::vector<boost::asio::ip::udp::endpoint> xor_peers_;
};

class TurnChannelDataCodec {
 public:
  static constexpr bool IsChannelData(ArrayView<const uint8_t> packet) {
    return packet.size() >= 4 && (packet[0] & 0xC0) == 0x40;
  }

  static std::vector<uint8_t> Wrap(uint16_t channel_number,
                                   ArrayView<const uint8_t> payload);
  static bool Unwrap(ArrayView<const uint8_t> packet,
                     uint16_t* out_channel,
                     ArrayView<const uint8_t>* out_payload);
};

enum class IceCandidateType {
  kHost = 0,
  kSrflx = 1,
  kPrflx = 2,
  kRelay = 3,
};

struct IceCandidate {
  std::string foundation = "1";
  uint32_t component = 1;
  std::string protocol = "udp";
  uint32_t priority = 0;
  boost::asio::ip::udp::endpoint address;
  IceCandidateType type = IceCandidateType::kHost;

  static uint32_t ComputePriority(IceCandidateType type,
                                  uint16_t local_pref = 65535,
                                  uint8_t component_id = 1);
  std::string ToSdpAttribute() const;
  static std::optional<IceCandidate> FromSdpAttribute(std::string_view line);
};

struct IceParameters {
  std::string ufrag;
  std::string pwd;
  bool ice_lite = false;
};

enum class IceTransportState {
  kNew = 0,
  kChecking = 1,
  kConnected = 2,
  kCompleted = 3,
  kDisconnected = 4,
  kFailed = 5,
};

class IceTransportObserver {
 public:
  virtual ~IceTransportObserver() = default;

  virtual void OnLocalCandidateGathered(const IceCandidate& candidate) = 0;
  virtual void OnIceTransportStateChanged(IceTransportState state) = 0;
  virtual void OnIcePacketReceived(ArrayView<const uint8_t> packet,
                                   Timestamp receive_time) = 0;
};

struct TurnServerSpec {
  boost::asio::ip::udp::endpoint server_endpoint;
  std::string host;
  uint16_t port = 3478;
  std::string username;
  std::string password;
  bool is_turn = false;
};

class IceTransportChannel {
 public:
  static bool ParseIceServerUri(std::string_view uri,
                                std::string_view username,
                                std::string_view password,
                                TurnServerSpec* out_spec);

  IceTransportChannel(Clock* clock,
                      TaskQueueBoost* network_queue,
                      IceTransportObserver* observer,
                      bool controlling_role = true);
  ~IceTransportChannel();

  IceTransportChannel(const IceTransportChannel&) = delete;
  IceTransportChannel& operator=(const IceTransportChannel&) = delete;

  void set_observer(IceTransportObserver* observer) {
    observer_.store(observer, std::memory_order_release);
  }
  void SetIceControlling(bool controlling);
  void SetLocalIceParameters(const IceParameters& params);
  void SetRemoteIceParameters(const IceParameters& params);
  void ConfigureServers(const std::vector<TurnServerSpec>& servers);

  bool StartGatheringAndBind(uint16_t preferred_local_port = 0);
  bool WaitForServerReflexiveGathering(TimeDelta max_wait);
  void AddRemoteCandidate(const IceCandidate& remote);
  void RestartIce(const IceParameters& new_local_params);

  int SendPacket(ArrayView<const uint8_t> packet);

  void SetSimulatedRxDropRate(double drop_probability) {
    rx_drop_prob_.store(drop_probability, std::memory_order_release);
  }

  IceParameters local_parameters() const;
  std::vector<IceCandidate> LocalCandidatesSnapshot() const;
  uint16_t bound_local_port() const { return bound_port_; }
  TimeDelta last_rtt() const {
    return TimeDelta::Micros(smoothed_rtt_us_.load(std::memory_order_acquire));
  }
  IceTransportState state() const {
    return state_.load(std::memory_order_acquire);
  }

  static constexpr uint64_t ComputeCandidatePairPriority(
      uint32_t controlling_prio,
      uint32_t controlled_prio) {
    const uint64_t g = controlling_prio;
    const uint64_t d = controlled_prio;
    const uint64_t min_gd = g < d ? g : d;
    const uint64_t max_gd = g > d ? g : d;
    const uint64_t tie = (g > d) ? 1ULL : 0ULL;
    return (min_gd << 32) + (2ULL * max_gd) + tie;
  }

 private:
  enum class PairState {
    kWaiting = 0,
    kInProgress = 1,
    kSucceeded = 2,
    kFailed = 3,
  };

  struct CandidatePair {
    IceCandidate local;
    IceCandidate remote;
    uint64_t priority = 0;
    PairState state = PairState::kWaiting;
    bool nominated = false;
    bool via_turn_relay = false;
    Timestamp last_ping_sent = Timestamp::MinusInfinity();
    Timestamp last_response_received = Timestamp::MinusInfinity();
    int unacked_pings = 0;
  };

  struct PendingPing {
    size_t pair_index = 0;
    Timestamp sent_time = Timestamp::MinusInfinity();
  };

  struct ActiveTurnState {
    TurnServerSpec spec;
    std::string realm;
    std::string nonce;
    std::string integrity_key;
    uint16_t next_channel = 0x4000;
    uint32_t lifetime_sec = 600;
    bool allocated = false;
    Timestamp last_refresh_sent = Timestamp::MinusInfinity();
    boost::asio::ip::udp::endpoint relayed_ep;
    std::map<boost::asio::ip::udp::endpoint, uint16_t> peer_to_channel;
    std::map<uint16_t, boost::asio::ip::udp::endpoint> channel_to_peer;
    std::set<uint16_t> confirmed_channels;
  };

  struct ResolvedServerEntry {
    TurnServerSpec spec;
    std::vector<boost::asio::ip::udp::endpoint> resolved_endpoints;
    bool resolving = false;
    bool dns_failed = false;
    bool srflx_gathered = false;
    int stun_tx_count = 0;
    Timestamp last_stun_tx = Timestamp::MinusInfinity();
  };

  void DoAsyncReceive();
  void NotifyServerGatheringProgress();
  void ResolveAndProbeServer(size_t server_index);
  void SendStunProbeToServer(size_t server_index, Timestamp now);
  void HandleUdpDatagram(ArrayView<const uint8_t> datagram,
                         const boost::asio::ip::udp::endpoint& from,
                         bool via_turn_relay = false);
  void HandleIncomingStun(ArrayView<const uint8_t> datagram,
                          const boost::asio::ip::udp::endpoint& from,
                          bool via_turn_relay = false);
  void RebuildCandidatePairs();
  void OnPeriodicCheckTick();
  void SendConnectivityCheck(size_t pair_index);
  void StartTurnAllocation(const TurnServerSpec& turn);
  void EnsureTurnPeerBound(const boost::asio::ip::udp::endpoint& peer_ep);
  int SendViaTurnRelay(const boost::asio::ip::udp::endpoint& peer_ep,
                       ArrayView<const uint8_t> payload);
  void SetState(IceTransportState new_state);

  Clock* const clock_;
  TaskQueueBoost* const network_queue_;
  SequenceChecker net_checker_;
  std::atomic<IceTransportObserver*> observer_;
  bool controlling_role_;
  uint64_t tie_breaker_ = 0;
  std::atomic<double> rx_drop_prob_{0.0};

  std::unique_ptr<boost::asio::ip::udp::socket> socket_;
  std::unique_ptr<boost::asio::ip::udp::resolver> resolver_;
  std::array<uint8_t, 2048> rx_buf_{};
  boost::asio::ip::udp::endpoint sender_ep_;
  uint16_t bound_port_ = 0;

  IceParameters local_params_;
  IceParameters remote_params_;
  std::vector<TurnServerSpec> servers_;
  std::vector<ResolvedServerEntry> resolved_servers_;

  std::vector<IceCandidate> local_candidates_;
  std::vector<IceCandidate> remote_candidates_;
  std::vector<CandidatePair> pairs_;
  std::optional<size_t> selected_pair_idx_;
  std::map<StunTransactionId, PendingPing> pending_pings_;
  std::optional<ActiveTurnState> turn_state_;

  std::atomic<IceTransportState> state_{IceTransportState::kNew};
  std::atomic<int64_t> smoothed_rtt_us_{30'000};
  mutable std::mutex gather_cv_mu_;
  std::condition_variable gather_cv_;
  bool all_servers_settled_ = true;
  ScopedTaskSafety safety_;
};

}  // namespace rtc

#endif  // SRC_P2P_STUN_TURN_ICE_H_
