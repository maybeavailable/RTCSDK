#include "server/stun_turn_relay_server.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "modules/rtp_rtcp/byte_io.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {

constexpr uint32_t kPermissionLifetimeSec = 300;
constexpr uint32_t kChannelLifetimeSec = 600;
constexpr int64_t kNonceMaxAgeSec = 3600;

int64_t CurrentUnixSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

}  // namespace

struct StunTurnRelayServer::TurnAllocation
    : public std::enable_shared_from_this<StunTurnRelayServer::TurnAllocation> {
  struct ChannelBindingInfo {
    boost::asio::ip::udp::endpoint peer_ep;
    Timestamp expires_at = Timestamp::MinusInfinity();
  };

  boost::asio::ip::udp::endpoint client_endpoint;
  std::string username;
  std::string integrity_key;
  StunTransactionId create_tx_id{};
  uint32_t lifetime_sec = 600;
  Timestamp expires_at = Timestamp::MinusInfinity();

  std::unique_ptr<boost::asio::ip::udp::socket> relay_socket;
  uint16_t relay_port = 0;
  boost::asio::ip::address_v4 local_bound_ipv4;
  boost::asio::ip::udp::endpoint advertised_relay_ep;
  std::array<uint8_t, 2048> relay_rx_buf{};
  boost::asio::ip::udp::endpoint relay_sender_ep;
  bool closed = false;

  // 对端 IPv4 权限表（RFC 5766 第 8 节：按 IP 授权，不区分端口，有效期 300s）。
  std::map<uint32_t, Timestamp> ip_permissions;
  // 4 字节 ChannelData 通道双向映射表（0x4000..0x7FFE，有效期 600s）。
  std::map<uint16_t, ChannelBindingInfo> channel_to_peer;
  std::map<boost::asio::ip::udp::endpoint, uint16_t> peer_to_channel;
};

StunTurnRelayServer::StunTurnRelayServer(StunTurnServerConfig config)
    : clock_(Clock::GetRealTimeClock()),
      config_(std::move(config)),
      queue_("stun-turn-srv", TaskQueuePriority::kHigh),
      checker_(&queue_),
      control_socket_(queue_.io_context()),
      next_relay_port_cursor_(config_.min_relay_port),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {
  RAND_bytes(nonce_secret_.data(), static_cast<int>(nonce_secret_.size()));
  if (config_.min_relay_port == 0) {
    config_.min_relay_port = 49152;
  }
  if (config_.max_relay_port < config_.min_relay_port) {
    config_.max_relay_port = config_.min_relay_port;
  }
  next_relay_port_cursor_ = config_.min_relay_port;

  if (!config_.external_ip.empty()) {
    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address_v4(config_.external_ip, ec);
    if (!ec) {
      parsed_external_ipv4_ = addr;
    } else {
      RTC_LOG(kWarning) << "Invalid external_ip '" << config_.external_ip
                        << "' in StunTurnServerConfig, ignoring";
    }
  }
}

StunTurnRelayServer::~StunTurnRelayServer() { Stop(); }

std::string StunTurnRelayServer::ComputeRestApiPassword(
    std::string_view rest_secret,
    std::string_view timed_username) {
  unsigned char hmac_raw[20]{};
  unsigned int hmac_len = 0;
  HMAC(EVP_sha1(), rest_secret.data(), static_cast<int>(rest_secret.size()),
       reinterpret_cast<const unsigned char*>(timed_username.data()),
       timed_username.size(), hmac_raw, &hmac_len);

  unsigned char b64_buf[32]{};
  const int b64_len = EVP_EncodeBlock(b64_buf, hmac_raw, 20);
  if (b64_len <= 0) {
    return {};
  }
  return std::string(reinterpret_cast<const char*>(b64_buf),
                     static_cast<size_t>(b64_len));
}

bool StunTurnRelayServer::Start() {
  bool ok = false;
  queue_.Invoke([this, &ok]() {
    RTC_DCHECK_RUN_ON(&checker_);
    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address_v4(config_.bind_ip, ec);
    if (ec) {
      RTC_LOG(kError) << "StunTurnRelayServer invalid bind_ip: "
                      << config_.bind_ip;
      return;
    }
    control_socket_.open(boost::asio::ip::udp::v4(), ec);
    if (ec) {
      return;
    }
    control_socket_.set_option(
        boost::asio::socket_base::receive_buffer_size(4 * 1024 * 1024), ec);
    control_socket_.set_option(
        boost::asio::socket_base::send_buffer_size(4 * 1024 * 1024), ec);
    control_socket_.bind(boost::asio::ip::udp::endpoint(addr, config_.port),
                         ec);
    if (ec) {
      control_socket_.close(ec);
      return;
    }
    bound_port_ = control_socket_.local_endpoint(ec).port();
    ok = !ec;
    if (ok) {
      stopped_.store(false, std::memory_order_release);
      DoControlReceive();
      ScheduleSweepTimer();
    }
  });

  if (ok) {
    RTC_LOG(kInfo) << "StunTurnRelayServer (RFC 5389 STUN + RFC 5766 TURN) "
                      "listening on udp://"
                   << config_.bind_ip << ":" << bound_port_
                   << " (realm=" << config_.realm << ", relay_ports="
                   << config_.min_relay_port << "-" << config_.max_relay_port
                   << (parsed_external_ipv4_.has_value()
                           ? (", external_ip=" +
                              parsed_external_ipv4_->to_string())
                           : "")
                   << ")";
  }
  return ok;
}

void StunTurnRelayServer::Stop() {
  bool expected = false;
  if (!stopped_.compare_exchange_strong(expected, true,
                                        std::memory_order_acq_rel)) {
    return;
  }
  if (!queue_.IsStopped()) {
    queue_.Invoke([this]() {
      RTC_DCHECK_RUN_ON(&checker_);
      safety_.flag()->SetNotAlive();
      boost::system::error_code ec;
      control_socket_.close(ec);
      for (auto& [ep, alloc] : allocations_by_client_) {
        (void)ep;
        alloc->closed = true;
        if (alloc->relay_socket) {
          alloc->relay_socket->close(ec);
        }
      }
      allocations_by_client_.clear();
      allocations_by_port_.clear();
    });
    queue_.Shutdown();
  }
  RTC_LOG(kInfo) << "StunTurnRelayServer stopped";
}

StunTurnStatsSnapshot StunTurnRelayServer::GetStatsSnapshot() const {
  StunTurnStatsSnapshot snap;
  if (stopped_.load(std::memory_order_acquire) || queue_.IsStopped()) {
    return snap;
  }
  queue_.Invoke([this, &snap]() {
    RTC_DCHECK_RUN_ON(&checker_);
    snap.stun_binding_requests = stat_stun_bindings_;
    snap.active_allocations = allocations_by_client_.size();
    snap.total_allocations = stat_total_allocs_;
    snap.relayed_packets = stat_relayed_pkts_;
    snap.relayed_bytes = stat_relayed_bytes_;
    snap.auth_failures = stat_auth_failures_;
  });
  return snap;
}

void StunTurnRelayServer::DoControlReceive() {
  RTC_DCHECK_RUN_ON(&checker_);
  if (!control_socket_.is_open()) {
    return;
  }
  control_socket_.async_receive_from(
      boost::asio::buffer(rx_buf_), sender_ep_,
      SafeTask(safety_.flag(),
               [this](const boost::system::error_code& ec, size_t nbytes) {
                 RTC_DCHECK_RUN_ON(&checker_);
                 if (!ec && nbytes > 0) {
                   HandleControlDatagram(MakeArrayView(rx_buf_.data(), nbytes),
                                         sender_ep_);
                 }
                 if (control_socket_.is_open()) {
                   DoControlReceive();
                 }
               }));
}

void StunTurnRelayServer::ScheduleSweepTimer() {
  RTC_DCHECK_RUN_ON(&checker_);
  queue_.PostDelayedTask(
      SafeTask(safety_.flag(),
               [this]() {
                 RTC_DCHECK_RUN_ON(&checker_);
                 OnSweepExpiredAllocations();
                 ScheduleSweepTimer();
               }),
      TimeDelta::Seconds(5));
}

void StunTurnRelayServer::OnSweepExpiredAllocations() {
  RTC_DCHECK_RUN_ON(&checker_);
  const Timestamp now = clock_->CurrentTime();
  std::vector<boost::asio::ip::udp::endpoint> expired_clients;

  for (auto& [cli_ep, alloc] : allocations_by_client_) {
    if (now >= alloc->expires_at) {
      expired_clients.push_back(cli_ep);
      continue;
    }
    for (auto pit = alloc->ip_permissions.begin();
         pit != alloc->ip_permissions.end();) {
      if (now >= pit->second) {
        pit = alloc->ip_permissions.erase(pit);
      } else {
        ++pit;
      }
    }
    for (auto cit = alloc->channel_to_peer.begin();
         cit != alloc->channel_to_peer.end();) {
      if (now >= cit->second.expires_at) {
        alloc->peer_to_channel.erase(cit->second.peer_ep);
        cit = alloc->channel_to_peer.erase(cit);
      } else {
        ++cit;
      }
    }
  }

  for (const auto& cli_ep : expired_clients) {
    DestroyAllocation(cli_ep);
  }
}

void StunTurnRelayServer::HandleControlDatagram(
    ArrayView<const uint8_t> datagram,
    const boost::asio::ip::udp::endpoint& from) {
  RTC_DCHECK_RUN_ON(&checker_);
  if (!from.address().is_v4()) {
    return;
  }

  // 1. 快速路径：处理 RFC 5766 第 11 节 4 字节零拷贝 ChannelData 转发帧（首两比特 0b01）。
  if (TurnChannelDataCodec::IsChannelData(datagram)) {
    const auto ait = allocations_by_client_.find(from);
    if (ait == allocations_by_client_.end()) {
      return;
    }
    uint16_t ch = 0;
    ArrayView<const uint8_t> inner;
    if (!TurnChannelDataCodec::Unwrap(datagram, &ch, &inner)) {
      return;
    }
    const Timestamp now = clock_->CurrentTime();
    const auto cit = ait->second->channel_to_peer.find(ch);
    if (cit == ait->second->channel_to_peer.end() ||
        now >= cit->second.expires_at) {
      return;
    }
    ForwardClientPayloadToPeer(ait->second, cit->second.peer_ep, inner, now);
    return;
  }

  // 2. 控制路径：处理 STUN Binding 与 TURN 信令/指示报文。
  if (StunMessage::IsStunPacket(datagram)) {
    HandleStunOrTurnPacket(datagram, from);
  }
}

void StunTurnRelayServer::HandleStunOrTurnPacket(
    ArrayView<const uint8_t> datagram,
    const boost::asio::ip::udp::endpoint& from) {
  RTC_DCHECK_RUN_ON(&checker_);
  const uint16_t raw_type = ReadBigEndian16(datagram.data());
  const Timestamp now = clock_->CurrentTime();

  // 2.1 无状态 STUN Binding 请求（兼容任意 WebRTC 终端与浏览器的 srflx 地址收集）。
  if (raw_type == static_cast<uint16_t>(StunMessageType::kBindingRequest)) {
    auto req = StunMessage::Parse(datagram, "");
    if (!req.has_value()) {
      return;
    }
    ++stat_stun_bindings_;
    StunMessage resp(StunMessageType::kBindingResponse);
    resp.set_transaction_id(req->transaction_id());
    resp.set_xor_mapped_address(from);
    resp.set_software("rtcsdk-turn");
    const auto wire = resp.Serialize("", true);
    boost::system::error_code ec;
    control_socket_.send_to(boost::asio::buffer(wire), from, 0, ec);
    return;
  }

  // 2.2 TURN Send Indication (0x0016)：无事务响应，校验对端 IP 权限后直接转发数据。
  if (raw_type == static_cast<uint16_t>(StunMessageType::kSendIndication)) {
    const auto ait = allocations_by_client_.find(from);
    if (ait == allocations_by_client_.end()) {
      return;
    }
    auto ind = StunMessage::Parse(datagram, "");
    if (!ind.has_value() || !ind->xor_peer_address().has_value() ||
        !ind->data().has_value()) {
      return;
    }
    const auto peer_ep = *ind->xor_peer_address();
    if (!IsAllowedPeerEndpoint(peer_ep)) {
      return;
    }
    const uint32_t peer_ip = peer_ep.address().to_v4().to_uint();
    const auto pit = ait->second->ip_permissions.find(peer_ip);
    if (pit == ait->second->ip_permissions.end() || now >= pit->second) {
      return;
    }
    ForwardClientPayloadToPeer(ait->second, peer_ep, *ind->data(), now);
    return;
  }

  // 2.3 需要长期凭证 MESSAGE-INTEGRITY 鉴权的 TURN 请求族。
  if (raw_type == static_cast<uint16_t>(StunMessageType::kAllocateRequest)) {
    StunMessage req;
    std::string username;
    std::string ikey;
    if (!AuthenticateTurnRequest(datagram, from,
                                 StunMessageType::kAllocateErrorResponse, &req,
                                 &username, &ikey)) {
      return;
    }

    const auto existing = allocations_by_client_.find(from);
    if (existing != allocations_by_client_.end()) {
      if (existing->second->create_tx_id == req.transaction_id()) {
        // 幂等重传上一次成功的 AllocateResponse（防客户端 UDP 丢包重试误判）。
        StunMessage dup_resp(StunMessageType::kAllocateResponse);
        dup_resp.set_transaction_id(req.transaction_id());
        dup_resp.set_xor_relayed_address(existing->second->advertised_relay_ep);
        dup_resp.set_xor_mapped_address(from);
        dup_resp.set_lifetime(existing->second->lifetime_sec);
        const auto wire = dup_resp.Serialize(ikey, true);
        boost::system::error_code ec;
        control_socket_.send_to(boost::asio::buffer(wire), from, 0, ec);
      } else {
        SendErrorResponse(StunMessageType::kAllocateErrorResponse,
                          req.transaction_id(), 437, "Allocation Mismatch",
                          false, from);
      }
      return;
    }

    if (req.requested_transport().value_or(17) != 17) {
      SendErrorResponse(StunMessageType::kAllocateErrorResponse,
                        req.transaction_id(), 442,
                        "Unsupported Transport Protocol", false, from);
      return;
    }

    if (allocations_by_client_.size() >= config_.max_allocations) {
      SendErrorResponse(StunMessageType::kAllocateErrorResponse,
                        req.transaction_id(), 508, "Insufficient Capacity",
                        false, from);
      return;
    }

    boost::system::error_code bind_ec;
    const auto relay_bind_addr =
        boost::asio::ip::make_address_v4(config_.relay_bind_ip, bind_ec);
    if (bind_ec) {
      SendErrorResponse(StunMessageType::kAllocateErrorResponse,
                        req.transaction_id(), 508, "Server Bind Config Error",
                        false, from);
      return;
    }

    auto relay_sock =
        std::make_unique<boost::asio::ip::udp::socket>(queue_.io_context());
    relay_sock->open(boost::asio::ip::udp::v4(), bind_ec);
    if (bind_ec) {
      SendErrorResponse(StunMessageType::kAllocateErrorResponse,
                        req.transaction_id(), 508, "Socket Open Failed", false,
                        from);
      return;
    }
    relay_sock->set_option(
        boost::asio::socket_base::receive_buffer_size(2 * 1024 * 1024),
        bind_ec);
    relay_sock->set_option(
        boost::asio::socket_base::send_buffer_size(2 * 1024 * 1024), bind_ec);

    const uint32_t port_span =
        static_cast<uint32_t>(config_.max_relay_port - config_.min_relay_port) +
        1u;
    uint16_t chosen_port = 0;
    for (uint32_t attempt = 0; attempt < port_span; ++attempt) {
      const uint16_t candidate_port = next_relay_port_cursor_;
      next_relay_port_cursor_ =
          (next_relay_port_cursor_ >= config_.max_relay_port)
              ? config_.min_relay_port
              : static_cast<uint16_t>(next_relay_port_cursor_ + 1);
      if (allocations_by_port_.count(candidate_port) > 0) {
        continue;
      }
      relay_sock->bind(
          boost::asio::ip::udp::endpoint(relay_bind_addr, candidate_port),
          bind_ec);
      if (!bind_ec) {
        chosen_port = candidate_port;
        break;
      }
    }

    if (chosen_port == 0) {
      boost::system::error_code close_ec;
      relay_sock->close(close_ec);
      SendErrorResponse(StunMessageType::kAllocateErrorResponse,
                        req.transaction_id(), 508, "Relay Port Pool Exhausted",
                        false, from);
      return;
    }

    const uint32_t granted_lifetime = std::clamp<uint32_t>(
        req.lifetime().value_or(config_.default_lifetime_sec), 60u,
        config_.max_lifetime_sec);
    const auto adv_ip = DetermineAdvertisedAddress(from);

    auto alloc = std::make_shared<TurnAllocation>();
    alloc->client_endpoint = from;
    alloc->username = std::move(username);
    alloc->integrity_key = ikey;
    alloc->create_tx_id = req.transaction_id();
    alloc->lifetime_sec = granted_lifetime;
    alloc->expires_at = now + TimeDelta::Seconds(granted_lifetime);
    alloc->relay_socket = std::move(relay_sock);
    alloc->relay_port = chosen_port;
    alloc->local_bound_ipv4 = relay_bind_addr;
    alloc->advertised_relay_ep =
        boost::asio::ip::udp::endpoint(adv_ip, chosen_port);

    allocations_by_client_[from] = alloc;
    allocations_by_port_[chosen_port] = alloc;
    ++stat_total_allocs_;
    StartRelayReceiveLoop(alloc);

    RTC_LOG(kInfo) << "TURN allocation created for user='" << alloc->username
                   << "' client=" << from.address().to_string() << ":"
                   << from.port() << " -> relay="
                   << alloc->advertised_relay_ep.address().to_string() << ":"
                   << chosen_port << " (lifetime=" << granted_lifetime << "s)";

    StunMessage resp(StunMessageType::kAllocateResponse);
    resp.set_transaction_id(req.transaction_id());
    resp.set_xor_relayed_address(alloc->advertised_relay_ep);
    resp.set_xor_mapped_address(from);
    resp.set_lifetime(granted_lifetime);
    resp.set_software("rtcsdk-turn");
    const auto wire = resp.Serialize(ikey, true);
    boost::system::error_code send_ec;
    control_socket_.send_to(boost::asio::buffer(wire), from, 0, send_ec);
    return;
  }

  if (raw_type == static_cast<uint16_t>(StunMessageType::kRefreshRequest)) {
    StunMessage req;
    std::string username;
    std::string ikey;
    if (!AuthenticateTurnRequest(datagram, from,
                                 StunMessageType::kRefreshErrorResponse, &req,
                                 &username, &ikey)) {
      return;
    }
    const auto ait = allocations_by_client_.find(from);
    if (ait == allocations_by_client_.end()) {
      SendErrorResponse(StunMessageType::kRefreshErrorResponse,
                        req.transaction_id(), 437, "Allocation Mismatch", false,
                        from);
      return;
    }
    if (ait->second->username != username) {
      SendErrorResponse(StunMessageType::kRefreshErrorResponse,
                        req.transaction_id(), 441, "Wrong Credentials", false,
                        from);
      return;
    }

    const uint32_t requested =
        req.lifetime().value_or(config_.default_lifetime_sec);
    if (requested == 0) {
      StunMessage resp(StunMessageType::kRefreshResponse);
      resp.set_transaction_id(req.transaction_id());
      resp.set_lifetime(0);
      const auto wire = resp.Serialize(ikey, true);
      boost::system::error_code ec;
      control_socket_.send_to(boost::asio::buffer(wire), from, 0, ec);
      DestroyAllocation(from);
      return;
    }

    const uint32_t granted =
        std::clamp<uint32_t>(requested, 60u, config_.max_lifetime_sec);
    ait->second->lifetime_sec = granted;
    ait->second->expires_at = now + TimeDelta::Seconds(granted);
    ait->second->integrity_key = ikey;

    StunMessage resp(StunMessageType::kRefreshResponse);
    resp.set_transaction_id(req.transaction_id());
    resp.set_lifetime(granted);
    const auto wire = resp.Serialize(ikey, true);
    boost::system::error_code ec;
    control_socket_.send_to(boost::asio::buffer(wire), from, 0, ec);
    return;
  }

  if (raw_type ==
      static_cast<uint16_t>(StunMessageType::kCreatePermissionRequest)) {
    StunMessage req;
    std::string username;
    std::string ikey;
    if (!AuthenticateTurnRequest(
            datagram, from, StunMessageType::kCreatePermissionErrorResponse,
            &req, &username, &ikey)) {
      return;
    }
    const auto ait = allocations_by_client_.find(from);
    if (ait == allocations_by_client_.end()) {
      SendErrorResponse(StunMessageType::kCreatePermissionErrorResponse,
                        req.transaction_id(), 437, "Allocation Mismatch", false,
                        from);
      return;
    }
    if (ait->second->username != username) {
      SendErrorResponse(StunMessageType::kCreatePermissionErrorResponse,
                        req.transaction_id(), 441, "Wrong Credentials", false,
                        from);
      return;
    }
    if (req.xor_peer_addresses().empty()) {
      SendErrorResponse(StunMessageType::kCreatePermissionErrorResponse,
                        req.transaction_id(), 400, "Missing XOR-PEER-ADDRESS",
                        false, from);
      return;
    }
    for (const auto& peer_ep : req.xor_peer_addresses()) {
      if (!IsAllowedPeerEndpoint(peer_ep)) {
        SendErrorResponse(StunMessageType::kCreatePermissionErrorResponse,
                          req.transaction_id(), 403, "Forbidden Peer Address",
                          false, from);
        return;
      }
    }
    for (const auto& peer_ep : req.xor_peer_addresses()) {
      ait->second->ip_permissions[peer_ep.address().to_v4().to_uint()] =
          now + TimeDelta::Seconds(kPermissionLifetimeSec);
    }

    StunMessage resp(StunMessageType::kCreatePermissionResponse);
    resp.set_transaction_id(req.transaction_id());
    const auto wire = resp.Serialize(ikey, true);
    boost::system::error_code ec;
    control_socket_.send_to(boost::asio::buffer(wire), from, 0, ec);
    return;
  }

  if (raw_type == static_cast<uint16_t>(StunMessageType::kChannelBindRequest)) {
    StunMessage req;
    std::string username;
    std::string ikey;
    if (!AuthenticateTurnRequest(datagram, from,
                                 StunMessageType::kChannelBindErrorResponse,
                                 &req, &username, &ikey)) {
      return;
    }
    const auto ait = allocations_by_client_.find(from);
    if (ait == allocations_by_client_.end()) {
      SendErrorResponse(StunMessageType::kChannelBindErrorResponse,
                        req.transaction_id(), 437, "Allocation Mismatch", false,
                        from);
      return;
    }
    if (ait->second->username != username) {
      SendErrorResponse(StunMessageType::kChannelBindErrorResponse,
                        req.transaction_id(), 441, "Wrong Credentials", false,
                        from);
      return;
    }
    if (!req.channel_number().has_value() ||
        !req.xor_peer_address().has_value()) {
      SendErrorResponse(StunMessageType::kChannelBindErrorResponse,
                        req.transaction_id(), 400, "Bad ChannelBind Attributes",
                        false, from);
      return;
    }
    const uint16_t ch = *req.channel_number();
    const auto peer_ep = *req.xor_peer_address();
    // RFC 5766 第 11.1 节：合法通道号范围为 0x4000..0x7FFE。
    if (ch < 0x4000u || ch > 0x7FFEu) {
      SendErrorResponse(StunMessageType::kChannelBindErrorResponse,
                        req.transaction_id(), 400,
                        "Channel Number Out Of Range", false, from);
      return;
    }
    if (!IsAllowedPeerEndpoint(peer_ep)) {
      SendErrorResponse(StunMessageType::kChannelBindErrorResponse,
                        req.transaction_id(), 403, "Forbidden Peer Address",
                        false, from);
      return;
    }

    auto& alloc = *ait->second;
    const auto existing_ch = alloc.channel_to_peer.find(ch);
    if (existing_ch != alloc.channel_to_peer.end() &&
        now < existing_ch->second.expires_at &&
        existing_ch->second.peer_ep != peer_ep) {
      SendErrorResponse(StunMessageType::kChannelBindErrorResponse,
                        req.transaction_id(), 400, "Channel Already Bound",
                        false, from);
      return;
    }
    const auto existing_peer = alloc.peer_to_channel.find(peer_ep);
    if (existing_peer != alloc.peer_to_channel.end() &&
        existing_peer->second != ch) {
      const auto old_cit = alloc.channel_to_peer.find(existing_peer->second);
      if (old_cit != alloc.channel_to_peer.end() &&
          now < old_cit->second.expires_at) {
        SendErrorResponse(StunMessageType::kChannelBindErrorResponse,
                          req.transaction_id(), 400, "Peer Already Bound",
                          false, from);
        return;
      }
      alloc.peer_to_channel.erase(existing_peer);
    }

    alloc.channel_to_peer[ch] = TurnAllocation::ChannelBindingInfo{
        peer_ep, now + TimeDelta::Seconds(kChannelLifetimeSec)};
    alloc.peer_to_channel[peer_ep] = ch;
    alloc.ip_permissions[peer_ep.address().to_v4().to_uint()] =
        now + TimeDelta::Seconds(kPermissionLifetimeSec);

    StunMessage resp(StunMessageType::kChannelBindResponse);
    resp.set_transaction_id(req.transaction_id());
    const auto wire = resp.Serialize(ikey, true);
    boost::system::error_code ec;
    control_socket_.send_to(boost::asio::buffer(wire), from, 0, ec);
    return;
  }
}

bool StunTurnRelayServer::AuthenticateTurnRequest(
    ArrayView<const uint8_t> raw_datagram,
    const boost::asio::ip::udp::endpoint& from,
    StunMessageType error_resp_type,
    StunMessage* out_verified_msg,
    std::string* out_username,
    std::string* out_integrity_key) {
  auto unverified = StunMessage::Parse(raw_datagram, "");
  if (!unverified.has_value()) {
    return false;
  }

  if (!unverified->has_message_integrity() ||
      !unverified->username().has_value() || !unverified->realm().has_value() ||
      !unverified->nonce().has_value()) {
    SendErrorResponse(error_resp_type, unverified->transaction_id(), 401,
                      "Unauthorized", true, from);
    return false;
  }

  const int64_t unix_now = CurrentUnixSeconds();
  if (*unverified->realm() != config_.realm) {
    ++stat_auth_failures_;
    SendErrorResponse(error_resp_type, unverified->transaction_id(), 401,
                      "Unauthorized", true, from);
    return false;
  }

  if (!VerifyNonce(*unverified->nonce(), unix_now)) {
    SendErrorResponse(error_resp_type, unverified->transaction_id(), 438,
                      "Stale Nonce", true, from);
    return false;
  }

  const auto password = LookupUserPassword(*unverified->username(), unix_now);
  if (!password.has_value()) {
    ++stat_auth_failures_;
    SendErrorResponse(error_resp_type, unverified->transaction_id(), 401,
                      "Unauthorized", true, from);
    return false;
  }

  const std::string ikey = StunMessage::ComputeLongTermKey(
      *unverified->username(), config_.realm, *password);
  auto verified = StunMessage::Parse(raw_datagram, ikey);
  if (!verified.has_value()) {
    ++stat_auth_failures_;
    SendErrorResponse(error_resp_type, unverified->transaction_id(), 401,
                      "Unauthorized", true, from);
    return false;
  }

  *out_verified_msg = std::move(*verified);
  *out_username = *out_verified_msg->username();
  *out_integrity_key = ikey;
  return true;
}

std::optional<std::string> StunTurnRelayServer::LookupUserPassword(
    std::string_view username,
    int64_t unix_now_sec) const {
  const auto it = config_.static_users.find(std::string(username));
  if (it != config_.static_users.end()) {
    return it->second;
  }

  // 兼容 coturn TURN REST API（格式：`<unix_expiry_ts>:<client_id>`）。
  if (!config_.rest_api_secret.empty()) {
    const size_t colon = username.find(':');
    const std::string_view ts_part =
        (colon == std::string_view::npos) ? username : username.substr(0, colon);
    int64_t exp_ts = 0;
    const auto [ptr, ec] = std::from_chars(
        ts_part.data(), ts_part.data() + ts_part.size(), exp_ts);
    if (ec == std::errc() && ptr == ts_part.data() + ts_part.size() &&
        exp_ts >= unix_now_sec) {
      return ComputeRestApiPassword(config_.rest_api_secret, username);
    }
  }
  return std::nullopt;
}

std::string StunTurnRelayServer::GenerateNonce(int64_t unix_now_sec) const {
  std::ostringstream ts_oss;
  ts_oss << std::hex << std::setw(16) << std::setfill('0')
         << static_cast<uint64_t>(unix_now_sec);
  const std::string ts_hex = ts_oss.str();

  unsigned char mac[20]{};
  unsigned int mac_len = 0;
  HMAC(EVP_sha1(), nonce_secret_.data(), static_cast<int>(nonce_secret_.size()),
       reinterpret_cast<const unsigned char*>(ts_hex.data()), ts_hex.size(),
       mac, &mac_len);

  std::ostringstream full;
  full << ts_hex << '.';
  full << std::hex << std::setfill('0');
  for (int i = 0; i < 8; ++i) {
    full << std::setw(2) << static_cast<int>(mac[i]);
  }
  return full.str();
}

bool StunTurnRelayServer::VerifyNonce(std::string_view nonce,
                                      int64_t unix_now_sec) const {
  if (nonce.size() != 33 || nonce[16] != '.') {
    return false;
  }
  const std::string_view ts_hex = nonce.substr(0, 16);
  uint64_t issued_ts = 0;
  const auto [ptr, ec] =
      std::from_chars(ts_hex.data(), ts_hex.data() + ts_hex.size(), issued_ts,
                      16);
  if (ec != std::errc() || ptr != ts_hex.data() + ts_hex.size()) {
    return false;
  }
  const int64_t age = unix_now_sec - static_cast<int64_t>(issued_ts);
  if (age < -60 || age > kNonceMaxAgeSec) {
    return false;
  }
  const std::string expected =
      GenerateNonce(static_cast<int64_t>(issued_ts));
  return expected.size() == nonce.size() &&
         CRYPTO_memcmp(expected.data(), nonce.data(), nonce.size()) == 0;
}

void StunTurnRelayServer::SendErrorResponse(
    StunMessageType error_type,
    const StunTransactionId& tx_id,
    int code,
    std::string_view reason,
    bool include_challenge,
    const boost::asio::ip::udp::endpoint& to) {
  StunMessage resp(error_type);
  resp.set_transaction_id(tx_id);
  resp.set_error_code(code, std::string(reason));
  if (include_challenge) {
    resp.set_realm(config_.realm);
    resp.set_nonce(GenerateNonce(CurrentUnixSeconds()));
  }
  const auto wire = resp.Serialize("", true);
  boost::system::error_code ec;
  control_socket_.send_to(boost::asio::buffer(wire), to, 0, ec);
}

bool StunTurnRelayServer::IsAllowedPeerEndpoint(
    const boost::asio::ip::udp::endpoint& peer_ep) const {
  if (!peer_ep.address().is_v4() || peer_ep.port() == 0) {
    return false;
  }
  const auto ipv4 = peer_ep.address().to_v4();
  if (ipv4.is_unspecified() || ipv4.is_multicast() ||
      ipv4.to_uint() == 0xFFFFFFFFu) {
    return false;
  }
  if (!config_.allow_loopback_peers && ipv4.is_loopback()) {
    return false;
  }
  return true;
}

boost::asio::ip::address_v4 StunTurnRelayServer::DetermineAdvertisedAddress(
    const boost::asio::ip::udp::endpoint& client_ep) const {
  if (parsed_external_ipv4_.has_value()) {
    return *parsed_external_ipv4_;
  }
  boost::system::error_code ec;
  const auto r_addr = boost::asio::ip::make_address_v4(config_.relay_bind_ip, ec);
  if (!ec && !r_addr.is_unspecified()) {
    return r_addr;
  }
  const auto b_addr = boost::asio::ip::make_address_v4(config_.bind_ip, ec);
  if (!ec && !b_addr.is_unspecified()) {
    return b_addr;
  }
  if (client_ep.address().is_loopback()) {
    return boost::asio::ip::make_address_v4("127.0.0.1");
  }
  // 当监听 0.0.0.0 时，利用内核路由表查询到达该客户端的精确出站网卡 IPv4 地址（零发包开销）。
  boost::asio::ip::udp::socket probe(queue_.io_context());
  probe.open(boost::asio::ip::udp::v4(), ec);
  if (!ec) {
    probe.connect(client_ep, ec);
    if (!ec) {
      const auto local_ep = probe.local_endpoint(ec);
      if (!ec && local_ep.address().is_v4() &&
          !local_ep.address().is_unspecified()) {
        return local_ep.address().to_v4();
      }
    }
  }
  return boost::asio::ip::make_address_v4("127.0.0.1");
}

std::shared_ptr<StunTurnRelayServer::TurnAllocation>
StunTurnRelayServer::FindHairpinTarget(
    const boost::asio::ip::udp::endpoint& target_ep) const {
  if (!target_ep.address().is_v4()) {
    return nullptr;
  }
  const auto it = allocations_by_port_.find(target_ep.port());
  if (it == allocations_by_port_.end() || it->second->closed) {
    return nullptr;
  }
  const auto target_ip = target_ep.address().to_v4();
  if (target_ip == it->second->advertised_relay_ep.address().to_v4() ||
      (!it->second->local_bound_ipv4.is_unspecified() &&
       target_ip == it->second->local_bound_ipv4) ||
      (config_.allow_loopback_peers && target_ip.is_loopback())) {
    return it->second;
  }
  return nullptr;
}

void StunTurnRelayServer::ForwardClientPayloadToPeer(
    const std::shared_ptr<TurnAllocation>& sender_alloc,
    const boost::asio::ip::udp::endpoint& peer_ep,
    ArrayView<const uint8_t> payload,
    Timestamp now) {
  if (!sender_alloc || sender_alloc->closed || !sender_alloc->relay_socket) {
    return;
  }
  ++stat_relayed_pkts_;
  stat_relayed_bytes_ += payload.size();

  // 若目标端点属于本机另一个活跃 TURN 分配（例如两个对称型 NAT 客户端均通过同一台公网 TURN 中继），
  // 直接执行内存级发卡弯（Hairpinning）投递，彻底规避云厂商 VPC 阻断弹性公网 IP 自环 UDP 的问题。
  if (auto hairpin_dst = FindHairpinTarget(peer_ep)) {
    if (hairpin_dst.get() != sender_alloc.get()) {
      DeliverPeerPayloadToClient(hairpin_dst, sender_alloc->advertised_relay_ep,
                                 payload, now);
      return;
    }
  }

  boost::system::error_code ec;
  sender_alloc->relay_socket->send_to(
      boost::asio::buffer(payload.data(), payload.size()), peer_ep, 0, ec);
}

void StunTurnRelayServer::DeliverPeerPayloadToClient(
    const std::shared_ptr<TurnAllocation>& target_alloc,
    const boost::asio::ip::udp::endpoint& peer_ep,
    ArrayView<const uint8_t> payload,
    Timestamp now) {
  if (!target_alloc || target_alloc->closed || !peer_ep.address().is_v4()) {
    return;
  }
  const uint32_t peer_ip = peer_ep.address().to_v4().to_uint();
  const auto pit = target_alloc->ip_permissions.find(peer_ip);
  if (pit == target_alloc->ip_permissions.end() || now >= pit->second) {
    return;
  }

  ++stat_relayed_pkts_;
  stat_relayed_bytes_ += payload.size();

  boost::system::error_code ec;
  const auto pc_it = target_alloc->peer_to_channel.find(peer_ep);
  if (pc_it != target_alloc->peer_to_channel.end()) {
    const auto cit = target_alloc->channel_to_peer.find(pc_it->second);
    if (cit != target_alloc->channel_to_peer.end() &&
        now < cit->second.expires_at) {
      const auto ch_wire = TurnChannelDataCodec::Wrap(pc_it->second, payload);
      control_socket_.send_to(boost::asio::buffer(ch_wire),
                              target_alloc->client_endpoint, 0, ec);
      return;
    }
  }

  StunMessage data_ind(StunMessageType::kDataIndication);
  data_ind.set_xor_peer_address(peer_ep);
  data_ind.set_data(payload);
  const auto ind_wire = data_ind.Serialize("", true);
  control_socket_.send_to(boost::asio::buffer(ind_wire),
                          target_alloc->client_endpoint, 0, ec);
}

void StunTurnRelayServer::StartRelayReceiveLoop(
    const std::shared_ptr<TurnAllocation>& alloc) {
  RTC_DCHECK_RUN_ON(&checker_);
  if (!alloc || alloc->closed || !alloc->relay_socket ||
      !alloc->relay_socket->is_open()) {
    return;
  }

  alloc->relay_socket->async_receive_from(
      boost::asio::buffer(alloc->relay_rx_buf), alloc->relay_sender_ep,
      SafeTask(safety_.flag(),
               [this, alloc](const boost::system::error_code& ec,
                             size_t nbytes) {
                 RTC_DCHECK_RUN_ON(&checker_);
                 if (alloc->closed) {
                   return;
                 }
                 if (!ec && nbytes > 0) {
                   DeliverPeerPayloadToClient(
                       alloc, alloc->relay_sender_ep,
                       MakeArrayView(alloc->relay_rx_buf.data(), nbytes),
                       clock_->CurrentTime());
                 }
                 if (!alloc->closed && alloc->relay_socket &&
                     alloc->relay_socket->is_open()) {
                   StartRelayReceiveLoop(alloc);
                 }
               }));
}

void StunTurnRelayServer::DestroyAllocation(
    const boost::asio::ip::udp::endpoint& client_ep) {
  RTC_DCHECK_RUN_ON(&checker_);
  const auto it = allocations_by_client_.find(client_ep);
  if (it == allocations_by_client_.end()) {
    return;
  }
  auto alloc = it->second;
  alloc->closed = true;
  if (alloc->relay_socket) {
    boost::system::error_code ec;
    alloc->relay_socket->close(ec);
  }
  allocations_by_port_.erase(alloc->relay_port);
  allocations_by_client_.erase(it);
  RTC_LOG(kInfo) << "TURN allocation released (relay_port="
                 << alloc->relay_port << ", user='" << alloc->username << "')";
}

}  // namespace rtc
