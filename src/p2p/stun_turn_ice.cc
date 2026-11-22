#include "p2p/stun_turn_ice.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <algorithm>
#include <cstring>
#include <sstream>

#include <boost/crc.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "modules/rtp_rtcp/byte_io.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {
constexpr uint32_t kStunFingerprintXor = 0x5354554Eu;

void WriteUint64BE(uint8_t* dst, uint64_t val) {
  WriteBigEndian32(dst, static_cast<uint32_t>(val >> 32));
  WriteBigEndian32(dst + 4, static_cast<uint32_t>(val & 0xFFFFFFFFULL));
}

uint64_t ReadUint64BE(const uint8_t* src) {
  return (static_cast<uint64_t>(ReadBigEndian32(src)) << 32) |
         static_cast<uint64_t>(ReadBigEndian32(src + 4));
}

void AppendAttr(uint16_t type,
                const uint8_t* val,
                size_t len,
                std::vector<uint8_t>* buf) {
  const size_t padded = (len + 3) & ~size_t{3};
  const size_t pos = buf->size();
  buf->resize(pos + 4 + padded, 0);
  WriteBigEndian16(buf->data() + pos, type);
  WriteBigEndian16(buf->data() + pos + 2, static_cast<uint16_t>(len));
  if (len > 0 && val != nullptr) {
    std::memcpy(buf->data() + pos + 4, val, len);
  }
}

void AppendXorEndpointAttr(uint16_t attr_type,
                           const boost::asio::ip::udp::endpoint& ep,
                           const StunTransactionId& tx_id,
                           std::vector<uint8_t>* buf) {
  if (ep.address().is_v4()) {
    uint8_t v[8]{};
    v[0] = 0;
    v[1] = 0x01;
    const uint16_t xport =
        ep.port() ^ static_cast<uint16_t>(kStunMagicCookie >> 16);
    WriteBigEndian16(v + 2, xport);
    const uint32_t xaddr = ep.address().to_v4().to_uint() ^ kStunMagicCookie;
    WriteBigEndian32(v + 4, xaddr);
    AppendAttr(attr_type, v, 8, buf);
  } else if (ep.address().is_v6()) {
    uint8_t v[20]{};
    v[0] = 0;
    v[1] = 0x02;
    const uint16_t xport =
        ep.port() ^ static_cast<uint16_t>(kStunMagicCookie >> 16);
    WriteBigEndian16(v + 2, xport);
    const auto bytes = ep.address().to_v6().to_bytes();
    uint8_t xor_mask[16];
    WriteBigEndian32(xor_mask, kStunMagicCookie);
    std::memcpy(xor_mask + 4, tx_id.data(), 12);
    for (size_t i = 0; i < 16; ++i) {
      v[4 + i] = bytes[i] ^ xor_mask[i];
    }
    AppendAttr(attr_type, v, 20, buf);
  }
}

std::optional<boost::asio::ip::udp::endpoint> ParseXorEndpointAttr(
    const uint8_t* val,
    size_t len,
    const StunTransactionId& tx_id) {
  if (len < 8) {
    return std::nullopt;
  }
  const uint8_t family = val[1];
  const uint16_t port =
      ReadBigEndian16(val + 2) ^ static_cast<uint16_t>(kStunMagicCookie >> 16);
  if (family == 0x01) {
    const uint32_t ip = ReadBigEndian32(val + 4) ^ kStunMagicCookie;
    return boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4(ip),
                                          port);
  }
  if (family == 0x02 && len >= 20) {
    boost::asio::ip::address_v6::bytes_type b;
    uint8_t xor_mask[16];
    WriteBigEndian32(xor_mask, kStunMagicCookie);
    std::memcpy(xor_mask + 4, tx_id.data(), 12);
    for (size_t i = 0; i < 16; ++i) {
      b[i] = val[4 + i] ^ xor_mask[i];
    }
    return boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6(b), port);
  }
  return std::nullopt;
}

const char* IceStateToString(IceTransportState state) {
  switch (state) {
    case IceTransportState::kNew:
      return "kNew";
    case IceTransportState::kChecking:
      return "kChecking";
    case IceTransportState::kConnected:
      return "kConnected";
    case IceTransportState::kCompleted:
      return "kCompleted";
    case IceTransportState::kDisconnected:
      return "kDisconnected";
    case IceTransportState::kFailed:
      return "kFailed";
  }
  return "Unknown";
}
}  // namespace

// ======================= StunMessage STUN 报文编解码 =======================

StunMessage::StunMessage(StunMessageType type)
    : type_(type), tx_id_(GenerateTransactionId()) {}

bool StunMessage::IsStunPacket(ArrayView<const uint8_t> packet) {
  if (packet.size() < 20) {
    return false;
  }
  if ((packet[0] & 0xC0) != 0x00) {
    return false;
  }
  return ReadBigEndian32(packet.data() + 4) == kStunMagicCookie;
}

StunTransactionId StunMessage::GenerateTransactionId() {
  StunTransactionId id{};
  RAND_bytes(id.data(), static_cast<int>(id.size()));
  return id;
}

std::string StunMessage::ComputeLongTermKey(std::string_view username,
                                            std::string_view realm,
                                            std::string_view password) {
  std::string input;
  input.reserve(username.size() + realm.size() + password.size() + 2);
  input.append(username);
  input.push_back(':');
  input.append(realm);
  input.push_back(':');
  input.append(password);

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
  EVP_DigestUpdate(ctx, input.data(), input.size());
  EVP_DigestFinal_ex(ctx, digest, &digest_len);
  EVP_MD_CTX_free(ctx);
  return std::string(reinterpret_cast<const char*>(digest), digest_len);
}

std::vector<uint8_t> StunMessage::Serialize(std::string_view integrity_key,
                                            bool add_fingerprint) const {
  std::vector<uint8_t> out(20, 0);
  WriteBigEndian16(out.data(), static_cast<uint16_t>(type_));
  WriteBigEndian32(out.data() + 4, kStunMagicCookie);
  std::memcpy(out.data() + 8, tx_id_.data(), 12);

  if (username_.has_value()) {
    AppendAttr(stun_attr_type::kUsername,
               reinterpret_cast<const uint8_t*>(username_->data()),
               username_->size(), &out);
  }
  if (realm_.has_value()) {
    AppendAttr(stun_attr_type::kRealm,
               reinterpret_cast<const uint8_t*>(realm_->data()), realm_->size(),
               &out);
  }
  if (nonce_.has_value()) {
    AppendAttr(stun_attr_type::kNonce,
               reinterpret_cast<const uint8_t*>(nonce_->data()), nonce_->size(),
               &out);
  }
  if (priority_.has_value()) {
    uint8_t b[4];
    WriteBigEndian32(b, *priority_);
    AppendAttr(stun_attr_type::kPriority, b, 4, &out);
  }
  if (use_candidate_) {
    AppendAttr(stun_attr_type::kUseCandidate, nullptr, 0, &out);
  }
  if (ice_controlling_.has_value()) {
    uint8_t b[8];
    WriteUint64BE(b, *ice_controlling_);
    AppendAttr(stun_attr_type::kIceControlling, b, 8, &out);
  }
  if (ice_controlled_.has_value()) {
    uint8_t b[8];
    WriteUint64BE(b, *ice_controlled_);
    AppendAttr(stun_attr_type::kIceControlled, b, 8, &out);
  }
  if (channel_number_.has_value()) {
    uint8_t b[4]{};
    WriteBigEndian16(b, *channel_number_);
    AppendAttr(stun_attr_type::kChannelNumber, b, 4, &out);
  }
  if (error_code_.has_value()) {
    uint8_t b[4]{};
    b[2] = static_cast<uint8_t>(*error_code_ / 100);
    b[3] = static_cast<uint8_t>(*error_code_ % 100);
    AppendAttr(stun_attr_type::kErrorCode, b, 4, &out);
  }
  if (xor_mapped_.has_value()) {
    AppendXorEndpointAttr(stun_attr_type::kXorMappedAddress, *xor_mapped_,
                          tx_id_, &out);
  }
  if (xor_relayed_.has_value()) {
    AppendXorEndpointAttr(stun_attr_type::kXorRelayedAddress, *xor_relayed_,
                          tx_id_, &out);
  }
  if (xor_peer_.has_value()) {
    AppendXorEndpointAttr(stun_attr_type::kXorPeerAddress, *xor_peer_, tx_id_,
                          &out);
  }

  if (!integrity_key.empty()) {
    const uint16_t len_with_mi = static_cast<uint16_t>((out.size() - 20) + 24);
    WriteBigEndian16(out.data() + 2, len_with_mi);

    unsigned char hmac_val[20];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha1(), integrity_key.data(),
         static_cast<int>(integrity_key.size()), out.data(), out.size(),
         hmac_val, &hmac_len);
    AppendAttr(stun_attr_type::kMessageIntegrity, hmac_val, 20, &out);
  }

  if (add_fingerprint) {
    const uint16_t len_with_fp = static_cast<uint16_t>((out.size() - 20) + 8);
    WriteBigEndian16(out.data() + 2, len_with_fp);

    boost::crc_32_type crc;
    crc.process_bytes(out.data(), out.size());
    const uint32_t fp = crc.checksum() ^ kStunFingerprintXor;
    uint8_t fp_bytes[4];
    WriteBigEndian32(fp_bytes, fp);
    AppendAttr(stun_attr_type::kFingerprint, fp_bytes, 4, &out);
  } else {
    WriteBigEndian16(out.data() + 2, static_cast<uint16_t>(out.size() - 20));
  }
  return out;
}

std::optional<StunMessage> StunMessage::Parse(
    ArrayView<const uint8_t> packet,
    std::string_view verify_integrity_key) {
  if (!IsStunPacket(packet)) {
    return std::nullopt;
  }
  const uint8_t* data = packet.data();
  const size_t len = packet.size();
  const uint16_t msg_len = ReadBigEndian16(data + 2);
  if ((msg_len % 4) != 0 || static_cast<size_t>(20 + msg_len) > len) {
    return std::nullopt;
  }

  StunMessage msg;
  msg.type_ = static_cast<StunMessageType>(ReadBigEndian16(data));
  std::memcpy(msg.tx_id_.data(), data + 8, 12);

  bool mi_verified = verify_integrity_key.empty();
  size_t offset = 20;
  const size_t end = 20 + msg_len;

  while (offset + 4 <= end) {
    const uint16_t attr_type = ReadBigEndian16(data + offset);
    const uint16_t attr_len = ReadBigEndian16(data + offset + 2);
    const size_t padded_len = (static_cast<size_t>(attr_len) + 3) & ~size_t{3};
    if (offset + 4 + padded_len > end) {
      return std::nullopt;
    }
    const uint8_t* val = data + offset + 4;

    switch (attr_type) {
      case stun_attr_type::kUsername:
        msg.username_.emplace(reinterpret_cast<const char*>(val), attr_len);
        break;
      case stun_attr_type::kRealm:
        msg.realm_.emplace(reinterpret_cast<const char*>(val), attr_len);
        break;
      case stun_attr_type::kNonce:
        msg.nonce_.emplace(reinterpret_cast<const char*>(val), attr_len);
        break;
      case stun_attr_type::kPriority:
        if (attr_len == 4) {
          msg.priority_ = ReadBigEndian32(val);
        }
        break;
      case stun_attr_type::kUseCandidate:
        msg.use_candidate_ = true;
        break;
      case stun_attr_type::kIceControlling:
        if (attr_len == 8) {
          msg.ice_controlling_ = ReadUint64BE(val);
        }
        break;
      case stun_attr_type::kIceControlled:
        if (attr_len == 8) {
          msg.ice_controlled_ = ReadUint64BE(val);
        }
        break;
      case stun_attr_type::kChannelNumber:
        if (attr_len >= 2) {
          msg.channel_number_ = ReadBigEndian16(val);
        }
        break;
      case stun_attr_type::kErrorCode:
        if (attr_len >= 4) {
          msg.error_code_ = static_cast<int>(val[2] & 0x07) * 100 + val[3];
        }
        break;
      case stun_attr_type::kXorMappedAddress:
        msg.xor_mapped_ = ParseXorEndpointAttr(val, attr_len, msg.tx_id_);
        break;
      case stun_attr_type::kXorRelayedAddress:
        msg.xor_relayed_ = ParseXorEndpointAttr(val, attr_len, msg.tx_id_);
        break;
      case stun_attr_type::kXorPeerAddress:
        msg.xor_peer_ = ParseXorEndpointAttr(val, attr_len, msg.tx_id_);
        break;
      case stun_attr_type::kMessageIntegrity:
        if (!verify_integrity_key.empty()) {
          if (attr_len != 20) {
            return std::nullopt;
          }
          std::vector<uint8_t> prefix(data, data + offset);
          WriteBigEndian16(prefix.data() + 2,
                           static_cast<uint16_t>((offset - 20) + 24));
          unsigned char expected[20];
          unsigned int exp_len = 0;
          HMAC(EVP_sha1(), verify_integrity_key.data(),
               static_cast<int>(verify_integrity_key.size()), prefix.data(),
               prefix.size(), expected, &exp_len);
          if (CRYPTO_memcmp(expected, val, 20) != 0) {
            RTC_LOG(kVerbose) << "STUN MESSAGE-INTEGRITY verification failed";
            return std::nullopt;
          }
          mi_verified = true;
        }
        break;
      case stun_attr_type::kFingerprint:
        if (attr_len == 4) {
          std::vector<uint8_t> prefix(data, data + offset);
          WriteBigEndian16(prefix.data() + 2,
                           static_cast<uint16_t>((offset - 20) + 8));
          boost::crc_32_type crc;
          crc.process_bytes(prefix.data(), prefix.size());
          const uint32_t expected_fp = crc.checksum() ^ kStunFingerprintXor;
          if (ReadBigEndian32(val) != expected_fp) {
            RTC_LOG(kWarning) << "STUN FINGERPRINT CRC32 mismatch";
            return std::nullopt;
          }
        }
        break;
      default:
        break;
    }
    offset += 4 + padded_len;
  }

  if (!mi_verified) {
    return std::nullopt;
  }
  return msg;
}

// ======================= TurnChannelDataCodec TURN 通道数据编解码 =======================

std::vector<uint8_t> TurnChannelDataCodec::Wrap(
    uint16_t channel_number,
    ArrayView<const uint8_t> payload) {
  const size_t padded = (payload.size() + 3) & ~size_t{3};
  std::vector<uint8_t> out(4 + padded, 0);
  WriteBigEndian16(out.data(), channel_number);
  WriteBigEndian16(out.data() + 2, static_cast<uint16_t>(payload.size()));
  if (!payload.empty()) {
    std::memcpy(out.data() + 4, payload.data(), payload.size());
  }
  return out;
}

bool TurnChannelDataCodec::Unwrap(ArrayView<const uint8_t> packet,
                                  uint16_t* out_channel,
                                  ArrayView<const uint8_t>* out_payload) {
  if (!IsChannelData(packet)) {
    return false;
  }
  const uint16_t ch = ReadBigEndian16(packet.data());
  const uint16_t plen = ReadBigEndian16(packet.data() + 2);
  if (static_cast<size_t>(4 + plen) > packet.size()) {
    return false;
  }
  *out_channel = ch;
  *out_payload = packet.subview(4, plen);
  return true;
}

// ======================= IceCandidate 与 IceTransportChannel ICE 传输通道 =======================

uint32_t IceCandidate::ComputePriority(IceCandidateType type,
                                       uint16_t local_pref,
                                       uint8_t component_id) {
  uint32_t type_pref = 126;
  switch (type) {
    case IceCandidateType::kHost:
      type_pref = 126;
      break;
    case IceCandidateType::kPrflx:
      type_pref = 110;
      break;
    case IceCandidateType::kSrflx:
      type_pref = 100;
      break;
    case IceCandidateType::kRelay:
      type_pref = 0;
      break;
  }
  return (type_pref << 24) | (static_cast<uint32_t>(local_pref) << 8) |
         static_cast<uint32_t>(256 - component_id);
}

std::string IceCandidate::ToSdpAttribute() const {
  const char* type_str = "host";
  switch (type) {
    case IceCandidateType::kHost:
      type_str = "host";
      break;
    case IceCandidateType::kSrflx:
      type_str = "srflx";
      break;
    case IceCandidateType::kPrflx:
      type_str = "prflx";
      break;
    case IceCandidateType::kRelay:
      type_str = "relay";
      break;
  }
  std::ostringstream oss;
  oss << "candidate:" << foundation << " " << component << " " << protocol
      << " " << priority << " " << address.address().to_string() << " "
      << address.port() << " typ " << type_str;
  return oss.str();
}

std::optional<IceCandidate> IceCandidate::FromSdpAttribute(
    std::string_view line) {
  if (line.substr(0, 2) == "a=") {
    line.remove_prefix(2);
  }
  if (line.substr(0, 10) == "candidate:") {
    line.remove_prefix(10);
  }

  std::istringstream iss{std::string(line)};
  IceCandidate c;
  std::string ip_str;
  std::string typ_kw;
  std::string typ_val;
  uint16_t port = 0;
  if (!(iss >> c.foundation >> c.component >> c.protocol >> c.priority >>
        ip_str >> port >> typ_kw >> typ_val)) {
    return std::nullopt;
  }
  std::transform(c.protocol.begin(), c.protocol.end(), c.protocol.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>((ch >= 'A' && ch <= 'Z')
                                                ? (ch - 'A' + 'a')
                                                : ch);
                 });
  if (c.protocol != "udp") {
    return std::nullopt;
  }
  boost::system::error_code ec;
  const auto addr = boost::asio::ip::make_address(ip_str, ec);
  if (ec) {
    return std::nullopt;
  }
  c.address = boost::asio::ip::udp::endpoint(addr, port);
  if (typ_val == "srflx") {
    c.type = IceCandidateType::kSrflx;
  } else if (typ_val == "prflx") {
    c.type = IceCandidateType::kPrflx;
  } else if (typ_val == "relay") {
    c.type = IceCandidateType::kRelay;
  } else {
    c.type = IceCandidateType::kHost;
  }
  return c;
}

IceTransportChannel::IceTransportChannel(Clock* clock,
                                         TaskQueueBoost* network_queue,
                                         IceTransportObserver* observer,
                                         bool controlling_role)
    : clock_(clock),
      network_queue_(network_queue),
      net_checker_(network_queue),
      observer_(observer),
      controlling_role_(controlling_role),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {
  RAND_bytes(reinterpret_cast<uint8_t*>(&tie_breaker_), sizeof(tie_breaker_));
}

IceTransportChannel::~IceTransportChannel() {
  network_queue_->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    safety_.flag()->SetNotAlive();
    if (socket_ && socket_->is_open()) {
      boost::system::error_code ec;
      socket_->close(ec);
    }
  });
}

void IceTransportChannel::SetIceControlling(bool controlling) {
  network_queue_->PostTask(SafeTask(safety_.flag(), [this, controlling]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    if (controlling_role_ != controlling) {
      controlling_role_ = controlling;
      RebuildCandidatePairs();
    }
  }));
}

void IceTransportChannel::SetLocalIceParameters(const IceParameters& params) {
  network_queue_->PostTask(SafeTask(safety_.flag(), [this, params]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    local_params_ = params;
  }));
}

void IceTransportChannel::SetRemoteIceParameters(const IceParameters& params) {
  network_queue_->PostTask(SafeTask(safety_.flag(), [this, params]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    remote_params_ = params;
    RebuildCandidatePairs();
  }));
}

void IceTransportChannel::ConfigureServers(
    const std::vector<TurnServerSpec>& servers) {
  network_queue_->PostTask(SafeTask(safety_.flag(), [this, servers]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    servers_ = servers;
  }));
}

bool IceTransportChannel::StartGatheringAndBind(uint16_t preferred_local_port) {
  return network_queue_->Invoke([this, preferred_local_port]() -> bool {
    RTC_DCHECK_RUN_ON(&net_checker_);
    boost::system::error_code ec;
    socket_ = std::make_unique<boost::asio::ip::udp::socket>(
        network_queue_->io_context());
    socket_->open(boost::asio::ip::udp::v4(), ec);
    if (ec) {
      RTC_LOG(kError) << "Failed to open ICE UDP socket: " << ec.message();
      return false;
    }
    socket_->set_option(
        boost::asio::socket_base::receive_buffer_size(2 * 1024 * 1024), ec);
    socket_->set_option(
        boost::asio::socket_base::send_buffer_size(2 * 1024 * 1024), ec);

    socket_->bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(),
                                                 preferred_local_port),
                  ec);
    if (ec) {
      RTC_LOG(kError) << "Failed to bind ICE UDP port " << preferred_local_port
                      << ": " << ec.message();
      return false;
    }
    bound_port_ = socket_->local_endpoint(ec).port();

    local_candidates_.clear();
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == 0 && ifaddr != nullptr) {
      uint16_t pref = 65535;
      for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET) {
          continue;
        }
        if ((ifa->ifa_flags & IFF_UP) == 0) {
          continue;
        }
        const auto* sin =
            reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_addr);
        const uint32_t host_ip = ntohl(sin->sin_addr.s_addr);
        IceCandidate cand;
        cand.type = IceCandidateType::kHost;
        cand.priority =
            IceCandidate::ComputePriority(IceCandidateType::kHost, pref--);
        cand.address = boost::asio::ip::udp::endpoint(
            boost::asio::ip::address_v4(host_ip), bound_port_);
        local_candidates_.push_back(cand);
        if (auto* obs = observer_.load(std::memory_order_acquire)) {
          obs->OnLocalCandidateGathered(cand);
        }
      }
      freeifaddrs(ifaddr);
    }
    if (local_candidates_.empty()) {
      IceCandidate lo;
      lo.type = IceCandidateType::kHost;
      lo.priority = IceCandidate::ComputePriority(IceCandidateType::kHost);
      lo.address = boost::asio::ip::udp::endpoint(
          boost::asio::ip::make_address_v4("127.0.0.1"), bound_port_);
      local_candidates_.push_back(lo);
      if (auto* obs = observer_.load(std::memory_order_acquire)) {
        obs->OnLocalCandidateGathered(lo);
      }
    }

    RTC_LOG(kInfo) << "ICE socket bound on UDP port=" << bound_port_
                   << " gathered_host_candidates=" << local_candidates_.size();

    for (const auto& srv : servers_) {
      if (!srv.is_turn) {
        StunMessage req(StunMessageType::kBindingRequest);
        auto bytes = req.Serialize("", true);
        boost::system::error_code send_ec;
        socket_->send_to(boost::asio::buffer(bytes), srv.server_endpoint, 0,
                         send_ec);
      } else {
        StartTurnAllocation(srv);
      }
    }

    DoAsyncReceive();
    RebuildCandidatePairs();
    OnPeriodicCheckTick();
    return true;
  });
}

void IceTransportChannel::StartTurnAllocation(const TurnServerSpec& turn) {
  ActiveTurnState ts;
  ts.spec = turn;
  turn_state_ = ts;

  RTC_LOG(kInfo) << "Initiating TURN Allocate to "
                 << turn.server_endpoint.address().to_string() << ":"
                 << turn.server_endpoint.port();
  StunMessage alloc(StunMessageType::kAllocateRequest);
  auto bytes = alloc.Serialize("", true);
  boost::system::error_code send_ec;
  socket_->send_to(boost::asio::buffer(bytes), turn.server_endpoint, 0,
                   send_ec);
}

void IceTransportChannel::AddRemoteCandidate(const IceCandidate& remote) {
  network_queue_->PostTask(SafeTask(safety_.flag(), [this, remote]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    remote_candidates_.push_back(remote);
    RebuildCandidatePairs();
    if (state_.load(std::memory_order_relaxed) == IceTransportState::kNew) {
      SetState(IceTransportState::kChecking);
    }
    if (!pairs_.empty()) {
      SendConnectivityCheck(0);
    }
  }));
}

void IceTransportChannel::RestartIce(const IceParameters& new_local_params) {
  network_queue_->PostTask(SafeTask(safety_.flag(), [this, new_local_params]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    RTC_LOG(kInfo) << "Performing ICE Restart (new ufrag="
                   << new_local_params.ufrag << ")";
    local_params_ = new_local_params;
    remote_candidates_.clear();
    pairs_.clear();
    selected_pair_idx_.reset();
    pending_pings_.clear();
    SetState(IceTransportState::kChecking);
  }));
}

void IceTransportChannel::RebuildCandidatePairs() {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (local_candidates_.empty() || remote_candidates_.empty()) {
    return;
  }

  pairs_.clear();
  selected_pair_idx_.reset();

  for (const auto& lc : local_candidates_) {
    for (const auto& rc : remote_candidates_) {
      if (lc.address.address().is_v4() != rc.address.address().is_v4()) {
        continue;
      }
      if (lc.address.address().is_loopback() !=
          rc.address.address().is_loopback()) {
        continue;
      }
      CandidatePair pair;
      pair.local = lc;
      pair.remote = rc;
      pair.via_turn_relay = (lc.type == IceCandidateType::kRelay);
      const uint32_t ctrl_p = controlling_role_ ? lc.priority : rc.priority;
      const uint32_t ctle_p = controlling_role_ ? rc.priority : lc.priority;
      pair.priority = ComputeCandidatePairPriority(ctrl_p, ctle_p);
      pairs_.push_back(pair);
    }
  }

  std::sort(pairs_.begin(), pairs_.end(),
            [](const CandidatePair& a, const CandidatePair& b) {
              return a.priority > b.priority;
            });
}

void IceTransportChannel::SendConnectivityCheck(size_t pair_index) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (!socket_ || pair_index >= pairs_.size() || remote_params_.pwd.empty()) {
    return;
  }

  CandidatePair& pair = pairs_[pair_index];
  StunMessage req(StunMessageType::kBindingRequest);
  req.set_username(remote_params_.ufrag + ":" + local_params_.ufrag);
  req.set_priority(IceCandidate::ComputePriority(IceCandidateType::kPrflx));
  if (controlling_role_) {
    req.set_ice_controlling(tie_breaker_);
    if (remote_params_.ice_lite || pair.state == PairState::kSucceeded) {
      req.set_use_candidate(true);
    }
  } else {
    req.set_ice_controlled(tie_breaker_);
  }

  const Timestamp now = clock_->CurrentTime();
  pending_pings_[req.transaction_id()] = PendingPing{pair_index, now};
  pair.last_ping_sent = now;
  ++pair.unacked_pings;
  if (pair.state == PairState::kWaiting) {
    pair.state = PairState::kInProgress;
  }

  auto wire = req.Serialize(remote_params_.pwd, true);
  boost::system::error_code send_ec;
  if (pair.via_turn_relay && turn_state_.has_value() &&
      turn_state_->channel_bound) {
    auto ch_wire = TurnChannelDataCodec::Wrap(turn_state_->bound_channel, wire);
    socket_->send_to(boost::asio::buffer(ch_wire),
                     turn_state_->spec.server_endpoint, 0, send_ec);
  } else {
    socket_->send_to(boost::asio::buffer(wire), pair.remote.address, 0,
                     send_ec);
  }
}

void IceTransportChannel::OnPeriodicCheckTick() {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const Timestamp now = clock_->CurrentTime();

  if (selected_pair_idx_.has_value() && *selected_pair_idx_ < pairs_.size()) {
    auto& sel = pairs_[*selected_pair_idx_];
    if (sel.last_ping_sent.IsMinusInfinity() ||
        (now - sel.last_ping_sent) >= TimeDelta::Millis(500)) {
      SendConnectivityCheck(*selected_pair_idx_);
    }
    if (sel.last_response_received.IsFinite() &&
        (now - sel.last_response_received) > TimeDelta::Seconds(5)) {
      RTC_LOG(kWarning) << "ICE nominated pair timed out after 5s silence";
      SetState(IceTransportState::kDisconnected);
      selected_pair_idx_.reset();
    }
  } else if (!pairs_.empty()) {
    if (state_.load(std::memory_order_relaxed) == IceTransportState::kNew) {
      SetState(IceTransportState::kChecking);
    }
    for (size_t i = 0; i < pairs_.size(); ++i) {
      if (pairs_[i].unacked_pings < 8) {
        SendConnectivityCheck(i);
        break;
      }
    }
  }

  network_queue_->PostDelayedTask(
      SafeTask(safety_.flag(), [this]() { OnPeriodicCheckTick(); }),
      TimeDelta::Millis(50));
}

void IceTransportChannel::DoAsyncReceive() {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (!socket_ || !socket_->is_open()) {
    return;
  }

  socket_->async_receive_from(
      boost::asio::buffer(rx_buf_), sender_ep_,
      SafeTask(safety_.flag(),
               [this](const boost::system::error_code& ec,
                      std::size_t bytes_recvd) {
                 RTC_DCHECK_RUN_ON(&net_checker_);
                 if (!ec && bytes_recvd > 0) {
                   HandleUdpDatagram(
                       MakeArrayView(rx_buf_.data(), bytes_recvd), sender_ep_);
                 }
                 if (socket_ && socket_->is_open()) {
                   DoAsyncReceive();
                 }
               }));
}

void IceTransportChannel::HandleUdpDatagram(
    ArrayView<const uint8_t> datagram,
    const boost::asio::ip::udp::endpoint& from) {
  if (turn_state_.has_value() && from == turn_state_->spec.server_endpoint &&
      TurnChannelDataCodec::IsChannelData(datagram)) {
    uint16_t ch = 0;
    ArrayView<const uint8_t> inner;
    if (TurnChannelDataCodec::Unwrap(datagram, &ch, &inner)) {
      HandleUdpDatagram(inner, turn_state_->bound_peer_ep);
    }
    return;
  }

  if (!StunMessage::IsStunPacket(datagram)) {
    const double drop_p = rx_drop_prob_.load(std::memory_order_relaxed);
    if (drop_p > 0.0) {
      thread_local uint32_t lcg = 0x13579BDFu;
      lcg = lcg * 1664525u + 1013904223u;
      const double sample =
          static_cast<double>(lcg & 0x00FFFFFFu) / static_cast<double>(0x01000000u);
      if (sample < drop_p) {
        return;
      }
    }
  }

  if (StunMessage::IsStunPacket(datagram)) {
    HandleIncomingStun(datagram, from);
    return;
  }

  if (auto* obs = observer_.load(std::memory_order_acquire)) {
    obs->OnIcePacketReceived(datagram, clock_->CurrentTime());
  }
}

void IceTransportChannel::HandleIncomingStun(
    ArrayView<const uint8_t> datagram,
    const boost::asio::ip::udp::endpoint& from) {
  const Timestamp now = clock_->CurrentTime();

  if (turn_state_.has_value() && from == turn_state_->spec.server_endpoint) {
    auto turn_msg = StunMessage::Parse(datagram, "");
    if (!turn_msg.has_value()) {
      return;
    }

    if (turn_msg->type() == StunMessageType::kAllocateErrorResponse &&
        turn_msg->error_code().value_or(0) == 401 &&
        turn_msg->realm().has_value() && turn_msg->nonce().has_value()) {
      turn_state_->realm = *turn_msg->realm();
      turn_state_->nonce = *turn_msg->nonce();
      turn_state_->integrity_key = StunMessage::ComputeLongTermKey(
          turn_state_->spec.username, turn_state_->realm,
          turn_state_->spec.password);

      StunMessage auth_alloc(StunMessageType::kAllocateRequest);
      auth_alloc.set_username(turn_state_->spec.username);
      auth_alloc.set_realm(turn_state_->realm);
      auth_alloc.set_nonce(turn_state_->nonce);
      auto wire = auth_alloc.Serialize(turn_state_->integrity_key, true);
      boost::system::error_code send_ec;
      socket_->send_to(boost::asio::buffer(wire), from, 0, send_ec);
      return;
    }
    if (turn_msg->type() == StunMessageType::kAllocateResponse &&
        turn_msg->xor_relayed_address().has_value()) {
      turn_state_->allocated = true;
      turn_state_->relayed_ep = *turn_msg->xor_relayed_address();
      RTC_LOG(kInfo) << "TURN relay allocated at "
                     << turn_state_->relayed_ep.address().to_string() << ":"
                     << turn_state_->relayed_ep.port();

      IceCandidate relay_cand;
      relay_cand.type = IceCandidateType::kRelay;
      relay_cand.priority =
          IceCandidate::ComputePriority(IceCandidateType::kRelay);
      relay_cand.address = turn_state_->relayed_ep;
      local_candidates_.push_back(relay_cand);
      if (auto* obs = observer_.load(std::memory_order_acquire)) {
        obs->OnLocalCandidateGathered(relay_cand);
      }
      RebuildCandidatePairs();

      if (!remote_candidates_.empty()) {
        turn_state_->bound_peer_ep = remote_candidates_.front().address;
        StunMessage ch_bind(StunMessageType::kChannelBindRequest);
        ch_bind.set_username(turn_state_->spec.username);
        ch_bind.set_realm(turn_state_->realm);
        ch_bind.set_nonce(turn_state_->nonce);
        ch_bind.set_channel_number(turn_state_->bound_channel);
        ch_bind.set_xor_peer_address(turn_state_->bound_peer_ep);
        auto wire = ch_bind.Serialize(turn_state_->integrity_key, true);
        boost::system::error_code send_ec;
        socket_->send_to(boost::asio::buffer(wire), from, 0, send_ec);
      }
      return;
    }
    if (turn_msg->type() == StunMessageType::kChannelBindResponse) {
      turn_state_->channel_bound = true;
      RTC_LOG(kInfo) << "TURN 4-byte ChannelData bound (channel=0x" << std::hex
                     << turn_state_->bound_channel << std::dec << ")";
      return;
    }
  }

  const uint16_t raw_type = ReadBigEndian16(datagram.data());
  if (raw_type == static_cast<uint16_t>(StunMessageType::kBindingRequest)) {
    auto req = StunMessage::Parse(datagram, local_params_.pwd);
    if (!req.has_value()) {
      return;
    }

    StunMessage resp(StunMessageType::kBindingResponse);
    resp.set_transaction_id(req->transaction_id());
    resp.set_xor_mapped_address(from);
    auto wire = resp.Serialize(local_params_.pwd, true);
    boost::system::error_code send_ec;
    socket_->send_to(boost::asio::buffer(wire), from, 0, send_ec);

    size_t matched_idx = pairs_.size();
    for (size_t i = 0; i < pairs_.size(); ++i) {
      if (pairs_[i].remote.address == from) {
        matched_idx = i;
        break;
      }
    }
    if (matched_idx == pairs_.size() && !local_candidates_.empty()) {
      IceCandidate prflx;
      prflx.type = IceCandidateType::kPrflx;
      prflx.priority = req->priority().value_or(
          IceCandidate::ComputePriority(IceCandidateType::kPrflx));
      prflx.address = from;
      CandidatePair p;
      p.local = local_candidates_.front();
      p.remote = prflx;
      p.state = PairState::kSucceeded;
      p.last_response_received = now;
      pairs_.push_back(p);
      matched_idx = pairs_.size() - 1;
    }
    if (matched_idx < pairs_.size()) {
      pairs_[matched_idx].state = PairState::kSucceeded;
      pairs_[matched_idx].last_response_received = now;
      if (req->use_candidate() || !selected_pair_idx_.has_value()) {
        pairs_[matched_idx].nominated = true;
        selected_pair_idx_ = matched_idx;
        SetState(IceTransportState::kConnected);
      }
    }
    return;
  }

  if (raw_type ==
      static_cast<uint16_t>(StunMessageType::kBindingErrorResponse)) {
    auto err_resp = StunMessage::Parse(datagram, "");
    if (err_resp.has_value() && err_resp->error_code().value_or(0) == 487) {
      controlling_role_ = !controlling_role_;
      RTC_LOG(kWarning) << "ICE 487 Role Conflict resolved: switched to "
                        << (controlling_role_ ? "CONTROLLING" : "CONTROLLED");
      RebuildCandidatePairs();
    }
    return;
  }

  if (raw_type == static_cast<uint16_t>(StunMessageType::kBindingResponse)) {
    for (const auto& srv : servers_) {
      if (!srv.is_turn && from == srv.server_endpoint) {
        auto srflx_resp = StunMessage::Parse(datagram, "");
        if (srflx_resp.has_value() &&
            srflx_resp->xor_mapped_address().has_value()) {
          IceCandidate srflx;
          srflx.type = IceCandidateType::kSrflx;
          srflx.priority =
              IceCandidate::ComputePriority(IceCandidateType::kSrflx);
          srflx.address = *srflx_resp->xor_mapped_address();
          local_candidates_.push_back(srflx);
          RTC_LOG(kInfo) << "STUN server-reflexive candidate gathered: "
                         << srflx.address.address().to_string() << ":"
                         << srflx.address.port();
          if (auto* obs = observer_.load(std::memory_order_acquire)) {
            obs->OnLocalCandidateGathered(srflx);
          }
          RebuildCandidatePairs();
        }
        return;
      }
    }

    auto resp = StunMessage::Parse(datagram, remote_params_.pwd);
    if (!resp.has_value()) {
      return;
    }

    const auto it = pending_pings_.find(resp->transaction_id());
    if (it == pending_pings_.end()) {
      return;
    }
    const size_t idx = it->second.pair_index;
    const TimeDelta sample_rtt =
        std::max(TimeDelta::Millis(1), now - it->second.sent_time);
    pending_pings_.erase(it);

    const int64_t prev_rtt_us = smoothed_rtt_us_.load(std::memory_order_relaxed);
    const int64_t next_rtt_us =
        static_cast<int64_t>(0.8 * prev_rtt_us + 0.2 * sample_rtt.us());
    smoothed_rtt_us_.store(next_rtt_us, std::memory_order_release);

    if (idx < pairs_.size()) {
      auto& pair = pairs_[idx];
      pair.state = PairState::kSucceeded;
      pair.unacked_pings = 0;
      pair.last_response_received = now;
      if (!selected_pair_idx_.has_value() ||
          pair.priority > pairs_[*selected_pair_idx_].priority) {
        pair.nominated = true;
        selected_pair_idx_ = idx;
        RTC_LOG(kInfo) << "ICE candidate pair nominated: "
                       << pair.local.address.address().to_string() << ":"
                       << pair.local.address.port() << " <-> "
                       << pair.remote.address.address().to_string() << ":"
                       << pair.remote.address.port()
                       << " (rtt_ms=" << (next_rtt_us / 1000) << ")";
        SetState(IceTransportState::kConnected);
        if (controlling_role_) {
          // 立即发送携带 USE-CANDIDATE 的提名检查报文，实现毫秒级 P2P 路径锁定。
          SendConnectivityCheck(idx);
        }
      }
    }
  }
}

IceParameters IceTransportChannel::local_parameters() const {
  return network_queue_->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    return local_params_;
  });
}

std::vector<IceCandidate> IceTransportChannel::LocalCandidatesSnapshot() const {
  return network_queue_->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    return local_candidates_;
  });
}

int IceTransportChannel::SendPacket(ArrayView<const uint8_t> packet) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (!socket_ || !socket_->is_open() || !selected_pair_idx_.has_value()) {
    return -1;
  }
  const CandidatePair& sel = pairs_[*selected_pair_idx_];
  boost::system::error_code ec;
  if (sel.via_turn_relay && turn_state_.has_value() &&
      turn_state_->channel_bound) {
    auto ch_pkt = TurnChannelDataCodec::Wrap(turn_state_->bound_channel, packet);
    socket_->send_to(boost::asio::buffer(ch_pkt),
                     turn_state_->spec.server_endpoint, 0, ec);
  } else {
    socket_->send_to(boost::asio::buffer(packet.data(), packet.size()),
                     sel.remote.address, 0, ec);
  }
  return ec ? -1 : static_cast<int>(packet.size());
}

void IceTransportChannel::SetState(IceTransportState new_state) {
  const IceTransportState old_state =
      state_.exchange(new_state, std::memory_order_acq_rel);
  if (old_state == new_state) {
    return;
  }
  RTC_LOG(kInfo) << "ICE state transition: " << IceStateToString(old_state)
                 << " -> " << IceStateToString(new_state);
  if (auto* obs = observer_.load(std::memory_order_acquire)) {
    obs->OnIceTransportStateChanged(new_state);
  }
}

}  // namespace rtc
