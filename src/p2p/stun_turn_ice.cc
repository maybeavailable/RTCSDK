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
  if (lifetime_.has_value()) {
    uint8_t b[4]{};
    WriteBigEndian32(b, *lifetime_);
    AppendAttr(stun_attr_type::kLifetime, b, 4, &out);
  }
  if (requested_transport_.has_value()) {
    uint8_t b[4]{*requested_transport_, 0, 0, 0};
    AppendAttr(stun_attr_type::kRequestedTransport, b, 4, &out);
  }
  if (software_.has_value()) {
    AppendAttr(stun_attr_type::kSoftware,
               reinterpret_cast<const uint8_t*>(software_->data()),
               software_->size(), &out);
  }
  if (error_code_.has_value()) {
    std::vector<uint8_t> err_val(4 + error_reason_.size(), 0);
    err_val[2] = static_cast<uint8_t>(*error_code_ / 100);
    err_val[3] = static_cast<uint8_t>(*error_code_ % 100);
    if (!error_reason_.empty()) {
      std::memcpy(err_val.data() + 4, error_reason_.data(),
                  error_reason_.size());
    }
    AppendAttr(stun_attr_type::kErrorCode, err_val.data(), err_val.size(),
               &out);
  }
  if (xor_mapped_.has_value()) {
    AppendXorEndpointAttr(stun_attr_type::kXorMappedAddress, *xor_mapped_,
                          tx_id_, &out);
  }
  if (xor_relayed_.has_value()) {
    AppendXorEndpointAttr(stun_attr_type::kXorRelayedAddress, *xor_relayed_,
                          tx_id_, &out);
  }
  for (const auto& xp : xor_peers_) {
    AppendXorEndpointAttr(stun_attr_type::kXorPeerAddress, xp, tx_id_, &out);
  }
  if (data_.has_value()) {
    AppendAttr(stun_attr_type::kData, data_->data(), data_->size(), &out);
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
      case stun_attr_type::kLifetime:
        if (attr_len == 4) {
          msg.lifetime_ = ReadBigEndian32(val);
        }
        break;
      case stun_attr_type::kRequestedTransport:
        if (attr_len >= 1) {
          msg.requested_transport_ = val[0];
        }
        break;
      case stun_attr_type::kData:
        msg.data_.emplace(val, val + attr_len);
        break;
      case stun_attr_type::kSoftware:
        msg.software_.emplace(reinterpret_cast<const char*>(val), attr_len);
        break;
      case stun_attr_type::kErrorCode:
        if (attr_len >= 4) {
          msg.error_code_ = static_cast<int>(val[2] & 0x07) * 100 + val[3];
          if (attr_len > 4) {
            msg.error_reason_.assign(reinterpret_cast<const char*>(val + 4),
                                     attr_len - 4);
          }
        }
        break;
      case stun_attr_type::kXorMappedAddress:
        msg.xor_mapped_ = ParseXorEndpointAttr(val, attr_len, msg.tx_id_);
        break;
      case stun_attr_type::kXorRelayedAddress:
        msg.xor_relayed_ = ParseXorEndpointAttr(val, attr_len, msg.tx_id_);
        break;
      case stun_attr_type::kXorPeerAddress:
        if (auto ep = ParseXorEndpointAttr(val, attr_len, msg.tx_id_)) {
          msg.xor_peers_.push_back(*ep);
        }
        break;
      case stun_attr_type::kMessageIntegrity:
        msg.has_message_integrity_ = true;
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

bool IceTransportChannel::ParseIceServerUri(std::string_view uri,
                                            std::string_view username,
                                            std::string_view password,
                                            TurnServerSpec* out_spec) {
  if (out_spec == nullptr) {
    return false;
  }
  while (!uri.empty() &&
         (uri.front() == ' ' || uri.front() == '\t' || uri.front() == '\r' ||
          uri.front() == '\n')) {
    uri.remove_prefix(1);
  }
  while (!uri.empty() &&
         (uri.back() == ' ' || uri.back() == '\t' || uri.back() == '\r' ||
          uri.back() == '\n')) {
    uri.remove_suffix(1);
  }

  const size_t scheme_colon = uri.find(':');
  if (scheme_colon == std::string_view::npos || scheme_colon == 0) {
    return false;
  }
  std::string scheme(uri.substr(0, scheme_colon));
  std::transform(scheme.begin(), scheme.end(), scheme.begin(),
                 [](unsigned char c) {
                   return static_cast<char>((c >= 'A' && c <= 'Z')
                                                ? (c - 'A' + 'a')
                                                : c);
                 });

  bool is_turn = false;
  uint16_t default_port = 3478;
  if (scheme == "stun") {
    is_turn = false;
    default_port = 3478;
  } else if (scheme == "stuns") {
    is_turn = false;
    default_port = 5349;
  } else if (scheme == "turn") {
    is_turn = true;
    default_port = 3478;
  } else if (scheme == "turns") {
    is_turn = true;
    default_port = 5349;
  } else {
    return false;
  }

  std::string_view rest = uri.substr(scheme_colon + 1);
  if (rest.substr(0, 2) == "//") {
    rest.remove_prefix(2);
  }

  const size_t q = rest.find('?');
  if (q != std::string_view::npos) {
    std::string query(rest.substr(q + 1));
    std::transform(query.begin(), query.end(), query.begin(),
                   [](unsigned char c) {
                     return static_cast<char>((c >= 'A' && c <= 'Z')
                                                  ? (c - 'A' + 'a')
                                                  : c);
                   });
    const size_t tpos = query.find("transport=");
    if (tpos != std::string::npos) {
      std::string_view tval = std::string_view(query).substr(tpos + 10);
      const size_t amp = tval.find('&');
      if (amp != std::string_view::npos) {
        tval = tval.substr(0, amp);
      }
      if (tval != "udp") {
        return false;
      }
    }
    rest = rest.substr(0, q);
  }

  if (rest.empty()) {
    return false;
  }

  std::string host;
  uint16_t port = default_port;
  auto parse_port_strict = [](std::string_view pstr, uint16_t* out_p) -> bool {
    if (pstr.empty() || pstr.size() > 5) {
      return false;
    }
    uint32_t acc = 0;
    for (char ch : pstr) {
      if (ch < '0' || ch > '9') {
        return false;
      }
      acc = acc * 10 + static_cast<uint32_t>(ch - '0');
    }
    if (acc == 0 || acc > 65535) {
      return false;
    }
    *out_p = static_cast<uint16_t>(acc);
    return true;
  };

  if (rest.front() == '[') {
    const size_t rbr = rest.find(']');
    if (rbr == std::string_view::npos || rbr <= 1) {
      return false;
    }
    host = std::string(rest.substr(1, rbr - 1));
    const std::string_view tail = rest.substr(rbr + 1);
    if (!tail.empty()) {
      if (tail.front() != ':' || !parse_port_strict(tail.substr(1), &port)) {
        return false;
      }
    }
  } else {
    const size_t first_colon = rest.find(':');
    const size_t last_colon = rest.rfind(':');
    if (first_colon != last_colon) {
      // 未加方括号的多冒号字符串非法（IPv6 字面量必须使用方括号包裹）。
      return false;
    }
    if (last_colon != std::string_view::npos) {
      host = std::string(rest.substr(0, last_colon));
      if (!parse_port_strict(rest.substr(last_colon + 1), &port)) {
        return false;
      }
    } else {
      host = std::string(rest);
    }
  }

  if (host.empty()) {
    return false;
  }
  for (unsigned char ch : host) {
    if (ch <= 0x20 || ch == '/' || ch == '\\' || ch == '@' || ch == '#') {
      return false;
    }
  }

  TurnServerSpec spec;
  spec.host = host;
  spec.port = port;
  spec.username = std::string(username);
  spec.password = std::string(password);
  spec.is_turn = is_turn;

  boost::system::error_code ec;
  const auto ip = boost::asio::ip::make_address(host, ec);
  if (!ec) {
    spec.server_endpoint = boost::asio::ip::udp::endpoint(ip, port);
  }
  *out_spec = std::move(spec);
  return true;
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
  auto cleanup = [this]() {
    safety_.flag()->SetNotAlive();
    if (resolver_) {
      resolver_->cancel();
      resolver_.reset();
    }
    if (socket_ && socket_->is_open()) {
      boost::system::error_code ec;
      socket_->close(ec);
    }
  };
  if (!network_queue_->IsStopped()) {
    network_queue_->Invoke([this, &cleanup]() {
      RTC_DCHECK_RUN_ON(&net_checker_);
      cleanup();
    });
  } else {
    cleanup();
  }
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

    resolver_ = std::make_unique<boost::asio::ip::udp::resolver>(
        network_queue_->io_context());
    resolved_servers_.clear();
    resolved_servers_.reserve(servers_.size());
    for (const auto& srv : servers_) {
      ResolvedServerEntry entry;
      entry.spec = srv;
      if (srv.server_endpoint.port() != 0 &&
          srv.server_endpoint.address().is_v4()) {
        entry.resolved_endpoints.push_back(srv.server_endpoint);
      }
      resolved_servers_.push_back(std::move(entry));
    }
    NotifyServerGatheringProgress();

    DoAsyncReceive();
    const Timestamp now = clock_->CurrentTime();
    for (size_t i = 0; i < resolved_servers_.size(); ++i) {
      auto& entry = resolved_servers_[i];
      if (!entry.resolved_endpoints.empty()) {
        if (!entry.spec.is_turn) {
          SendStunProbeToServer(i, now);
        } else {
          entry.spec.server_endpoint = entry.resolved_endpoints.front();
          StartTurnAllocation(entry.spec);
        }
      } else if (!entry.spec.host.empty()) {
        ResolveAndProbeServer(i);
      }
    }

    RebuildCandidatePairs();
    OnPeriodicCheckTick();
    return true;
  });
}

void IceTransportChannel::ResolveAndProbeServer(size_t server_index) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (!resolver_ || server_index >= resolved_servers_.size()) {
    return;
  }
  auto& entry = resolved_servers_[server_index];
  if (entry.resolving || entry.spec.host.empty()) {
    return;
  }
  entry.resolving = true;
  const std::string host = entry.spec.host;
  const std::string service = std::to_string(entry.spec.port);

  resolver_->async_resolve(
      boost::asio::ip::udp::v4(), host, service,
      SafeTask(safety_.flag(),
               [this, server_index, host](
                   const boost::system::error_code& ec,
                   boost::asio::ip::udp::resolver::results_type results) {
                 RTC_DCHECK_RUN_ON(&net_checker_);
                 if (server_index >= resolved_servers_.size()) {
                   return;
                 }
                 auto& ent = resolved_servers_[server_index];
                 ent.resolving = false;
                 if (ec) {
                   ent.dns_failed = true;
                   NotifyServerGatheringProgress();
                   RTC_LOG(kWarning) << "STUN/TURN DNS resolve failed for '"
                                     << host << "': " << ec.message();
                   return;
                 }
                 for (const auto& r : results) {
                   const auto ep = r.endpoint();
                   if (ep.address().is_v4() && ep.port() != 0) {
                     if (std::find(ent.resolved_endpoints.begin(),
                                   ent.resolved_endpoints.end(),
                                   ep) == ent.resolved_endpoints.end()) {
                       ent.resolved_endpoints.push_back(ep);
                     }
                   }
                 }
                 if (ent.resolved_endpoints.empty()) {
                   ent.dns_failed = true;
                   NotifyServerGatheringProgress();
                   RTC_LOG(kWarning)
                       << "STUN/TURN DNS resolve returned no IPv4 address for '"
                       << host << "'";
                   return;
                 }
                 ent.spec.server_endpoint = ent.resolved_endpoints.front();
                 RTC_LOG(kInfo)
                     << "Resolved " << (ent.spec.is_turn ? "TURN" : "STUN")
                     << " domain '" << host << ":" << ent.spec.port << "' -> "
                     << ent.spec.server_endpoint.address().to_string() << ":"
                     << ent.spec.server_endpoint.port();

                 if (!ent.spec.is_turn) {
                   SendStunProbeToServer(server_index, clock_->CurrentTime());
                 } else if (!turn_state_.has_value()) {
                   StartTurnAllocation(ent.spec);
                 }
               }));
}

void IceTransportChannel::SendStunProbeToServer(size_t server_index,
                                                Timestamp now) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (!socket_ || !socket_->is_open() ||
      server_index >= resolved_servers_.size()) {
    return;
  }
  auto& entry = resolved_servers_[server_index];
  if (entry.spec.is_turn || entry.resolved_endpoints.empty()) {
    return;
  }
  entry.last_stun_tx = now;
  ++entry.stun_tx_count;

  const size_t max_eps = std::min<size_t>(entry.resolved_endpoints.size(), 2);
  for (size_t k = 0; k < max_eps; ++k) {
    StunMessage req(StunMessageType::kBindingRequest);
    auto bytes = req.Serialize("", true);
    boost::system::error_code send_ec;
    socket_->send_to(boost::asio::buffer(bytes), entry.resolved_endpoints[k], 0,
                     send_ec);
  }
}

void IceTransportChannel::NotifyServerGatheringProgress() {
  RTC_DCHECK_RUN_ON(&net_checker_);
  bool has_stun = false;
  bool any_srflx = false;
  bool all_stun_failed = true;
  bool has_turn = false;
  bool turn_ready = false;
  bool all_turn_failed = true;

  for (const auto& ent : resolved_servers_) {
    if (!ent.spec.is_turn) {
      has_stun = true;
      if (ent.srflx_gathered) {
        any_srflx = true;
      }
      if (!ent.dns_failed && ent.stun_tx_count < 4) {
        all_stun_failed = false;
      }
    } else {
      has_turn = true;
      if (turn_state_.has_value() && turn_state_->allocated) {
        turn_ready = true;
      }
      if (!ent.dns_failed) {
        all_turn_failed = false;
      }
    }
  }

  const bool stun_settled = !has_stun || any_srflx || all_stun_failed;
  const bool turn_settled = !has_turn || turn_ready || all_turn_failed;
  const bool all_done = stun_settled && turn_settled;
  {
    std::lock_guard<std::mutex> lock(gather_cv_mu_);
    all_servers_settled_ = all_done;
  }
  if (all_done) {
    gather_cv_.notify_all();
  }
}

bool IceTransportChannel::WaitForServerReflexiveGathering(TimeDelta max_wait) {
  std::unique_lock<std::mutex> lock(gather_cv_mu_);
  if (all_servers_settled_ || max_wait <= TimeDelta::Zero()) {
    return all_servers_settled_;
  }
  return gather_cv_.wait_for(
      lock, std::chrono::microseconds(max_wait.us()),
      [this]() { return all_servers_settled_; });
}

void IceTransportChannel::StartTurnAllocation(const TurnServerSpec& turn) {
  ActiveTurnState ts;
  ts.spec = turn;
  turn_state_ = ts;

  RTC_LOG(kInfo) << "Initiating TURN Allocate to "
                 << turn.server_endpoint.address().to_string() << ":"
                 << turn.server_endpoint.port();
  StunMessage alloc(StunMessageType::kAllocateRequest);
  alloc.set_requested_transport(17);  // IANA UDP 传输协议号 = 17
  auto bytes = alloc.Serialize("", true);
  boost::system::error_code send_ec;
  socket_->send_to(boost::asio::buffer(bytes), turn.server_endpoint, 0,
                   send_ec);
}

void IceTransportChannel::EnsureTurnPeerBound(
    const boost::asio::ip::udp::endpoint& peer_ep) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (!socket_ || !turn_state_.has_value() || !turn_state_->allocated ||
      !peer_ep.address().is_v4() || peer_ep.port() == 0) {
    return;
  }

  uint16_t ch = 0;
  const auto existing = turn_state_->peer_to_channel.find(peer_ep);
  if (existing != turn_state_->peer_to_channel.end()) {
    if (turn_state_->confirmed_channels.count(existing->second) > 0) {
      return;
    }
    ch = existing->second;
  } else {
    if (turn_state_->next_channel > 0x7FFEu) {
      return;
    }
    ch = turn_state_->next_channel++;
    turn_state_->peer_to_channel[peer_ep] = ch;
    turn_state_->channel_to_peer[ch] = peer_ep;
  }

  // 同时下发 CreatePermission 与 ChannelBind，确保在 ChannelBind 确认前即可通过 Send/Data Indication 立即收发。
  StunMessage perm(StunMessageType::kCreatePermissionRequest);
  perm.set_username(turn_state_->spec.username);
  perm.set_realm(turn_state_->realm);
  perm.set_nonce(turn_state_->nonce);
  perm.set_xor_peer_address(peer_ep);
  auto perm_wire = perm.Serialize(turn_state_->integrity_key, true);
  boost::system::error_code ec;
  socket_->send_to(boost::asio::buffer(perm_wire),
                   turn_state_->spec.server_endpoint, 0, ec);

  StunMessage ch_bind(StunMessageType::kChannelBindRequest);
  ch_bind.set_username(turn_state_->spec.username);
  ch_bind.set_realm(turn_state_->realm);
  ch_bind.set_nonce(turn_state_->nonce);
  ch_bind.set_channel_number(ch);
  ch_bind.set_xor_peer_address(peer_ep);
  auto ch_wire = ch_bind.Serialize(turn_state_->integrity_key, true);
  socket_->send_to(boost::asio::buffer(ch_wire),
                   turn_state_->spec.server_endpoint, 0, ec);
}

int IceTransportChannel::SendViaTurnRelay(
    const boost::asio::ip::udp::endpoint& peer_ep,
    ArrayView<const uint8_t> payload) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (!socket_ || !turn_state_.has_value() || !turn_state_->allocated) {
    return -1;
  }
  EnsureTurnPeerBound(peer_ep);
  boost::system::error_code ec;
  const auto ch_it = turn_state_->peer_to_channel.find(peer_ep);
  if (ch_it != turn_state_->peer_to_channel.end() &&
      turn_state_->confirmed_channels.count(ch_it->second) > 0) {
    const auto ch_wire = TurnChannelDataCodec::Wrap(ch_it->second, payload);
    socket_->send_to(boost::asio::buffer(ch_wire),
                     turn_state_->spec.server_endpoint, 0, ec);
  } else {
    StunMessage send_ind(StunMessageType::kSendIndication);
    send_ind.set_xor_peer_address(peer_ep);
    send_ind.set_data(payload);
    const auto ind_wire = send_ind.Serialize("", true);
    socket_->send_to(boost::asio::buffer(ind_wire),
                     turn_state_->spec.server_endpoint, 0, ec);
  }
  return ec ? -1 : static_cast<int>(payload.size());
}

void IceTransportChannel::AddRemoteCandidate(const IceCandidate& remote) {
  network_queue_->PostTask(SafeTask(safety_.flag(), [this, remote]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    remote_candidates_.push_back(remote);
    if (turn_state_.has_value() && turn_state_->allocated) {
      EnsureTurnPeerBound(remote.address);
    }
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
    const Timestamp now = clock_->CurrentTime();
    for (size_t i = 0; i < resolved_servers_.size(); ++i) {
      auto& entry = resolved_servers_[i];
      if (!entry.spec.is_turn) {
        entry.srflx_gathered = false;
        entry.stun_tx_count = 0;
        if (!entry.resolved_endpoints.empty()) {
          SendStunProbeToServer(i, now);
        } else if (!entry.spec.host.empty()) {
          ResolveAndProbeServer(i);
        }
      }
    }
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
  pending_pings_.clear();

  for (const auto& lc : local_candidates_) {
    for (const auto& rc : remote_candidates_) {
      if (lc.address.address().is_v4() != rc.address.address().is_v4()) {
        continue;
      }
      if (lc.type != IceCandidateType::kRelay &&
          rc.type != IceCandidateType::kRelay &&
          lc.address.address().is_loopback() !=
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
  // 定期清理超时未应答（如不可达内网候选或弱网丢包）的 STUN Binding 事务记录，防止 pending_pings_ 持续增长泄漏。
  for (auto it = pending_pings_.begin(); it != pending_pings_.end();) {
    if ((now - it->second.sent_time) > TimeDelta::Seconds(5)) {
      it = pending_pings_.erase(it);
    } else {
      ++it;
    }
  }
  while (pending_pings_.size() >= 256) {
    pending_pings_.erase(pending_pings_.begin());
  }
  pending_pings_[req.transaction_id()] = PendingPing{pair_index, now};
  pair.last_ping_sent = now;
  ++pair.unacked_pings;
  if (pair.state == PairState::kWaiting) {
    pair.state = PairState::kInProgress;
  }

  auto wire = req.Serialize(remote_params_.pwd, true);
  if (pair.via_turn_relay) {
    SendViaTurnRelay(pair.remote.address, wire);
  } else {
    boost::system::error_code send_ec;
    socket_->send_to(boost::asio::buffer(wire), pair.remote.address, 0,
                     send_ec);
  }
}

void IceTransportChannel::OnPeriodicCheckTick() {
  RTC_DCHECK_RUN_ON(&net_checker_);
  const Timestamp now = clock_->CurrentTime();

  // TURN 分配保活刷新（在有效期过半时自动发送 RefreshRequest）。
  if (turn_state_.has_value() && turn_state_->allocated &&
      turn_state_->lifetime_sec > 0 &&
      (turn_state_->last_refresh_sent.IsMinusInfinity() ||
       (now - turn_state_->last_refresh_sent) >=
           TimeDelta::Seconds(std::max<int64_t>(30, turn_state_->lifetime_sec / 2)))) {
    turn_state_->last_refresh_sent = now;
    StunMessage refresh(StunMessageType::kRefreshRequest);
    refresh.set_username(turn_state_->spec.username);
    refresh.set_realm(turn_state_->realm);
    refresh.set_nonce(turn_state_->nonce);
    refresh.set_lifetime(turn_state_->lifetime_sec);
    const auto rwire = refresh.Serialize(turn_state_->integrity_key, true);
    boost::system::error_code ec;
    socket_->send_to(boost::asio::buffer(rwire),
                     turn_state_->spec.server_endpoint, 0, ec);
  }

  // 对尚未收到反射响应的 STUN 服务器按 RFC 5389 执行最多 4 次超时重传探测。
  for (size_t i = 0; i < resolved_servers_.size(); ++i) {
    auto& entry = resolved_servers_[i];
    if (!entry.spec.is_turn && !entry.srflx_gathered &&
        !entry.resolved_endpoints.empty() && entry.stun_tx_count < 4 &&
        (entry.last_stun_tx.IsMinusInfinity() ||
         (now - entry.last_stun_tx) >= TimeDelta::Millis(250))) {
      SendStunProbeToServer(i, now);
    }
  }

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
    const boost::asio::ip::udp::endpoint& from,
    bool via_turn_relay) {
  if (!via_turn_relay && turn_state_.has_value() &&
      from == turn_state_->spec.server_endpoint &&
      TurnChannelDataCodec::IsChannelData(datagram)) {
    uint16_t ch = 0;
    ArrayView<const uint8_t> inner;
    if (TurnChannelDataCodec::Unwrap(datagram, &ch, &inner)) {
      const auto pit = turn_state_->channel_to_peer.find(ch);
      if (pit != turn_state_->channel_to_peer.end()) {
        HandleUdpDatagram(inner, pit->second, /*via_turn_relay=*/true);
      }
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
    HandleIncomingStun(datagram, from, via_turn_relay);
    return;
  }

  if (auto* obs = observer_.load(std::memory_order_acquire)) {
    obs->OnIcePacketReceived(datagram, clock_->CurrentTime());
  }
}

void IceTransportChannel::HandleIncomingStun(
    ArrayView<const uint8_t> datagram,
    const boost::asio::ip::udp::endpoint& from,
    bool via_turn_relay) {
  const Timestamp now = clock_->CurrentTime();

  if (!via_turn_relay && turn_state_.has_value() &&
      from == turn_state_->spec.server_endpoint) {
    auto turn_msg = StunMessage::Parse(datagram, "");
    if (!turn_msg.has_value()) {
      return;
    }

    if (turn_msg->type() == StunMessageType::kDataIndication &&
        turn_msg->xor_peer_address().has_value() &&
        turn_msg->data().has_value()) {
      HandleUdpDatagram(*turn_msg->data(), *turn_msg->xor_peer_address(),
                        /*via_turn_relay=*/true);
      return;
    }

    if ((turn_msg->type() == StunMessageType::kAllocateErrorResponse ||
         turn_msg->type() == StunMessageType::kRefreshErrorResponse ||
         turn_msg->type() == StunMessageType::kCreatePermissionErrorResponse ||
         turn_msg->type() == StunMessageType::kChannelBindErrorResponse) &&
        (turn_msg->error_code().value_or(0) == 401 ||
         turn_msg->error_code().value_or(0) == 438) &&
        turn_msg->realm().has_value() && turn_msg->nonce().has_value()) {
      turn_state_->realm = *turn_msg->realm();
      turn_state_->nonce = *turn_msg->nonce();
      turn_state_->integrity_key = StunMessage::ComputeLongTermKey(
          turn_state_->spec.username, turn_state_->realm,
          turn_state_->spec.password);

      if (!turn_state_->allocated) {
        StunMessage auth_alloc(StunMessageType::kAllocateRequest);
        auth_alloc.set_requested_transport(17);
        auth_alloc.set_username(turn_state_->spec.username);
        auth_alloc.set_realm(turn_state_->realm);
        auth_alloc.set_nonce(turn_state_->nonce);
        auto wire = auth_alloc.Serialize(turn_state_->integrity_key, true);
        boost::system::error_code send_ec;
        socket_->send_to(boost::asio::buffer(wire), from, 0, send_ec);
      }
      return;
    }
    if (turn_msg->type() == StunMessageType::kAllocateResponse &&
        turn_msg->xor_relayed_address().has_value()) {
      turn_state_->allocated = true;
      turn_state_->relayed_ep = *turn_msg->xor_relayed_address();
      turn_state_->lifetime_sec = turn_msg->lifetime().value_or(600);
      turn_state_->last_refresh_sent = now;
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
      NotifyServerGatheringProgress();

      for (const auto& rc : remote_candidates_) {
        EnsureTurnPeerBound(rc.address);
      }
      return;
    }
    if (turn_msg->type() == StunMessageType::kChannelBindResponse) {
      for (const auto& [ep, ch] : turn_state_->peer_to_channel) {
        (void)ep;
        turn_state_->confirmed_channels.insert(ch);
      }
      RTC_LOG(kInfo) << "TURN 4-byte ChannelData active ("
                     << turn_state_->confirmed_channels.size() << " peer(s))";
      return;
    }
    if (turn_msg->type() == StunMessageType::kCreatePermissionResponse ||
        turn_msg->type() == StunMessageType::kRefreshResponse) {
      if (turn_msg->lifetime().has_value()) {
        turn_state_->lifetime_sec = *turn_msg->lifetime();
      }
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
    if (via_turn_relay) {
      SendViaTurnRelay(from, wire);
    } else {
      boost::system::error_code send_ec;
      socket_->send_to(boost::asio::buffer(wire), from, 0, send_ec);
    }

    size_t matched_idx = pairs_.size();
    for (size_t i = 0; i < pairs_.size(); ++i) {
      if (pairs_[i].remote.address == from &&
          pairs_[i].via_turn_relay == via_turn_relay) {
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
      p.local = (via_turn_relay && turn_state_.has_value())
                    ? IceCandidate{"relay",
                                   1,
                                   "udp",
                                   IceCandidate::ComputePriority(
                                       IceCandidateType::kRelay),
                                   turn_state_->relayed_ep,
                                   IceCandidateType::kRelay}
                    : local_candidates_.front();
      p.remote = prflx;
      p.via_turn_relay = via_turn_relay;
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
    for (auto& entry : resolved_servers_) {
      if (!entry.spec.is_turn &&
          std::find(entry.resolved_endpoints.begin(),
                    entry.resolved_endpoints.end(),
                    from) != entry.resolved_endpoints.end()) {
        auto srflx_resp = StunMessage::Parse(datagram, "");
        if (srflx_resp.has_value() &&
            srflx_resp->xor_mapped_address().has_value()) {
          entry.srflx_gathered = true;
          const auto mapped_ep = *srflx_resp->xor_mapped_address();
          const bool already_present = std::any_of(
              local_candidates_.begin(), local_candidates_.end(),
              [&mapped_ep](const IceCandidate& c) {
                return c.type == IceCandidateType::kSrflx &&
                       c.address == mapped_ep;
              });
          if (!already_present) {
            IceCandidate srflx;
            srflx.type = IceCandidateType::kSrflx;
            srflx.priority =
                IceCandidate::ComputePriority(IceCandidateType::kSrflx);
            srflx.address = mapped_ep;
            local_candidates_.push_back(srflx);
            RTC_LOG(kInfo) << "STUN server-reflexive candidate gathered: "
                           << srflx.address.address().to_string() << ":"
                           << srflx.address.port();
            if (auto* obs = observer_.load(std::memory_order_acquire)) {
              obs->OnLocalCandidateGathered(srflx);
            }
            RebuildCandidatePairs();
          }
          NotifyServerGatheringProgress();
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
  if (sel.via_turn_relay) {
    return SendViaTurnRelay(sel.remote.address, packet);
  }
  boost::system::error_code ec;
  socket_->send_to(boost::asio::buffer(packet.data(), packet.size()),
                   sel.remote.address, 0, ec);
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
