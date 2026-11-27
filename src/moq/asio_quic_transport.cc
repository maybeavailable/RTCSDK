#include "moq/asio_quic_transport.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <limits>
#include <random>
#include <sstream>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "modules/rtp_rtcp/byte_io.h"
#include "moq/moq_transport.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {

// RFC 9001 第 5.2 节定义的 QUIC v1 初始盐值（Initial Salt）。
constexpr uint8_t kQuicV1InitialSalt[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

// RFC 9000 帧类型常量。
constexpr uint64_t kFramePadding = 0x00;
constexpr uint64_t kFramePing = 0x01;
constexpr uint64_t kFrameAck = 0x02;
constexpr uint64_t kFrameAckEcn = 0x03;
constexpr uint64_t kFrameResetStream = 0x04;
constexpr uint64_t kFrameStopSending = 0x05;
constexpr uint64_t kFrameCrypto = 0x06;
constexpr uint64_t kFrameNewToken = 0x07;
constexpr uint64_t kFrameStreamBase = 0x08;
constexpr uint64_t kFrameStreamFinBit = 0x01;
constexpr uint64_t kFrameStreamLenBit = 0x02;
constexpr uint64_t kFrameStreamOffBit = 0x04;
constexpr uint64_t kFrameMaxData = 0x10;
constexpr uint64_t kFrameMaxStreamData = 0x11;
constexpr uint64_t kFrameMaxStreamsBidi = 0x12;
constexpr uint64_t kFrameMaxStreamsUni = 0x13;
constexpr uint64_t kFrameDataBlocked = 0x14;
constexpr uint64_t kFrameStreamDataBlocked = 0x15;
constexpr uint64_t kFrameStreamsBlockedBidi = 0x16;
constexpr uint64_t kFrameStreamsBlockedUni = 0x17;
constexpr uint64_t kFrameNewConnectionId = 0x18;
constexpr uint64_t kFrameRetireConnectionId = 0x19;
constexpr uint64_t kFramePathChallenge = 0x1a;
constexpr uint64_t kFramePathResponse = 0x1b;
constexpr uint64_t kFrameConnectionCloseQuic = 0x1c;
constexpr uint64_t kFrameConnectionCloseApp = 0x1d;
constexpr uint64_t kFrameHandshakeDone = 0x1e;
constexpr uint64_t kFrameResetStreamAt = 0x24;
constexpr uint64_t kFrameDatagram = 0x30;
constexpr uint64_t kFrameDatagramLen = 0x31;

// RFC 8446 第 4 节定义的标准 TLS 1.3 握手消息类型与扩展常量。
constexpr uint8_t kTlsHsClientHello = 0x01;
constexpr uint8_t kTlsHsServerHello = 0x02;
constexpr uint8_t kTlsHsNewSessionTicket = 0x04;
constexpr uint8_t kTlsHsEncryptedExtensions = 0x08;
constexpr uint8_t kTlsHsCertificate = 0x0b;
constexpr uint8_t kTlsHsCertificateRequest = 0x0d;
constexpr uint8_t kTlsHsCertificateVerify = 0x0f;
constexpr uint8_t kTlsHsFinished = 0x14;

constexpr uint16_t kTlsCipherAes128GcmSha256 = 0x1301;
constexpr uint16_t kTlsGroupSecp256r1 = 0x0017;
constexpr uint16_t kTlsGroupX25519 = 0x001d;
constexpr uint16_t kTlsSigEcdsaSecp256r1Sha256 = 0x0403;
constexpr uint16_t kTlsSigRsaPssRsaeSha256 = 0x0804;

constexpr uint16_t kTlsExtServerName = 0x0000;
constexpr uint16_t kTlsExtSupportedGroups = 0x000a;
constexpr uint16_t kTlsExtSignatureAlgorithms = 0x000d;
constexpr uint16_t kTlsExtAlpn = 0x0010;
constexpr uint16_t kTlsExtPskKeyExchangeModes = 0x002d;
constexpr uint16_t kTlsExtSupportedVersions = 0x002b;
constexpr uint16_t kTlsExtKeyShare = 0x0033;
constexpr uint16_t kTlsExtQuicTransportParams = 0x0039;

// RFC 9000 第 18 节与 RFC 9221 第 3 节定义的传输参数 ID。
constexpr uint64_t kTpOriginalDestinationCid = 0x00;
constexpr uint64_t kTpMaxIdleTimeout = 0x01;
constexpr uint64_t kTpMaxUdpPayloadSize = 0x03;
constexpr uint64_t kTpInitialMaxData = 0x04;
constexpr uint64_t kTpInitialMaxStreamDataBidiLocal = 0x05;
constexpr uint64_t kTpInitialMaxStreamDataBidiRemote = 0x06;
constexpr uint64_t kTpInitialMaxStreamDataUni = 0x07;
constexpr uint64_t kTpInitialMaxStreamsBidi = 0x08;
constexpr uint64_t kTpInitialMaxStreamsUni = 0x09;
constexpr uint64_t kTpAckDelayExponent = 0x0a;
constexpr uint64_t kTpMaxAckDelay = 0x0b;
constexpr uint64_t kTpActiveConnectionIdLimit = 0x0e;
constexpr uint64_t kTpInitialSourceCid = 0x0f;
constexpr uint64_t kTpMaxDatagramFrameSize = 0x20;
constexpr uint64_t kTpResetStreamAt = 0x17f7586d2cb570ULL;

size_t LevelIndex(QuicEncryptionLevel level) {
  return static_cast<size_t>(level);
}

void ComputeAeadNonce(const std::array<uint8_t, 12>& iv,
                      uint64_t packet_number,
                      uint8_t out_nonce[12]) {
  std::memcpy(out_nonce, iv.data(), 12);
  uint8_t pn_be[8];
  WriteBigEndian32(pn_be, static_cast<uint32_t>(packet_number >> 32));
  WriteBigEndian32(pn_be + 4, static_cast<uint32_t>(packet_number & 0xFFFFFFFFULL));
  for (size_t i = 0; i < 8; ++i) {
    out_nonce[4 + i] ^= pn_be[i];
  }
}

bool ComputeHeaderProtectionMask(const std::array<uint8_t, 16>& hp_key,
                                 const uint8_t sample[16],
                                 uint8_t out_mask[16]) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return false;
  }
  int out_len = 0;
  int final_len = 0;
  const bool ok =
      EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, hp_key.data(),
                         nullptr) == 1 &&
      EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
      EVP_EncryptUpdate(ctx, out_mask, &out_len, sample, 16) == 1 &&
      EVP_EncryptFinal_ex(ctx, out_mask + out_len, &final_len) == 1 &&
      (out_len + final_len == 16);
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

void AppendTpVarInt(uint64_t id, uint64_t val, std::vector<uint8_t>* out) {
  std::vector<uint8_t> encoded_val;
  QuicVarInt::Append(val, &encoded_val);
  QuicVarInt::Append(id, out);
  QuicVarInt::Append(encoded_val.size(), out);
  out->insert(out->end(), encoded_val.begin(), encoded_val.end());
}

void AppendTpBytes(uint64_t id,
                   ArrayView<const uint8_t> bytes,
                   std::vector<uint8_t>* out) {
  QuicVarInt::Append(id, out);
  QuicVarInt::Append(bytes.size(), out);
  out->insert(out->end(), bytes.begin(), bytes.end());
}

bool ShouldSimulateDrop(double prob) {
  if (prob <= 0.0) {
    return false;
  }
  thread_local std::mt19937 rng{0x51554943u};
  std::uniform_real_distribution<double> dist(0.0, 1.0);
  return dist(rng) < prob;
}

}  // namespace

// ======================= QuicTransportParameters 传输参数编解码 =======================

std::vector<uint8_t> QuicTransportParameters::Encode() const {
  std::vector<uint8_t> out;
  out.reserve(96);
  if (has_original_destination_cid) {
    AppendTpBytes(kTpOriginalDestinationCid, original_destination_cid, &out);
  }
  AppendTpVarInt(kTpMaxIdleTimeout, max_idle_timeout_ms, &out);
  if (max_udp_payload_size != 65527) {
    AppendTpVarInt(kTpMaxUdpPayloadSize, max_udp_payload_size, &out);
  }
  AppendTpVarInt(kTpInitialMaxData, initial_max_data, &out);
  AppendTpVarInt(kTpInitialMaxStreamDataBidiLocal,
                 initial_max_stream_data_bidi_local, &out);
  AppendTpVarInt(kTpInitialMaxStreamDataBidiRemote,
                 initial_max_stream_data_bidi_remote, &out);
  AppendTpVarInt(kTpInitialMaxStreamDataUni, initial_max_stream_data_uni, &out);
  AppendTpVarInt(kTpInitialMaxStreamsBidi, initial_max_streams_bidi, &out);
  AppendTpVarInt(kTpInitialMaxStreamsUni, initial_max_streams_uni, &out);
  if (ack_delay_exponent != 3) {
    AppendTpVarInt(kTpAckDelayExponent, ack_delay_exponent, &out);
  }
  if (max_ack_delay_ms != 25) {
    AppendTpVarInt(kTpMaxAckDelay, max_ack_delay_ms, &out);
  }
  AppendTpVarInt(kTpActiveConnectionIdLimit,
                 std::max<uint64_t>(2, active_connection_id_limit), &out);
  AppendTpBytes(kTpInitialSourceCid, initial_source_cid, &out);
  if (max_datagram_frame_size > 0) {
    AppendTpVarInt(kTpMaxDatagramFrameSize, max_datagram_frame_size, &out);
  }
  if (reset_stream_at_supported) {
    AppendTpBytes(kTpResetStreamAt, ArrayView<const uint8_t>(), &out);
  }
  return out;
}

std::optional<QuicTransportParameters> QuicTransportParameters::Decode(
    ArrayView<const uint8_t> data) {
  QuicTransportParameters tp;
  tp.max_datagram_frame_size = 0;
  tp.reset_stream_at_supported = false;
  size_t off = 0;
  while (off < data.size()) {
    uint64_t id = 0;
    uint64_t len = 0;
    if (!QuicVarInt::Read(data, &off, &id) ||
        !QuicVarInt::Read(data, &off, &len) || len > data.size() - off) {
      return std::nullopt;
    }
    const ArrayView<const uint8_t> val_slice =
        data.subview(off, static_cast<size_t>(len));
    size_t voff = 0;
    switch (id) {
      case kTpOriginalDestinationCid:
        if (val_slice.size() > kQuicMaxCidLength) {
          return std::nullopt;
        }
        tp.original_destination_cid.Assign(val_slice.data(), val_slice.size());
        tp.has_original_destination_cid = true;
        break;
      case kTpMaxIdleTimeout:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.max_idle_timeout_ms) ||
            voff != val_slice.size()) {
          return std::nullopt;
        }
        break;
      case kTpMaxUdpPayloadSize:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.max_udp_payload_size) ||
            voff != val_slice.size() || tp.max_udp_payload_size < 1200) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxData:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.initial_max_data) ||
            voff != val_slice.size()) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxStreamDataBidiLocal:
        if (!QuicVarInt::Read(val_slice, &voff,
                              &tp.initial_max_stream_data_bidi_local) ||
            voff != val_slice.size()) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxStreamDataBidiRemote:
        if (!QuicVarInt::Read(val_slice, &voff,
                              &tp.initial_max_stream_data_bidi_remote) ||
            voff != val_slice.size()) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxStreamDataUni:
        if (!QuicVarInt::Read(val_slice, &voff,
                              &tp.initial_max_stream_data_uni) ||
            voff != val_slice.size()) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxStreamsBidi:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.initial_max_streams_bidi) ||
            voff != val_slice.size() ||
            tp.initial_max_streams_bidi > (uint64_t{1} << 60)) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxStreamsUni:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.initial_max_streams_uni) ||
            voff != val_slice.size() ||
            tp.initial_max_streams_uni > (uint64_t{1} << 60)) {
          return std::nullopt;
        }
        break;
      case kTpAckDelayExponent:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.ack_delay_exponent) ||
            voff != val_slice.size() || tp.ack_delay_exponent > 20) {
          return std::nullopt;
        }
        break;
      case kTpMaxAckDelay:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.max_ack_delay_ms) ||
            voff != val_slice.size() ||
            tp.max_ack_delay_ms >= (uint64_t{1} << 14)) {
          return std::nullopt;
        }
        break;
      case kTpActiveConnectionIdLimit:
        if (!QuicVarInt::Read(val_slice, &voff,
                              &tp.active_connection_id_limit) ||
            voff != val_slice.size() || tp.active_connection_id_limit < 2) {
          return std::nullopt;
        }
        break;
      case kTpInitialSourceCid:
        if (val_slice.size() > kQuicMaxCidLength) {
          return std::nullopt;
        }
        tp.initial_source_cid.Assign(val_slice.data(), val_slice.size());
        tp.has_initial_source_cid = true;
        break;
      case kTpMaxDatagramFrameSize:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.max_datagram_frame_size) ||
            voff != val_slice.size()) {
          return std::nullopt;
        }
        break;
      case kTpResetStreamAt:
        if (!val_slice.empty()) {
          return std::nullopt;
        }
        tp.reset_stream_at_supported = true;
        break;
      default:
        break;
    }
    off += static_cast<size_t>(len);
  }
  return tp;
}

// ======================= QuicCryptoUtils 加密与包保护工具 =======================

QuicCid QuicCryptoUtils::GenerateRandomCid() {
  QuicCid cid{};
  RAND_bytes(cid.data(), static_cast<int>(cid.size()));
  return cid;
}

bool QuicCryptoUtils::HkdfExtract(ArrayView<const uint8_t> salt,
                                  ArrayView<const uint8_t> ikm,
                                  std::array<uint8_t, 32>* out_prk) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (ctx == nullptr) {
    return false;
  }
  size_t out_len = out_prk->size();
  const bool ok =
      EVP_PKEY_derive_init(ctx) > 0 &&
      EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) > 0 &&
      EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
      EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(),
                                  static_cast<int>(salt.size())) > 0 &&
      EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(),
                                 static_cast<int>(ikm.size())) > 0 &&
      EVP_PKEY_derive(ctx, out_prk->data(), &out_len) > 0 && out_len == 32;
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

bool QuicCryptoUtils::HkdfExpandLabel(ArrayView<const uint8_t> secret,
                                      std::string_view label,
                                      ArrayView<const uint8_t> context,
                                      uint8_t* out,
                                      size_t out_len) {
  if (label.size() > 249 || context.size() > 255 || out_len > 65535) {
    return false;
  }
  std::vector<uint8_t> hkdf_label;
  hkdf_label.reserve(4 + 6 + label.size() + context.size());
  hkdf_label.push_back(static_cast<uint8_t>((out_len >> 8) & 0xFF));
  hkdf_label.push_back(static_cast<uint8_t>(out_len & 0xFF));
  hkdf_label.push_back(static_cast<uint8_t>(6 + label.size()));
  const char* kPrefix = "tls13 ";
  hkdf_label.insert(hkdf_label.end(), kPrefix, kPrefix + 6);
  hkdf_label.insert(hkdf_label.end(), label.begin(), label.end());
  hkdf_label.push_back(static_cast<uint8_t>(context.size()));
  hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (ctx == nullptr) {
    return false;
  }
  size_t derived_len = out_len;
  const bool ok =
      EVP_PKEY_derive_init(ctx) > 0 &&
      EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) > 0 &&
      EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
      EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.data(),
                                 static_cast<int>(secret.size())) > 0 &&
      EVP_PKEY_CTX_add1_hkdf_info(ctx, hkdf_label.data(),
                                  static_cast<int>(hkdf_label.size())) > 0 &&
      EVP_PKEY_derive(ctx, out, &derived_len) > 0 && derived_len == out_len;
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

bool QuicCryptoUtils::DeriveTrafficKeysFromSecret(
    const std::array<uint8_t, 32>& secret,
    QuicTrafficKeys* out_keys) {
  out_keys->secret = secret;
  ArrayView<const uint8_t> empty_ctx;
  if (!HkdfExpandLabel(secret, "quic key", empty_ctx,
                       out_keys->aead_key.data(), out_keys->aead_key.size()) ||
      !HkdfExpandLabel(secret, "quic iv", empty_ctx, out_keys->aead_iv.data(),
                       out_keys->aead_iv.size()) ||
      !HkdfExpandLabel(secret, "quic hp", empty_ctx, out_keys->hp_key.data(),
                       out_keys->hp_key.size())) {
    out_keys->valid = false;
    return false;
  }
  out_keys->valid = true;
  return true;
}

bool QuicCryptoUtils::DeriveInitialKeys(
    ArrayView<const uint8_t> client_dst_cid,
    QuicTrafficKeys* out_client_keys,
    QuicTrafficKeys* out_server_keys,
    std::array<uint8_t, 32>* out_initial_secret) {
  std::array<uint8_t, 32> initial_secret{};
  if (!HkdfExtract(kQuicV1InitialSalt, client_dst_cid, &initial_secret)) {
    return false;
  }
  if (out_initial_secret != nullptr) {
    *out_initial_secret = initial_secret;
  }

  std::array<uint8_t, 32> client_secret{};
  std::array<uint8_t, 32> server_secret{};
  ArrayView<const uint8_t> empty_ctx;
  if (!HkdfExpandLabel(initial_secret, "client in", empty_ctx,
                       client_secret.data(), client_secret.size()) ||
      !HkdfExpandLabel(initial_secret, "server in", empty_ctx,
                       server_secret.data(), server_secret.size())) {
    return false;
  }
  return DeriveTrafficKeysFromSecret(client_secret, out_client_keys) &&
         DeriveTrafficKeysFromSecret(server_secret, out_server_keys);
}

bool QuicCryptoUtils::GenerateX25519KeyPair(
    std::array<uint8_t, 32>* out_private_key,
    std::array<uint8_t, 32>* out_public_key) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (ctx == nullptr) {
    return false;
  }
  EVP_PKEY* pkey = nullptr;
  bool ok =
      EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_keygen(ctx, &pkey) > 0 &&
      pkey != nullptr;
  if (ok) {
    size_t priv_len = 32;
    size_t pub_len = 32;
    ok = EVP_PKEY_get_raw_private_key(pkey, out_private_key->data(),
                                      &priv_len) == 1 &&
         EVP_PKEY_get_raw_public_key(pkey, out_public_key->data(), &pub_len) ==
             1 &&
         priv_len == 32 && pub_len == 32;
  }
  if (pkey != nullptr) {
    EVP_PKEY_free(pkey);
  }
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

bool QuicCryptoUtils::ComputeX25519SharedSecret(
    const std::array<uint8_t, 32>& private_key,
    const std::array<uint8_t, 32>& peer_public_key,
    std::array<uint8_t, 32>* out_shared_secret) {
  EVP_PKEY* local_key = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
  EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, peer_public_key.data(), peer_public_key.size());
  if (local_key == nullptr || peer_key == nullptr) {
    if (local_key != nullptr) EVP_PKEY_free(local_key);
    if (peer_key != nullptr) EVP_PKEY_free(peer_key);
    return false;
  }
  EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(local_key, nullptr);
  size_t secret_len = out_shared_secret->size();
  const bool ok = dctx != nullptr && EVP_PKEY_derive_init(dctx) > 0 &&
                  EVP_PKEY_derive_set_peer(dctx, peer_key) > 0 &&
                  EVP_PKEY_derive(dctx, out_shared_secret->data(),
                                  &secret_len) > 0 &&
                  secret_len == 32;
  if (dctx != nullptr) {
    EVP_PKEY_CTX_free(dctx);
  }
  EVP_PKEY_free(local_key);
  EVP_PKEY_free(peer_key);
  return ok;
}

std::array<uint8_t, 32> QuicCryptoUtils::Sha256(ArrayView<const uint8_t> data) {
  std::array<uint8_t, 32> digest{};
  unsigned int out_len = 0;
  EVP_Digest(data.data(), data.size(), digest.data(), &out_len, EVP_sha256(),
             nullptr);
  return digest;
}

bool QuicCryptoUtils::HmacSha256(ArrayView<const uint8_t> key,
                                 ArrayView<const uint8_t> data,
                                 std::array<uint8_t, 32>* out_mac) {
  unsigned int mac_len = 0;
  const unsigned char* res =
      HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(),
           data.size(), out_mac->data(), &mac_len);
  return res != nullptr && mac_len == 32;
}

uint64_t QuicCryptoUtils::DecodePacketNumber(int64_t largest_pn,
                                             uint64_t truncated_pn,
                                             size_t pn_nbits) {
  const uint64_t expected_pn =
      (largest_pn < 0) ? 0ULL : static_cast<uint64_t>(largest_pn) + 1ULL;
  const uint64_t pn_win = uint64_t{1} << pn_nbits;
  const uint64_t pn_hwin = pn_win / 2;
  const uint64_t pn_mask = pn_win - 1;

  const uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
  if (candidate_pn + pn_hwin <= expected_pn &&
      candidate_pn < (uint64_t{1} << 62) - pn_win) {
    return candidate_pn + pn_win;
  }
  if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win) {
    return candidate_pn - pn_win;
  }
  return candidate_pn;
}

std::vector<uint8_t> QuicCryptoUtils::ProtectPacket(
    const QuicTrafficKeys& keys,
    uint64_t full_packet_number,
    ArrayView<const uint8_t> unmasked_header_without_length,
    bool is_long_header,
    ArrayView<const uint8_t> plaintext,
    size_t min_datagram_bytes) {
  if (!keys.valid || unmasked_header_without_length.empty()) {
    return {};
  }

  std::vector<uint8_t> padded(plaintext.begin(), plaintext.end());
  // 根据 RFC 9001 第 5.4.2 节填充明文，确保密文长度足以提取 16 字节包头保护采样。
  while (padded.size() < 4) {
    padded.push_back(static_cast<uint8_t>(kFramePadding));
  }

  constexpr size_t kPnLen = 4;
  if (min_datagram_bytes > 0) {
    const size_t length_varint_overhead = is_long_header ? 2 : 0;
    const size_t base_overhead = unmasked_header_without_length.size() +
                                 length_varint_overhead + kPnLen +
                                 kQuicAeadTagLength;
    if (min_datagram_bytes > base_overhead &&
        padded.size() < min_datagram_bytes - base_overhead) {
      padded.resize(min_datagram_bytes - base_overhead,
                    static_cast<uint8_t>(kFramePadding));
    }
  }

  std::vector<uint8_t> hdr(unmasked_header_without_length.begin(),
                           unmasked_header_without_length.end());
  hdr[0] = static_cast<uint8_t>((hdr[0] & ~0x03u) | (kPnLen - 1));
  if (is_long_header) {
    const uint64_t length_field = kPnLen + padded.size() + kQuicAeadTagLength;
    QuicVarInt::Append(length_field, &hdr);
  }

  const size_t pn_offset = hdr.size();
  uint8_t pn_bytes[4];
  WriteBigEndian32(pn_bytes,
                   static_cast<uint32_t>(full_packet_number & 0xFFFFFFFFULL));
  hdr.insert(hdr.end(), pn_bytes, pn_bytes + kPnLen);

  uint8_t nonce[12];
  ComputeAeadNonce(keys.aead_iv, full_packet_number, nonce);

  std::vector<uint8_t> pkt(hdr.size() + padded.size() + kQuicAeadTagLength);
  std::memcpy(pkt.data(), hdr.data(), hdr.size());

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return {};
  }
  int aad_len = 0;
  int enc_len = 0;
  int final_len = 0;
  const bool enc_ok =
      EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) ==
          1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, keys.aead_key.data(), nonce) ==
          1 &&
      EVP_EncryptUpdate(ctx, nullptr, &aad_len, hdr.data(),
                        static_cast<int>(hdr.size())) == 1 &&
      EVP_EncryptUpdate(ctx, pkt.data() + hdr.size(), &enc_len, padded.data(),
                        static_cast<int>(padded.size())) == 1 &&
      EVP_EncryptFinal_ex(ctx, pkt.data() + hdr.size() + enc_len, &final_len) ==
          1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                          static_cast<int>(kQuicAeadTagLength),
                          pkt.data() + hdr.size() + padded.size()) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!enc_ok) {
    return {};
  }

  const size_t sample_offset = pn_offset + 4;
  if (sample_offset + 16 > pkt.size()) {
    return {};
  }
  uint8_t mask[16];
  if (!ComputeHeaderProtectionMask(keys.hp_key, pkt.data() + sample_offset,
                                   mask)) {
    return {};
  }

  pkt[0] ^= static_cast<uint8_t>(mask[0] & (is_long_header ? 0x0fu : 0x1fu));
  for (size_t i = 0; i < kPnLen; ++i) {
    pkt[pn_offset + i] ^= mask[1 + i];
  }
  return pkt;
}

std::optional<QuicCryptoUtils::UnprotectedPacket>
QuicCryptoUtils::InspectHeaderIds(ArrayView<const uint8_t> datagram,
                                  bool* out_is_long_header,
                                  QuicEncryptionLevel* out_level,
                                  QuicCid* out_dcid,
                                  QuicCid* out_scid,
                                  size_t* out_total_packet_len,
                                  size_t short_dcid_len) {
  if (datagram.size() < 1 + 4 + kQuicAeadTagLength) {
    return std::nullopt;
  }
  const uint8_t first = datagram[0];
  if ((first & 0x40u) == 0) {
    return std::nullopt;
  }

  const bool is_long = (first & 0x80u) != 0;
  *out_is_long_header = is_long;
  UnprotectedPacket info;
  if (!is_long) {
    if (short_dcid_len > kQuicMaxCidLength ||
        datagram.size() < 1 + short_dcid_len + 4 + kQuicAeadTagLength) {
      return std::nullopt;
    }
    *out_level = QuicEncryptionLevel::kOneRtt;
    out_dcid->Assign(short_dcid_len > 0 ? (datagram.data() + 1) : nullptr,
                     short_dcid_len);
    out_scid->Assign(nullptr, 0);
    *out_total_packet_len = datagram.size();
    info.level = QuicEncryptionLevel::kOneRtt;
    info.dcid = *out_dcid;
    info.consumed_datagram_bytes = datagram.size();
    return info;
  }

  if (datagram.size() < 7) {
    return std::nullopt;
  }
  const uint32_t version = ReadBigEndian32(datagram.data() + 1);
  if (version != kQuicVersion1) {
    return std::nullopt;
  }
  const uint8_t long_type = (first >> 4) & 0x03u;
  if (long_type == 0x00) {
    *out_level = QuicEncryptionLevel::kInitial;
  } else if (long_type == 0x02) {
    *out_level = QuicEncryptionLevel::kHandshake;
  } else {
    return std::nullopt;
  }

  size_t off = 5;
  const uint8_t dcid_len = datagram[off++];
  if (dcid_len > kQuicMaxCidLength || off + dcid_len + 1 > datagram.size()) {
    return std::nullopt;
  }
  out_dcid->Assign(datagram.data() + off, dcid_len);
  off += dcid_len;

  const uint8_t scid_len = datagram[off++];
  if (scid_len > kQuicMaxCidLength || off + scid_len > datagram.size()) {
    return std::nullopt;
  }
  out_scid->Assign(datagram.data() + off, scid_len);
  off += scid_len;

  if (*out_level == QuicEncryptionLevel::kInitial) {
    uint64_t token_len = 0;
    if (!QuicVarInt::Read(datagram, &off, &token_len) ||
        token_len > datagram.size() - off) {
      return std::nullopt;
    }
    off += static_cast<size_t>(token_len);
  }

  uint64_t rem_len = 0;
  if (!QuicVarInt::Read(datagram, &off, &rem_len) ||
      rem_len > datagram.size() - off || rem_len < 1 + kQuicAeadTagLength) {
    return std::nullopt;
  }

  *out_total_packet_len = off + static_cast<size_t>(rem_len);
  info.level = *out_level;
  info.dcid = *out_dcid;
  info.scid = *out_scid;
  info.consumed_datagram_bytes = *out_total_packet_len;
  return info;
}

std::optional<QuicCryptoUtils::UnprotectedPacket>
QuicCryptoUtils::UnprotectPacket(ArrayView<const uint8_t> datagram,
                                 const QuicTrafficKeys& keys,
                                 int64_t largest_authenticated_pn,
                                 size_t short_dcid_len) {
  if (!keys.valid) {
    return std::nullopt;
  }

  bool is_long = false;
  QuicEncryptionLevel level = QuicEncryptionLevel::kOneRtt;
  QuicCid dcid{};
  QuicCid scid{};
  size_t total_pkt_len = 0;
  if (!InspectHeaderIds(datagram, &is_long, &level, &dcid, &scid,
                        &total_pkt_len, short_dcid_len)) {
    return std::nullopt;
  }

  const ArrayView<const uint8_t> pkt = datagram.subview(0, total_pkt_len);
  size_t pn_offset = 0;
  if (!is_long) {
    pn_offset = 1 + short_dcid_len;
  } else {
    pn_offset = 5 + 1 + dcid.size() + 1 + scid.size();
    if (level == QuicEncryptionLevel::kInitial) {
      uint64_t token_len = 0;
      if (!QuicVarInt::Read(pkt, &pn_offset, &token_len)) {
        return std::nullopt;
      }
      pn_offset += static_cast<size_t>(token_len);
    }
    uint64_t rem_len = 0;
    if (!QuicVarInt::Read(pkt, &pn_offset, &rem_len)) {
      return std::nullopt;
    }
  }

  const size_t sample_offset = pn_offset + 4;
  if (sample_offset + 16 > pkt.size()) {
    return std::nullopt;
  }

  uint8_t mask[16];
  if (!ComputeHeaderProtectionMask(keys.hp_key, pkt.data() + sample_offset,
                                   mask)) {
    return std::nullopt;
  }

  const uint8_t unmasked_first =
      pkt[0] ^ static_cast<uint8_t>(mask[0] & (is_long ? 0x0fu : 0x1fu));
  const size_t pn_len = static_cast<size_t>((unmasked_first & 0x03u) + 1u);
  if (pn_offset + pn_len + kQuicAeadTagLength > pkt.size()) {
    return std::nullopt;
  }

  uint64_t truncated_pn = 0;
  std::vector<uint8_t> aad(pkt.begin(),
                           pkt.begin() + static_cast<ptrdiff_t>(pn_offset + pn_len));
  aad[0] = unmasked_first;
  for (size_t i = 0; i < pn_len; ++i) {
    const uint8_t pn_byte = pkt[pn_offset + i] ^ mask[1 + i];
    aad[pn_offset + i] = pn_byte;
    truncated_pn = (truncated_pn << 8) | pn_byte;
  }

  const uint64_t full_pn =
      DecodePacketNumber(largest_authenticated_pn, truncated_pn, pn_len * 8);

  uint8_t nonce[12];
  ComputeAeadNonce(keys.aead_iv, full_pn, nonce);

  const size_t ciphertext_offset = pn_offset + pn_len;
  const size_t ciphertext_with_tag_len = pkt.size() - ciphertext_offset;
  const size_t ct_len = ciphertext_with_tag_len - kQuicAeadTagLength;

  std::vector<uint8_t> plaintext(ct_len);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return std::nullopt;
  }
  int aad_len = 0;
  int dec_len = 0;
  int final_len = 0;
  uint8_t tag_copy[kQuicAeadTagLength];
  std::memcpy(tag_copy, pkt.data() + ciphertext_offset + ct_len,
              kQuicAeadTagLength);

  const bool dec_ok =
      EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) ==
          1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, keys.aead_key.data(), nonce) ==
          1 &&
      EVP_DecryptUpdate(ctx, nullptr, &aad_len, aad.data(),
                        static_cast<int>(aad.size())) == 1 &&
      EVP_DecryptUpdate(ctx, plaintext.data(), &dec_len,
                        pkt.data() + ciphertext_offset,
                        static_cast<int>(ct_len)) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                          static_cast<int>(kQuicAeadTagLength), tag_copy) ==
          1 &&
      EVP_DecryptFinal_ex(ctx, plaintext.data() + dec_len, &final_len) == 1;
  EVP_CIPHER_CTX_free(ctx);

  if (!dec_ok) {
    return std::nullopt;
  }

  plaintext.resize(static_cast<size_t>(dec_len + final_len));
  UnprotectedPacket out;
  out.level = level;
  out.unmasked_first_byte = unmasked_first;
  out.dcid = dcid;
  out.scid = scid;
  out.packet_number = full_pn;
  out.plaintext = std::move(plaintext);
  out.consumed_datagram_bytes = pkt.size();
  return out;
}

// ======================= QuicAckRangeSet 选择性确认区间集 =======================

void QuicAckRangeSet::RecordReceived(uint64_t pn, bool ack_eliciting) {
  if (pn < min_acceptable_pn_) {
    return;
  }
  if (ack_eliciting) {
    ack_needed_ = true;
  }
  for (size_t i = 0; i < ranges_.size(); ++i) {
    if (pn >= ranges_[i].smallest && pn <= ranges_[i].largest) {
      return;
    }
    if (pn + 1 == ranges_[i].smallest) {
      ranges_[i].smallest = pn;
      if (i > 0 && ranges_[i - 1].largest + 1 == ranges_[i].smallest) {
        ranges_[i - 1].largest = ranges_[i].largest;
        ranges_.erase(ranges_.begin() + static_cast<ptrdiff_t>(i));
      }
      return;
    }
    if (pn == ranges_[i].largest + 1) {
      ranges_[i].largest = pn;
      if (i + 1 < ranges_.size() &&
          ranges_[i].largest + 1 == ranges_[i + 1].smallest) {
        ranges_[i].largest = ranges_[i + 1].largest;
        ranges_.erase(ranges_.begin() + static_cast<ptrdiff_t>(i + 1));
      }
      return;
    }
    if (pn < ranges_[i].smallest) {
      ranges_.insert(ranges_.begin() + static_cast<ptrdiff_t>(i),
                     Range{pn, pn});
      if (ranges_.size() > 32) {
        min_acceptable_pn_ =
            std::max(min_acceptable_pn_, ranges_.front().largest + 1);
        ranges_.erase(ranges_.begin());
      }
      return;
    }
  }
  ranges_.push_back(Range{pn, pn});
  if (ranges_.size() > 32) {
    min_acceptable_pn_ =
        std::max(min_acceptable_pn_, ranges_.front().largest + 1);
    ranges_.erase(ranges_.begin());
  }
}

bool QuicAckRangeSet::Contains(uint64_t pn) const {
  for (const auto& r : ranges_) {
    if (pn >= r.smallest && pn <= r.largest) {
      return true;
    }
  }
  return false;
}

void QuicAckRangeSet::EncodeAckFrame(uint64_t ack_delay_us,
                                     std::vector<uint8_t>* out) const {
  if (ranges_.empty()) {
    return;
  }
  const size_t max_blocks = std::min<size_t>(ranges_.size(), 16);
  const size_t first_idx = ranges_.size() - 1;
  const Range& top = ranges_[first_idx];

  QuicVarInt::Append(kFrameAck, out);
  QuicVarInt::Append(top.largest, out);
  // 默认 ack_delay_exponent = 3（即时间粒度为 2^3 = 8 微秒）。
  QuicVarInt::Append(ack_delay_us >> 3, out);
  QuicVarInt::Append(max_blocks - 1, out);
  QuicVarInt::Append(top.largest - top.smallest, out);

  uint64_t prev_smallest = top.smallest;
  for (size_t k = 1; k < max_blocks; ++k) {
    const Range& cur = ranges_[first_idx - k];
    const uint64_t gap = (prev_smallest - cur.largest) - 2;
    const uint64_t range_len = cur.largest - cur.smallest;
    QuicVarInt::Append(gap, out);
    QuicVarInt::Append(range_len, out);
    prev_smallest = cur.smallest;
  }
}

bool QuicAckRangeSet::DecodeAckFrame(ArrayView<const uint8_t> data,
                                     size_t* offset,
                                     uint64_t* out_ack_delay_us,
                                     std::vector<Range>* out_ranges,
                                     uint64_t ack_delay_exponent) {
  uint64_t frame_type = 0;
  if (!QuicVarInt::Read(data, offset, &frame_type) ||
      (frame_type != kFrameAck && frame_type != kFrameAckEcn)) {
    return false;
  }
  uint64_t largest_acked = 0;
  uint64_t raw_ack_delay = 0;
  uint64_t range_count = 0;
  uint64_t first_ack_range = 0;
  if (!QuicVarInt::Read(data, offset, &largest_acked) ||
      !QuicVarInt::Read(data, offset, &raw_ack_delay) ||
      !QuicVarInt::Read(data, offset, &range_count) ||
      !QuicVarInt::Read(data, offset, &first_ack_range) ||
      first_ack_range > largest_acked || range_count > 64) {
    return false;
  }

  const uint64_t shift = std::min<uint64_t>(ack_delay_exponent, 20);
  const uint64_t max_raw = std::numeric_limits<uint64_t>::max() >> shift;
  *out_ack_delay_us = std::min<uint64_t>(raw_ack_delay, max_raw) << shift;
  out_ranges->clear();
  uint64_t smallest = largest_acked - first_ack_range;
  out_ranges->push_back(Range{smallest, largest_acked});

  for (uint64_t i = 0; i < range_count; ++i) {
    uint64_t gap = 0;
    uint64_t ack_range_len = 0;
    if (!QuicVarInt::Read(data, offset, &gap) ||
        !QuicVarInt::Read(data, offset, &ack_range_len) ||
        smallest < gap + 2) {
      return false;
    }
    const uint64_t block_largest = smallest - gap - 2;
    if (ack_range_len > block_largest) {
      return false;
    }
    smallest = block_largest - ack_range_len;
    out_ranges->push_back(Range{smallest, block_largest});
  }

  if (frame_type == kFrameAckEcn) {
    uint64_t ect0 = 0;
    uint64_t ect1 = 0;
    uint64_t ce = 0;
    if (!QuicVarInt::Read(data, offset, &ect0) ||
        !QuicVarInt::Read(data, offset, &ect1) ||
        !QuicVarInt::Read(data, offset, &ce)) {
      return false;
    }
  }
  return true;
}

// ======================= QuicStreamReceiveBuffer 流接收重组缓冲区 =======================

bool QuicStreamReceiveBuffer::ValidateAndAccountReceive(
    uint64_t offset,
    size_t length,
    bool fin,
    uint64_t* out_newly_received_bytes,
    uint64_t* out_quic_error_code) {
  constexpr uint64_t kMaxQuicStreamOffset = (uint64_t{1} << 62) - 1;
  *out_newly_received_bytes = 0;
  *out_quic_error_code = 0;
  if (offset > kMaxQuicStreamOffset || length > kMaxQuicStreamOffset ||
      offset > kMaxQuicStreamOffset - length) {
    *out_quic_error_code = 0x03u;  // FLOW_CONTROL_ERROR
    return false;
  }
  const uint64_t end_offset = offset + length;
  if (flow_window_configured_ && end_offset > max_receive_offset_) {
    *out_quic_error_code = 0x03u;  // FLOW_CONTROL_ERROR
    return false;
  }
  if (final_offset_.has_value()) {
    if ((fin && *final_offset_ != end_offset) || end_offset > *final_offset_) {
      *out_quic_error_code = 0x06u;  // FINAL_SIZE_ERROR
      return false;
    }
  } else if (fin && end_offset < highest_received_offset_) {
    *out_quic_error_code = 0x06u;  // FINAL_SIZE_ERROR
    return false;
  }
  if (length > 0 && !stop_sending_requested_ && offset > next_deliver_offset_ &&
      chunks_.find(offset) == chunks_.end() &&
      chunks_.size() >= kMaxOutOfOrderChunks) {
    // 乱序缓存块达到上界时不关闭连接，仅拒绝接纳并阻止该包被确认以便对端在空洞补齐后重传；
    // 按序分片（offset <= next_deliver_offset_）始终放行。
    *out_quic_error_code = 0;
    return false;
  }
  if (end_offset > highest_received_offset_) {
    *out_newly_received_bytes = end_offset - highest_received_offset_;
    highest_received_offset_ = end_offset;
  }
  return true;
}

void QuicStreamReceiveBuffer::InsertChunk(uint64_t offset,
                                          ArrayView<const uint8_t> data,
                                          bool fin) {
  if (reset_ || fin_delivered_) {
    return;
  }
  const uint64_t chunk_end = offset + data.size();
  highest_received_offset_ = std::max(highest_received_offset_, chunk_end);
  if (fin) {
    final_offset_ = chunk_end;
  }
  if (stop_sending_requested_ || data.empty()) {
    return;
  }
  if (chunk_end <= next_deliver_offset_) {
    return;
  }

  uint64_t trimmed_offset = offset;
  ArrayView<const uint8_t> trimmed = data;
  if (trimmed_offset < next_deliver_offset_) {
    const size_t skip = static_cast<size_t>(next_deliver_offset_ - trimmed_offset);
    trimmed = trimmed.subview(skip);
    trimmed_offset = next_deliver_offset_;
  }

  auto it = chunks_.find(trimmed_offset);
  if (it == chunks_.end()) {
    if (trimmed_offset > next_deliver_offset_ &&
        chunks_.size() >= kMaxOutOfOrderChunks) {
      return;
    }
    chunks_[trimmed_offset].assign(trimmed.begin(), trimmed.end());
  } else if (it->second.size() < trimmed.size()) {
    it->second.assign(trimmed.begin(), trimmed.end());
  }
}

bool QuicStreamReceiveBuffer::ExtractContiguous(std::vector<uint8_t>* out_data,
                                                bool* out_fin) {
  const uint64_t max_off = pending_reset_reliable_size_.value_or(
      std::numeric_limits<uint64_t>::max());
  return ExtractContiguousUpTo(max_off, out_data, out_fin);
}

bool QuicStreamReceiveBuffer::ExtractContiguousUpTo(
    uint64_t max_offset,
    std::vector<uint8_t>* out_data,
    bool* out_fin) {
  out_data->clear();
  *out_fin = false;
  if (reset_ || fin_delivered_ || stop_sending_requested_) {
    return false;
  }

  while (!chunks_.empty() && next_deliver_offset_ < max_offset) {
    auto it = chunks_.begin();
    if (it->first > next_deliver_offset_) {
      break;
    }
    const uint64_t chunk_end = it->first + it->second.size();
    const uint64_t take_end = std::min(chunk_end, max_offset);
    if (take_end > next_deliver_offset_) {
      const size_t start_idx =
          static_cast<size_t>(next_deliver_offset_ - it->first);
      const size_t end_idx = static_cast<size_t>(take_end - it->first);
      out_data->insert(out_data->end(),
                       it->second.begin() + static_cast<ptrdiff_t>(start_idx),
                       it->second.begin() + static_cast<ptrdiff_t>(end_idx));
      next_deliver_offset_ = take_end;
    }
    if (chunk_end <= max_offset || pending_reset_reliable_size_.has_value()) {
      chunks_.erase(it);
    } else {
      break;
    }
  }

  if (!pending_reset_reliable_size_.has_value() && final_offset_.has_value() &&
      next_deliver_offset_ >= *final_offset_) {
    *out_fin = true;
    fin_delivered_ = true;
  }
  return !out_data->empty() || *out_fin;
}

void QuicStreamReceiveBuffer::Reset() {
  reset_ = true;
  pending_reset_reliable_size_.reset();
  chunks_.clear();
}

// ======================= 共享 QUIC 会话核心（遵循 RFC 9000/9001/9002） =======================

namespace {

class QuicSessionEvents {
 public:
  virtual ~QuicSessionEvents() = default;

  virtual void SendUdpDatagram(ArrayView<const uint8_t> bytes) = 0;
  virtual void OnHandshakeEstablished() = 0;
  virtual void OnConnectionClosed(int error_code) = 0;
  virtual void OnPeerStreamOpened(uint64_t stream_id, bool unidirectional) = 0;
  virtual void OnPeerStreamData(uint64_t stream_id,
                                ArrayView<const uint8_t> data,
                                bool fin) = 0;
  virtual void OnPeerStreamReset(uint64_t stream_id,
                                 uint64_t app_error_code) = 0;
  virtual void OnPeerStopSending(uint64_t stream_id,
                                 uint64_t app_error_code) = 0;
  virtual void OnPeerDatagramReceived(ArrayView<const uint8_t> data) = 0;
  virtual void OnHighestOneRttNonProbingPacket() {}
};

std::vector<std::string> SplitAlpnList(std::string_view csv) {
  std::vector<std::string> out;
  size_t pos = 0;
  while (pos < csv.size()) {
    const size_t comma = csv.find(',', pos);
    const std::string_view tok =
        (comma == std::string_view::npos) ? csv.substr(pos)
                                          : csv.substr(pos, comma - pos);
    if (!tok.empty()) {
      out.emplace_back(tok);
    }
    if (comma == std::string_view::npos) {
      break;
    }
    pos = comma + 1;
  }
  return out;
}

// 满足 W3C WebTransport `serverCertificateHashes` 规范要求的临时 ECDSA P-256 证书上下文
// （有效期 <= 14 天、包含 SAN localhost/127.0.0.1、支持 TLS 1.3 CertificateVerify 签名与验签）。
class QuicServerCertContext {
 public:
  static std::shared_ptr<QuicServerCertContext> GenerateEphemeralP256() {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    if (pkey == nullptr) {
      RTC_LOG(kError) << "OpenSSL EVP_PKEY_Q_keygen(EC P-256) failed for QUIC";
      return nullptr;
    }

    X509* x509 = X509_new();
    if (x509 == nullptr) {
      EVP_PKEY_free(pkey);
      return nullptr;
    }
    X509_set_version(x509, 2);

    uint64_t serial_rand = 1;
    RAND_bytes(reinterpret_cast<uint8_t*>(&serial_rand), sizeof(serial_rand));
    serial_rand = (serial_rand & 0x7FFFFFFFFFFFFFFFULL) | 1ULL;
    ASN1_INTEGER_set_uint64(X509_get_serialNumber(x509), serial_rand);

    // W3C WebTransport 规范强制要求自定义哈希证书总有效期不得超过 14 天（此处设为 10 天）。
    X509_gmtime_adj(X509_getm_notBefore(x509), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x509), 10L * 24 * 3600);
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, x509, x509, nullptr, nullptr, 0);
    if (X509_EXTENSION* ext_bc = X509V3_EXT_conf_nid(
            nullptr, &v3ctx, NID_basic_constraints, "critical,CA:FALSE")) {
      X509_add_ext(x509, ext_bc, -1);
      X509_EXTENSION_free(ext_bc);
    }
    if (X509_EXTENSION* ext_san = X509V3_EXT_conf_nid(
            nullptr, &v3ctx, NID_subject_alt_name,
            "DNS:localhost,IP:127.0.0.1,IP:::1")) {
      X509_add_ext(x509, ext_san, -1);
      X509_EXTENSION_free(ext_san);
    }

    if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
      X509_free(x509);
      EVP_PKEY_free(pkey);
      return nullptr;
    }

    unsigned char* der_ptr = nullptr;
    const int der_len = i2d_X509(x509, &der_ptr);
    X509_free(x509);
    if (der_len <= 0 || der_ptr == nullptr) {
      EVP_PKEY_free(pkey);
      return nullptr;
    }
    std::vector<uint8_t> der(der_ptr, der_ptr + der_len);
    OPENSSL_free(der_ptr);

    const auto sha256 = QuicCryptoUtils::Sha256(der);
    std::ostringstream hex_oss;
    hex_oss << std::hex << std::setfill('0');
    for (uint8_t b : sha256) {
      hex_oss << std::setw(2) << static_cast<int>(b);
    }

    return std::shared_ptr<QuicServerCertContext>(new QuicServerCertContext(
        pkey, std::move(der), sha256, hex_oss.str()));
  }

  ~QuicServerCertContext() {
    if (pkey_ != nullptr) {
      EVP_PKEY_free(pkey_);
    }
  }

  QuicServerCertContext(const QuicServerCertContext&) = delete;
  QuicServerCertContext& operator=(const QuicServerCertContext&) = delete;

  const std::vector<uint8_t>& der_bytes() const { return der_bytes_; }
  const std::array<uint8_t, 32>& sha256() const { return sha256_; }
  const std::string& sha256_hex() const { return sha256_hex_; }

  static std::array<uint8_t, 130> BuildServerCertVerifyInput(
      const std::array<uint8_t, 32>& transcript_hash) {
    static constexpr char kLabel[] = "TLS 1.3, server CertificateVerify";
    std::array<uint8_t, 130> content{};
    std::memset(content.data(), 0x20, 64);
    std::memcpy(content.data() + 64, kLabel, 33);
    content[97] = 0x00;
    std::memcpy(content.data() + 98, transcript_hash.data(), 32);
    return content;
  }

  bool SignServerCertVerify(const std::array<uint8_t, 32>& transcript_hash,
                            std::vector<uint8_t>* out_sig) const {
    if (pkey_ == nullptr || out_sig == nullptr) {
      return false;
    }
    const auto content = BuildServerCertVerifyInput(transcript_hash);
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == nullptr) {
      return false;
    }
    size_t sig_len = 0;
    bool ok = EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr,
                                 pkey_) == 1 &&
              EVP_DigestSign(md_ctx, nullptr, &sig_len, content.data(),
                             content.size()) == 1 &&
              sig_len > 0;
    if (ok) {
      out_sig->resize(sig_len);
      ok = EVP_DigestSign(md_ctx, out_sig->data(), &sig_len, content.data(),
                          content.size()) == 1;
      out_sig->resize(sig_len);
    }
    EVP_MD_CTX_free(md_ctx);
    return ok;
  }

  static bool VerifyServerCertVerify(
      ArrayView<const uint8_t> cert_der,
      uint16_t sig_scheme,
      ArrayView<const uint8_t> signature,
      const std::array<uint8_t, 32>& transcript_hash) {
    if ((sig_scheme != kTlsSigEcdsaSecp256r1Sha256 &&
         sig_scheme != kTlsSigRsaPssRsaeSha256) ||
        cert_der.empty() || signature.empty()) {
      return false;
    }
    const unsigned char* p = cert_der.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(cert_der.size()));
    if (cert == nullptr || p != cert_der.data() + cert_der.size()) {
      if (cert != nullptr) {
        X509_free(cert);
      }
      return false;
    }
    const bool time_valid =
        X509_cmp_current_time(X509_get0_notBefore(cert)) <= 0 &&
        X509_cmp_current_time(X509_get0_notAfter(cert)) >= 0;
    EVP_PKEY* pub = X509_get0_pubkey(cert);
    if (!time_valid || pub == nullptr) {
      X509_free(cert);
      return false;
    }
    const int key_id = EVP_PKEY_base_id(pub);
    if (sig_scheme == kTlsSigEcdsaSecp256r1Sha256) {
      if (key_id != EVP_PKEY_EC || EVP_PKEY_bits(pub) != 256) {
        X509_free(cert);
        return false;
      }
    } else if (sig_scheme == kTlsSigRsaPssRsaeSha256) {
      if (key_id != EVP_PKEY_RSA && key_id != EVP_PKEY_RSA_PSS) {
        X509_free(cert);
        return false;
      }
    }
    const auto content = BuildServerCertVerifyInput(transcript_hash);
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = md_ctx != nullptr &&
              EVP_DigestVerifyInit(md_ctx, &pctx, EVP_sha256(), nullptr, pub) ==
                  1 &&
              pctx != nullptr;
    if (ok && sig_scheme == kTlsSigRsaPssRsaeSha256) {
      ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
           EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0 &&
           EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) > 0;
    }
    if (ok) {
      ok = EVP_DigestVerify(md_ctx, signature.data(), signature.size(),
                            content.data(), content.size()) == 1;
    }
    if (md_ctx != nullptr) {
      EVP_MD_CTX_free(md_ctx);
    }
    X509_free(cert);
    return ok;
  }

 private:
  QuicServerCertContext(EVP_PKEY* pkey,
                        std::vector<uint8_t> der,
                        std::array<uint8_t, 32> sha256,
                        std::string sha256_hex)
      : pkey_(pkey),
        der_bytes_(std::move(der)),
        sha256_(sha256),
        sha256_hex_(std::move(sha256_hex)) {}

  EVP_PKEY* pkey_ = nullptr;
  std::vector<uint8_t> der_bytes_;
  std::array<uint8_t, 32> sha256_{};
  std::string sha256_hex_;
};

// RFC 5480 P-256 非压缩公钥 SubjectPublicKeyInfo ASN.1 DER 固定前缀，用于零弃用警告完成 P-256 ECDHE。
bool ComputeServerP256KeyExchange(ArrayView<const uint8_t> peer_uncompressed_pt,
                                  std::vector<uint8_t>* out_server_pub,
                                  std::array<uint8_t, 32>* out_shared_secret) {
  if (peer_uncompressed_pt.size() != 65 || peer_uncompressed_pt[0] != 0x04) {
    return false;
  }
  static constexpr uint8_t kP256SpkiPrefix[26] = {
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
      0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
      0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
  };
  std::vector<uint8_t> peer_spki(kP256SpkiPrefix, kP256SpkiPrefix + 26);
  peer_spki.insert(peer_spki.end(), peer_uncompressed_pt.begin(),
                   peer_uncompressed_pt.end());
  const unsigned char* pp = peer_spki.data();
  EVP_PKEY* peer_key =
      d2i_PUBKEY(nullptr, &pp, static_cast<long>(peer_spki.size()));
  if (peer_key == nullptr) {
    return false;
  }

  EVP_PKEY* local_key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
  if (local_key == nullptr) {
    EVP_PKEY_free(peer_key);
    return false;
  }

  unsigned char* local_spki = nullptr;
  const int spki_len = i2d_PUBKEY(local_key, &local_spki);
  bool ok = (spki_len == 91 && local_spki != nullptr && local_spki[26] == 0x04);
  if (ok) {
    out_server_pub->assign(local_spki + 26, local_spki + 91);
  }
  if (local_spki != nullptr) {
    OPENSSL_free(local_spki);
  }

  if (ok) {
    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(local_key, nullptr);
    size_t secret_len = out_shared_secret->size();
    ok = dctx != nullptr && EVP_PKEY_derive_init(dctx) > 0 &&
         EVP_PKEY_derive_set_peer(dctx, peer_key) > 0 &&
         EVP_PKEY_derive(dctx, out_shared_secret->data(), &secret_len) > 0 &&
         secret_len == 32;
    if (dctx != nullptr) {
      EVP_PKEY_CTX_free(dctx);
    }
  }
  EVP_PKEY_free(local_key);
  EVP_PKEY_free(peer_key);
  return ok;
}

void AppendUint16BE(uint16_t v, std::vector<uint8_t>* out) {
  out->push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
  out->push_back(static_cast<uint8_t>(v & 0xFFu));
}

void AppendUint24BE(size_t v, std::vector<uint8_t>* out) {
  out->push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
  out->push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
  out->push_back(static_cast<uint8_t>(v & 0xFFu));
}

void AppendTlsExt(uint16_t ext_type,
                  ArrayView<const uint8_t> ext_body,
                  std::vector<uint8_t>* out) {
  AppendUint16BE(ext_type, out);
  AppendUint16BE(static_cast<uint16_t>(ext_body.size()), out);
  out->insert(out->end(), ext_body.begin(), ext_body.end());
}

std::vector<uint8_t> WrapTlsHandshakeMsg(uint8_t hs_type,
                                         ArrayView<const uint8_t> body) {
  std::vector<uint8_t> msg;
  msg.reserve(4 + body.size());
  msg.push_back(hs_type);
  AppendUint24BE(body.size(), &msg);
  msg.insert(msg.end(), body.begin(), body.end());
  return msg;
}

struct QuicTlsVerifyConfig {
  bool verify_peer = false;
  std::string ca_cert_path;
  std::string pinned_cert_sha256;
};

bool NormalizeSha256PinHex(std::string_view input, std::string* out_upper_hex) {
  out_upper_hex->clear();
  out_upper_hex->reserve(64);
  for (char ch : input) {
    const unsigned char uc = static_cast<unsigned char>(ch);
    if (ch == ':' || std::isspace(uc) != 0) {
      continue;
    }
    if (std::isxdigit(uc) == 0) {
      return false;
    }
    out_upper_hex->push_back(static_cast<char>(std::toupper(uc)));
  }
  return out_upper_hex->size() == 64;
}

std::string BytesToUpperHex32(const std::array<uint8_t, 32>& digest) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(64);
  for (uint8_t b : digest) {
    out.push_back(kHex[(b >> 4) & 0x0Fu]);
    out.push_back(kHex[b & 0x0Fu]);
  }
  return out;
}

bool VerifyServerCertificateChain(
    const std::vector<std::vector<uint8_t>>& cert_chain_der,
    const QuicTlsVerifyConfig& cfg,
    const std::string& sni_host,
    uint64_t* out_tls_alert) {
  *out_tls_alert = 0x012au;  // bad_certificate
  if (cert_chain_der.empty() || cert_chain_der.front().empty()) {
    return false;
  }

  const unsigned char* leaf_p = cert_chain_der.front().data();
  X509* leaf = d2i_X509(nullptr, &leaf_p,
                        static_cast<long>(cert_chain_der.front().size()));
  if (leaf == nullptr ||
      leaf_p != cert_chain_der.front().data() + cert_chain_der.front().size()) {
    if (leaf != nullptr) {
      X509_free(leaf);
    }
    return false;
  }

  if (X509_cmp_current_time(X509_get0_notBefore(leaf)) > 0 ||
      X509_cmp_current_time(X509_get0_notAfter(leaf)) < 0) {
    *out_tls_alert = 0x012du;  // certificate_expired
    X509_free(leaf);
    return false;
  }

  STACK_OF(X509)* intermediates = sk_X509_new_null();
  if (intermediates == nullptr) {
    X509_free(leaf);
    return false;
  }
  for (size_t i = 1; i < cert_chain_der.size(); ++i) {
    const unsigned char* cp = cert_chain_der[i].data();
    X509* icert =
        d2i_X509(nullptr, &cp, static_cast<long>(cert_chain_der[i].size()));
    if (icert == nullptr ||
        cp != cert_chain_der[i].data() + cert_chain_der[i].size() ||
        sk_X509_push(intermediates, icert) == 0) {
      if (icert != nullptr) {
        X509_free(icert);
      }
      sk_X509_pop_free(intermediates, X509_free);
      X509_free(leaf);
      return false;
    }
  }

  if (!cfg.pinned_cert_sha256.empty()) {
    std::string expected_hex;
    const std::string actual_hex =
        BytesToUpperHex32(QuicCryptoUtils::Sha256(cert_chain_der.front()));
    if (!NormalizeSha256PinHex(cfg.pinned_cert_sha256, &expected_hex) ||
        CRYPTO_memcmp(actual_hex.data(), expected_hex.data(), 64) != 0) {
      RTC_LOG(kError) << "QUIC server leaf certificate SHA-256 pin mismatch";
      sk_X509_pop_free(intermediates, X509_free);
      X509_free(leaf);
      return false;
    }
    if (X509_cmp_current_time(X509_get0_notBefore(leaf)) > 0 ||
        X509_cmp_current_time(X509_get0_notAfter(leaf)) < 0) {
      RTC_LOG(kError) << "QUIC pinned server certificate is expired or not yet valid";
      *out_tls_alert = 0x012du;  // certificate_expired
      sk_X509_pop_free(intermediates, X509_free);
      X509_free(leaf);
      return false;
    }
  }

  const bool verify_ca_chain =
      !cfg.ca_cert_path.empty() ||
      (cfg.verify_peer && cfg.pinned_cert_sha256.empty());
  if (verify_ca_chain) {
    X509_STORE* store = X509_STORE_new();
    if (store == nullptr) {
      sk_X509_pop_free(intermediates, X509_free);
      X509_free(leaf);
      return false;
    }
    X509_STORE_set_default_paths(store);
    if (!cfg.ca_cert_path.empty()) {
      if (X509_STORE_load_locations(store, cfg.ca_cert_path.c_str(), nullptr) !=
              1 &&
          X509_STORE_load_locations(store, nullptr, cfg.ca_cert_path.c_str()) !=
              1) {
        RTC_LOG(kError) << "QUIC failed to load CA certificate path: "
                        << cfg.ca_cert_path;
        *out_tls_alert = 0x0130u;  // unknown_ca
        X509_STORE_free(store);
        sk_X509_pop_free(intermediates, X509_free);
        X509_free(leaf);
        return false;
      }
    }

    X509_STORE_CTX* sctx = X509_STORE_CTX_new();
    if (sctx == nullptr ||
        X509_STORE_CTX_init(sctx, store, leaf, intermediates) != 1) {
      if (sctx != nullptr) {
        X509_STORE_CTX_free(sctx);
      }
      X509_STORE_free(store);
      sk_X509_pop_free(intermediates, X509_free);
      X509_free(leaf);
      return false;
    }

    const int verify_rc = X509_verify_cert(sctx);
    const int verify_err = X509_STORE_CTX_get_error(sctx);
    X509_STORE_CTX_free(sctx);
    X509_STORE_free(store);
    if (verify_rc != 1) {
      RTC_LOG(kError) << "QUIC X.509 certificate verification failed: "
                      << X509_verify_cert_error_string(verify_err);
      *out_tls_alert = 0x0130u;  // unknown_ca
      sk_X509_pop_free(intermediates, X509_free);
      X509_free(leaf);
      return false;
    }

    if (!sni_host.empty()) {
      boost::system::error_code ip_ec;
      boost::asio::ip::make_address(sni_host, ip_ec);
      const int host_ok =
          !ip_ec ? X509_check_ip_asc(leaf, sni_host.c_str(), 0)
                 : X509_check_host(leaf, sni_host.data(), sni_host.size(),
                                   X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
                                   nullptr);
      if (host_ok != 1) {
        RTC_LOG(kError) << "QUIC X.509 SAN host/IP verification failed for "
                        << sni_host;
        *out_tls_alert = 0x012au;  // bad_certificate
        sk_X509_pop_free(intermediates, X509_free);
        X509_free(leaf);
        return false;
      }
    }
  }

  sk_X509_pop_free(intermediates, X509_free);
  X509_free(leaf);
  return true;
}

class QuicSessionCore {
 public:
  QuicSessionCore(
      Clock* clock,
      bool is_server,
      QuicCid local_scid,
      QuicCid initial_dcid,
      std::vector<std::string> supported_alpns,
      QuicSessionEvents* events,
      std::unique_ptr<IQuicCongestionController> initial_cc = nullptr,
      std::shared_ptr<QuicServerCertContext> server_cert = nullptr,
      std::string client_sni_host = {},
      QuicTlsVerifyConfig tls_verify_cfg = {})
      : clock_(clock),
        is_server_(is_server),
        local_scid_(local_scid),
        peer_dcid_(initial_dcid),
        initial_dcid_(initial_dcid),
        supported_alpns_(std::move(supported_alpns)),
        negotiated_alpn_(),
        events_(events),
        server_cert_(std::move(server_cert)),
        client_sni_host_(std::move(client_sni_host)),
        tls_verify_cfg_(std::move(tls_verify_cfg)),
        peer_address_validated_(!is_server),
        cc_(initial_cc ? std::move(initial_cc)
                       : CreateBuiltinQuicCongestionController(
                             RTC_QUIC_CC_BBR, kQuicMaxDatagramSize)) {
    if (is_server_ && !server_cert_) {
      server_cert_ = QuicServerCertContext::GenerateEphemeralP256();
    }
    local_tp_.initial_source_cid = local_scid_;
    local_tp_.has_initial_source_cid = true;
    if (is_server_) {
      local_tp_.original_destination_cid = initial_dcid_;
      local_tp_.has_original_destination_cid = true;
    }
    local_max_data_ = local_tp_.initial_max_data;
    local_max_streams_bidi_ = local_tp_.initial_max_streams_bidi;
    local_max_streams_uni_ = local_tp_.initial_max_streams_uni;
    peer_max_data_ = peer_tp_.initial_max_data;
    peer_max_streams_bidi_ = peer_tp_.initial_max_streams_bidi;
    peer_max_streams_uni_ = peer_tp_.initial_max_streams_uni;
    last_rx_time_ = clock_->CurrentTime();

    QuicTrafficKeys client_init;
    QuicTrafficKeys server_init;
    QuicCryptoUtils::DeriveInitialKeys(initial_dcid_, &client_init,
                                       &server_init, &initial_secret_);
    if (is_server_) {
      rx_keys_[LevelIndex(QuicEncryptionLevel::kInitial)] = client_init;
      tx_keys_[LevelIndex(QuicEncryptionLevel::kInitial)] = server_init;
    } else {
      tx_keys_[LevelIndex(QuicEncryptionLevel::kInitial)] = client_init;
      rx_keys_[LevelIndex(QuicEncryptionLevel::kInitial)] = server_init;
    }
    QuicCryptoUtils::GenerateX25519KeyPair(&local_x25519_priv_,
                                           &local_x25519_pub_);
    RAND_bytes(local_random_.data(), static_cast<int>(local_random_.size()));
  }

  void StartClientHandshake() {
    if (is_server_ || closed_) {
      return;
    }
    client_hello_bytes_ = BuildClientHello();
    QueueCryptoData(QuicEncryptionLevel::kInitial, client_hello_bytes_);
    FlushPackets(clock_->CurrentTime(), false);
  }

  void CloseConnection(uint64_t app_error_code) {
    if (closed_) {
      return;
    }
    if (!handshake_established_ ||
        !tx_keys_[LevelIndex(QuicEncryptionLevel::kOneRtt)].valid) {
      CloseTransportConnection(0x00u);
      return;
    }
    std::vector<uint8_t> close_frame;
    QuicVarInt::Append(kFrameConnectionCloseApp, &close_frame);
    QuicVarInt::Append(app_error_code, &close_frame);
    QuicVarInt::Append(0, &close_frame);
    // 主动关闭立即释放底层套接字后无法再走 PTO 重传，连发 2 个递增包号的幂等 CONNECTION_CLOSE 以抵抗弱网随机丢包。
    const Timestamp close_ts = clock_->CurrentTime();
    for (int attempt = 0; attempt < 2; ++attempt) {
      EmitSinglePacket(QuicEncryptionLevel::kOneRtt, close_frame, false,
                       std::vector<SentRetransmittable>{}, close_ts);
    }
    closed_ = true;
  }

  void CloseTransportConnection(uint64_t quic_transport_error) {
    if (closed_) {
      return;
    }
    QuicEncryptionLevel lvl = QuicEncryptionLevel::kInitial;
    if (tx_keys_[LevelIndex(QuicEncryptionLevel::kOneRtt)].valid) {
      lvl = QuicEncryptionLevel::kOneRtt;
    } else if (tx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].valid) {
      lvl = QuicEncryptionLevel::kHandshake;
    }
    std::vector<uint8_t> close_frame;
    QuicVarInt::Append(kFrameConnectionCloseQuic, &close_frame);
    QuicVarInt::Append(quic_transport_error, &close_frame);
    QuicVarInt::Append(0, &close_frame);
    QuicVarInt::Append(0, &close_frame);
    const Timestamp close_ts = clock_->CurrentTime();
    if (tx_keys_[LevelIndex(lvl)].valid) {
      for (int attempt = 0; attempt < 2; ++attempt) {
        EmitSinglePacket(lvl, close_frame, false,
                         std::vector<SentRetransmittable>{}, close_ts);
      }
    }
    closed_ = true;
  }

  void DiscardPacketSpace(QuicEncryptionLevel level) {
    const size_t idx = LevelIndex(level);
    rx_keys_[idx].valid = false;
    tx_keys_[idx].valid = false;
    for (const auto& [pn, info] : sent_packets_[idx]) {
      (void)pn;
      if (info.in_flight) {
        bytes_in_flight_ = (bytes_in_flight_ >= info.sent_bytes)
                               ? (bytes_in_flight_ - info.sent_bytes)
                               : 0;
      }
    }
    sent_packets_[idx].clear();
    crypto_tx_queue_[idx].clear();
    crypto_rx_buf_[idx].clear();
    crypto_rx_reassembler_[idx].Reset();
    ack_sets_[idx].ClearAckNeeded();
  }

  void SetTlsVerifyConfig(QuicTlsVerifyConfig cfg) {
    tls_verify_cfg_ = std::move(cfg);
  }

  bool has_authenticated_rx() const { return has_authenticated_rx_; }

  bool CanSendOnStream(uint64_t stream_id) const {
    const bool is_local = ((stream_id & 0x01u) == (is_server_ ? 1u : 0u));
    const bool is_uni = (stream_id & 0x02u) != 0;
    return is_local || !is_uni;
  }

  bool CanReceiveOnStream(uint64_t stream_id) const {
    const bool is_local = ((stream_id & 0x01u) == (is_server_ ? 1u : 0u));
    const bool is_uni = (stream_id & 0x02u) != 0;
    return !is_local || !is_uni;
  }

  size_t GetStreamUnsentBytes(uint64_t stream_id) const {
    const auto it = outbound_streams_.find(stream_id);
    return (it != outbound_streams_.end()) ? it->second.unsent_data.size() : 0;
  }

  void RegisterOutboundStream(uint64_t stream_id,
                              uint8_t publisher_priority,
                              int64_t send_order) {
    if (!CanSendOnStream(stream_id) || IsOutboundStreamRetired(stream_id)) {
      return;
    }
    const bool is_local = ((stream_id & 0x01u) == (is_server_ ? 1u : 0u));
    const bool is_uni = (stream_id & 0x02u) != 0;
    if (is_local) {
      if (is_uni) {
        local_opened_uni_count_ =
            std::max(local_opened_uni_count_, (stream_id >> 2) + 1);
      } else {
        local_opened_bidi_count_ =
            std::max(local_opened_bidi_count_, (stream_id >> 2) + 1);
      }
    }
    auto& st = outbound_streams_[stream_id];
    st.stream_id = stream_id;
    st.priority = publisher_priority;
    st.send_order = send_order;
    if (!st.flow_limit_initialized) {
      st.peer_max_stream_data = InitialPeerStreamMaxData(stream_id);
      st.flow_limit_initialized = true;
    }
  }

  int WriteStream(uint64_t stream_id, ArrayView<const uint8_t> data, bool fin) {
    if (closed_) {
      return RTC_ERR_NOT_CONNECTED;
    }
    if (!CanSendOnStream(stream_id) || IsOutboundStreamRetired(stream_id)) {
      return RTC_ERR_INVALID_ARG;
    }
    const bool is_local = ((stream_id & 0x01u) == (is_server_ ? 1u : 0u));
    const bool is_uni = (stream_id & 0x02u) != 0;
    if (is_local) {
      if (is_uni) {
        local_opened_uni_count_ =
            std::max(local_opened_uni_count_, (stream_id >> 2) + 1);
      } else {
        local_opened_bidi_count_ =
            std::max(local_opened_bidi_count_, (stream_id >> 2) + 1);
      }
    }
    auto& st = outbound_streams_[stream_id];
    st.stream_id = stream_id;
    if (!st.flow_limit_initialized) {
      st.peer_max_stream_data = InitialPeerStreamMaxData(stream_id);
      st.flow_limit_initialized = true;
    }
    if (st.reset || st.fin_queued || st.fin_sent) {
      return RTC_ERR_INVALID_ARG;
    }
    constexpr size_t kMaxOutboundStreamBufferBytes = 16 * 1024 * 1024;
    if (data.size() > kMaxOutboundStreamBufferBytes ||
        st.unsent_data.size() > kMaxOutboundStreamBufferBytes - data.size()) {
      return RTC_ERR_NO_MEMORY;
    }
    if (!data.empty()) {
      st.unsent_data.insert(st.unsent_data.end(), data.begin(), data.end());
    }
    if (fin) {
      st.fin_queued = true;
    }
    FlushPackets(clock_->CurrentTime(), false);
    return static_cast<int>(data.size());
  }

  void QueueResetStreamNoFlush(uint64_t stream_id,
                               uint64_t app_error_code,
                               bool allow_unopened_peer_bidi = false) {
    if (closed_ || !CanSendOnStream(stream_id) ||
        IsOutboundStreamRetired(stream_id)) {
      return;
    }
    const auto existing_it = outbound_streams_.find(stream_id);
    if (existing_it == outbound_streams_.end()) {
      const bool is_local = ((stream_id & 0x01u) == (is_server_ ? 1u : 0u));
      if (is_local) {
        const bool is_uni = (stream_id & 0x02u) != 0;
        const uint64_t opened_cnt =
            is_uni ? local_opened_uni_count_ : local_opened_bidi_count_;
        if ((stream_id >> 2) >= opened_cnt) {
          return;
        }
      } else if (!allow_unopened_peer_bidi &&
                 inbound_streams_.find(stream_id) == inbound_streams_.end() &&
                 !IsInboundStreamRetired(stream_id)) {
        return;
      }
    }
    auto& st = outbound_streams_[stream_id];
    st.stream_id = stream_id;
    if (st.reset) {
      return;
    }
    if (st.fin_sent && st.unsent_data.empty() && st.retransmit_chunks.empty() &&
        st.in_flight_frames == 0) {
      MaybeEraseCompletedOutboundStream(stream_id);
      return;
    }
    st.reset = true;
    st.reset_in_flight = true;
    st.unsent_data.clear();
    st.retransmit_chunks.clear();

    PendingReset rst;
    rst.stream_id = stream_id;
    rst.app_error_code = app_error_code;
    rst.final_size = st.next_send_offset;
    pending_resets_.push_back(rst);
  }

  void ResetStream(uint64_t stream_id, uint64_t app_error_code) {
    if (closed_) {
      return;
    }
    QueueResetStreamNoFlush(stream_id, app_error_code,
                            /*allow_unopened_peer_bidi=*/true);
    FlushPackets(clock_->CurrentTime(), false);
  }

  void StopSending(uint64_t stream_id, uint64_t app_error_code) {
    if (closed_ || !CanReceiveOnStream(stream_id) ||
        IsInboundStreamRetired(stream_id)) {
      return;
    }
    const bool is_local = ((stream_id & 0x01u) == (is_server_ ? 1u : 0u));
    if (is_local && (stream_id >> 2) >= local_opened_bidi_count_) {
      return;
    }
    auto& rx_buf = inbound_streams_[stream_id];
    rx_buf.ConfigureFlowControlWindow(InitialLocalReceiveStreamWindow(stream_id));
    if (rx_buf.is_stop_sending_requested()) {
      return;
    }
    // 遵循 RFC 9000 第 3.5 与 4.1 节：发送 STOP_SENDING 时保留接收流控跟踪并推进
    // conn_rx_consumed_total_，直到收到 FIN 或 RESET_STREAM(final_size) 后再退休该流，
    // 彻底杜绝连接级 MAX_DATA 死锁。
    if (rx_buf.highest_received_offset() > rx_buf.accounted_consumed_offset()) {
      conn_rx_consumed_total_ +=
          (rx_buf.highest_received_offset() -
           rx_buf.accounted_consumed_offset());
      rx_buf.set_accounted_consumed_offset(rx_buf.highest_received_offset());
      MaybeReplenishConnectionMaxData();
    }
    rx_buf.MarkStopSending();
    announced_inbound_streams_.insert(stream_id);
    pending_max_stream_data_sids_.erase(stream_id);

    if (rx_buf.has_pending_reset_at() || rx_buf.final_offset().has_value()) {
      const bool had_reset = rx_buf.has_pending_reset_at();
      const uint64_t rst_err = rx_buf.reset_app_error_code();
      RetireInboundStream(stream_id);
      if (had_reset) {
        events_->OnPeerStreamReset(stream_id, rst_err);
      }
      return;
    }

    PendingStopSending ss;
    ss.stream_id = stream_id;
    ss.app_error_code = app_error_code;
    pending_stop_sendings_.push_back(ss);
    FlushPackets(clock_->CurrentTime(), false);
  }

  int SendDatagram(ArrayView<const uint8_t> data) {
    if (closed_) {
      return RTC_ERR_NOT_CONNECTED;
    }
    const size_t max_payload = max_datagram_payload_size();
    if (max_payload == 0) {
      return RTC_ERR_PROTOCOL;
    }
    if (data.size() > max_payload) {
      return RTC_ERR_INVALID_ARG;
    }
    if (pending_datagrams_.size() >= 512) {
      pending_datagrams_.pop_front();
    }
    pending_datagrams_.emplace_back(data.begin(), data.end());
    FlushPackets(clock_->CurrentTime(), false);
    return RTC_OK;
  }

  size_t max_datagram_payload_size() const {
    const size_t short_hdr_and_frame_overhead =
        1 + peer_dcid_.size() + 4 + kQuicAeadTagLength + 4;
    if (handshake_established_ || peer_tp_received_) {
      if (peer_tp_.max_datagram_frame_size == 0) {
        return 0;
      }
      const size_t wire_cap =
          std::min(static_cast<size_t>(peer_tp_.max_datagram_frame_size),
                   kQuicMaxDatagramSize);
      return wire_cap > short_hdr_and_frame_overhead
                 ? (wire_cap - short_hdr_and_frame_overhead)
                 : 0;
    }
    return kQuicMaxDatagramSize - short_hdr_and_frame_overhead;
  }

  const std::string& negotiated_alpn() const { return negotiated_alpn_; }

  bool ProcessUdpDatagram(ArrayView<const uint8_t> datagram, Timestamp now) {
    if (closed_) {
      return false;
    }
    if (is_server_ && !peer_address_validated_) {
      pre_hs_rx_bytes_ += datagram.size();
    }
    bool authenticated_any = false;
    size_t offset = 0;
    while (offset < datagram.size()) {
      const ArrayView<const uint8_t> rem = datagram.subview(offset);
      bool is_long = false;
      QuicEncryptionLevel level = QuicEncryptionLevel::kOneRtt;
      QuicCid dcid{};
      QuicCid scid{};
      size_t pkt_len = 0;
      if (!QuicCryptoUtils::InspectHeaderIds(
              rem, &is_long, &level, &dcid, &scid, &pkt_len,
              local_scid_.size())) {
        break;
      }

      const bool valid_dcid =
          (is_server_ && level == QuicEncryptionLevel::kInitial)
              ? (dcid == local_scid_ || dcid == initial_dcid_)
              : (dcid == local_scid_);
      if (!valid_dcid || (is_long && peer_scid_learned_ && scid != peer_dcid_)) {
        offset += pkt_len;
        if (!is_long) {
          break;
        }
        continue;
      }

      // RFC 9001 第 4.1.2 节：服务端在完成 ClientFinished 校验前不得处理 1-RTT 数据包。
      if (is_server_ && level == QuicEncryptionLevel::kOneRtt &&
          !handshake_established_) {
        break;
      }

      const size_t lvl_idx = LevelIndex(level);
      if (!rx_keys_[lvl_idx].valid) {
        offset += pkt_len;
        if (!is_long) {
          break;
        }
        continue;
      }

      auto unprot = QuicCryptoUtils::UnprotectPacket(
          rem.subview(0, pkt_len), rx_keys_[lvl_idx],
          ack_sets_[lvl_idx].largest_received(), local_scid_.size());
      offset += pkt_len;
      if (!unprot.has_value()) {
        if (!is_long) {
          break;
        }
        continue;
      }

      authenticated_any = true;
      has_authenticated_rx_ = true;
      last_rx_time_ = now;

      // RFC 9000 第 17.2 与 17.3.1 节：移除头部保护并通过 AEAD 认证后校验保留位必须为 0。
      const uint8_t reserved_mask = is_long ? 0x0cu : 0x18u;
      if ((unprot->unmasked_first_byte & reserved_mask) != 0) {
        CloseTransportConnection(0x0au);
        events_->OnConnectionClosed(-105);
        return authenticated_any;
      }

      if (is_server_ && level == QuicEncryptionLevel::kHandshake) {
        peer_address_validated_ = true;
        if (rx_keys_[LevelIndex(QuicEncryptionLevel::kInitial)].valid) {
          // RFC 9001 第 4.9.1 节：服务端成功解密首个客户端 Handshake 包后立即丢弃 Initial 密钥空间。
          DiscardPacketSpace(QuicEncryptionLevel::kInitial);
        }
      }

      if ((level == QuicEncryptionLevel::kOneRtt &&
           unprot->packet_number < ack_sets_[lvl_idx].min_acceptable_pn()) ||
          ack_sets_[lvl_idx].Contains(unprot->packet_number)) {
        if (!is_long) {
          break;
        }
        continue;
      }

      if (!is_server_ && is_long && !peer_scid_learned_) {
        peer_dcid_ = unprot->scid;
        peer_cids_[0] = peer_dcid_;
        peer_scid_learned_ = true;
      } else if (is_server_ && level == QuicEncryptionLevel::kInitial &&
                 !peer_scid_learned_) {
        peer_dcid_ = unprot->scid;
        peer_cids_[0] = peer_dcid_;
        peer_scid_learned_ = true;
      }

      bool ack_eliciting = false;
      bool non_probing = false;
      if (ProcessFrames(level, unprot->plaintext, now, &ack_eliciting,
                        &non_probing)) {
        if (rx_keys_[lvl_idx].valid) {
          ack_sets_[lvl_idx].RecordReceived(unprot->packet_number,
                                            ack_eliciting);
          last_rx_pn_time_[lvl_idx] = now;
        }
        if (level == QuicEncryptionLevel::kOneRtt && non_probing &&
            (!has_highest_1rtt_pn_ ||
             unprot->packet_number >= highest_1rtt_pn_)) {
          has_highest_1rtt_pn_ = true;
          highest_1rtt_pn_ = unprot->packet_number;
          events_->OnHighestOneRttNonProbingPacket();
        }
      }

      if (!is_long || closed_) {
        break;
      }
    }

    if (!closed_ && authenticated_any) {
      FlushPackets(now, false);
    }
    return authenticated_any;
  }

  void OnPeriodicTimer(Timestamp now) {
    if (closed_) {
      return;
    }

    // RFC 9000 第 10.1 节：有效空闲超时取本地与对端非零声明值的最小值，且不低于 3 * PTO。
    const TimeDelta idle_timeout = EffectiveIdleTimeout();
    if (idle_timeout > TimeDelta::Zero() && last_rx_time_.IsFinite() &&
        (now - last_rx_time_) > idle_timeout) {
      closed_ = true;
      events_->OnConnectionClosed(-110);
      return;
    }

    DetectLostPacketsAllSpaces(now);

    // RFC 9002 第 6.2 节：探测超时（PTO）处理。
    if (bytes_in_flight_ > 0 || !handshake_established_) {
      const TimeDelta pto = ComputePtoDuration();
      if (last_ack_eliciting_tx_time_.IsFinite() &&
          (now - last_ack_eliciting_tx_time_) >= pto) {
        ++pto_count_;
        // RFC 9002 第 7.6.2 节：未获得首个 RTT 样本前严禁宣告持续拥塞。
        if (pto_count_ >= 3 && has_rtt_sample_ && cc_) {
          cc_->OnPersistentCongestion(now.us());
        }
        last_ack_eliciting_tx_time_ = now;
        RequeueOldestInFlightForPto();
        FlushPackets(now, true);
        return;
      }
    }

    FlushPackets(now, false);
  }

  void HotSwapCongestionController(
      std::unique_ptr<IQuicCongestionController> next_cc,
      Timestamp now) {
    if (!next_cc) {
      return;
    }
    if (cc_) {
      QuicCcMigrationState mig = cc_->ExportMigrationState();
      mig.bytes_in_flight = bytes_in_flight_;
      mig.delivered_bytes = conn_delivered_bytes_;
      if (mig.smoothed_rtt_us <= 0) {
        mig.smoothed_rtt_us = smoothed_rtt_.us();
      }
      if (mig.min_rtt_us <= 0 && min_rtt_.IsFinite()) {
        mig.min_rtt_us = min_rtt_.us();
      }
      const std::string_view prev_name = cc_->Name();
      next_cc->ImportMigrationState(mig, now.us());
      RTC_LOG(kInfo) << "Hot-swapped QUIC congestion controller: " << prev_name
                     << " -> " << next_cc->Name()
                     << " (cwnd=" << next_cc->GetCongestionWindowBytes()
                     << "B, bwe_kbps="
                     << (next_cc->GetBandwidthEstimateBps() / 1000) << ")";
    }
    cc_ = std::move(next_cc);
  }

  QuicCongestionSnapshot GetCongestionSnapshot(Timestamp now) const {
    const size_t cur_cwnd =
        cc_ ? cc_->GetCongestionWindowBytes() : (10 * kQuicMaxDatagramSize);
    const int64_t pace_bps =
        cc_ ? cc_->GetPacingRateBps(smoothed_rtt_.us()) : 1'500'000;
    const int64_t bw_est_bps =
        cc_ ? cc_->GetBandwidthEstimateBps() : 1'500'000;

    size_t unsent_total = 0;
    for (const auto& [sid, st] : outbound_streams_) {
      (void)sid;
      if (st.reset) {
        continue;
      }
      unsent_total += st.unsent_data.size();
      for (const auto& rtx_chunk : st.retransmit_chunks) {
        unsent_total += rtx_chunk.data.size();
      }
    }

    QuicCongestionSnapshot snap;
    snap.timestamp = now;
    snap.smoothed_rtt = smoothed_rtt_;
    snap.min_rtt = min_rtt_.IsFinite() ? min_rtt_ : smoothed_rtt_;
    snap.cwnd = DataSize::Bytes(static_cast<int64_t>(cur_cwnd));
    snap.bytes_in_flight = DataSize::Bytes(static_cast<int64_t>(bytes_in_flight_));
    snap.unsent_stream_bytes =
        DataSize::Bytes(static_cast<int64_t>(unsent_total));
    snap.pacing_rate = DataRate::BitsPerSec(pace_bps);
    snap.delivery_rate = DataRate::BitsPerSec(delivery_rate_bps_);
    snap.cc_bandwidth_estimate = DataRate::BitsPerSec(bw_est_bps);
    snap.active_cc_name = cc_ ? cc_->Name() : "BBRv1";
    snap.recent_loss_ratio = recent_loss_ratio_;
    snap.packets_sent = total_packets_sent_;
    snap.packets_lost = total_packets_lost_;
    snap.packets_retransmitted = total_packets_retransmitted_;
    return snap;
  }

  bool is_closed() const { return closed_; }

 private:
  struct StreamChunk {
    uint64_t stream_id = 0;
    uint64_t offset = 0;
    std::vector<uint8_t> data;
    bool fin = false;
  };

  struct PendingReset {
    uint64_t stream_id = 0;
    uint64_t app_error_code = 0;
    uint64_t final_size = 0;
  };

  struct PendingStopSending {
    uint64_t stream_id = 0;
    uint64_t app_error_code = 0;
  };

  struct SentRetransmittable {
    enum class Kind : uint8_t {
      kCrypto,
      kStream,
      kResetStream,
      kStopSending,
      kHandshakeDone,
      kMaxData,
      kMaxStreamData,
      kMaxStreamsBidi,
      kMaxStreamsUni,
      kRetireConnectionId,
    };
    Kind kind = Kind::kStream;
    bool is_retransmit = false;
    QuicEncryptionLevel crypto_level = QuicEncryptionLevel::kInitial;
    uint64_t offset = 0;
    uint64_t ctrl_stream_id = 0;
    uint64_t ctrl_value = 0;
    std::vector<uint8_t> data;
    StreamChunk stream_chunk;
    PendingReset reset_info;
    PendingStopSending stop_sending_info;
  };

  struct SentPacketInfo {
    uint64_t pn = 0;
    uint64_t cc_seq = 0;
    Timestamp sent_time = Timestamp::MinusInfinity();
    size_t sent_bytes = 0;
    size_t prior_in_flight_bytes = 0;
    uint64_t delivered_bytes_at_send = 0;
    int64_t delivered_time_us_at_send = 0;
    int64_t first_sent_time_us_at_send = 0;
    bool is_app_limited = false;
    bool ack_eliciting = false;
    bool in_flight = false;
    std::vector<SentRetransmittable> frames;
  };

  struct OutboundStreamState {
    uint64_t stream_id = 0;
    uint8_t priority = 64;
    int64_t send_order = 0;
    uint64_t next_send_offset = 0;
    uint64_t peer_max_stream_data = 0;
    bool flow_limit_initialized = false;
    std::vector<uint8_t> unsent_data;
    bool fin_queued = false;
    bool fin_sent = false;
    bool reset = false;
    bool reset_in_flight = false;
    size_t in_flight_frames = 0;
    std::deque<StreamChunk> retransmit_chunks;
  };

  uint64_t InitialLocalReceiveStreamWindow(uint64_t stream_id) const {
    const bool is_peer_initiated =
        ((stream_id & 0x01u) == (is_server_ ? 0u : 1u));
    const bool is_uni = (stream_id & 0x02u) != 0;
    if (is_uni) {
      return local_tp_.initial_max_stream_data_uni;
    }
    return is_peer_initiated ? local_tp_.initial_max_stream_data_bidi_remote
                             : local_tp_.initial_max_stream_data_bidi_local;
  }

  uint64_t InitialPeerStreamMaxData(uint64_t stream_id) const {
    const bool is_local_initiated =
        ((stream_id & 0x01u) == (is_server_ ? 1u : 0u));
    const bool is_uni = (stream_id & 0x02u) != 0;
    if (is_uni) {
      return peer_tp_.initial_max_stream_data_uni;
    }
    return is_local_initiated ? peer_tp_.initial_max_stream_data_bidi_remote
                              : peer_tp_.initial_max_stream_data_bidi_local;
  }

  void ApplyPeerTransportParameters(const QuicTransportParameters& tp) {
    peer_tp_ = tp;
    peer_tp_received_ = true;
    peer_max_data_ = tp.initial_max_data;
    peer_max_streams_bidi_ = tp.initial_max_streams_bidi;
    peer_max_streams_uni_ = tp.initial_max_streams_uni;
    for (auto& [sid, st] : outbound_streams_) {
      st.peer_max_stream_data = InitialPeerStreamMaxData(sid);
      st.flow_limit_initialized = true;
    }
  }

  TimeDelta EffectiveIdleTimeout() const {
    uint64_t eff_ms = local_tp_.max_idle_timeout_ms;
    if (peer_tp_received_) {
      if (eff_ms == 0) {
        eff_ms = peer_tp_.max_idle_timeout_ms;
      } else if (peer_tp_.max_idle_timeout_ms > 0) {
        eff_ms = std::min(eff_ms, peer_tp_.max_idle_timeout_ms);
      }
    }
    if (eff_ms == 0) {
      return TimeDelta::Zero();
    }
    eff_ms = std::min<uint64_t>(eff_ms, 600'000ULL);
    return std::max(TimeDelta::Millis(static_cast<int64_t>(eff_ms)),
                    ComputePtoDuration() * 3);
  }

  void MaybeReplenishConnectionMaxData() {
    const uint64_t win = local_tp_.initial_max_data;
    if (win > 0 && local_max_data_ >= conn_rx_consumed_total_ &&
        (local_max_data_ - conn_rx_consumed_total_) <= win / 2) {
      local_max_data_ = conn_rx_consumed_total_ + win;
      pending_max_data_ = true;
    }
  }

  bool IsInboundStreamRetired(uint64_t stream_id) const {
    if (retired_inbound_streams_.count(stream_id) > 0) {
      return true;
    }
    if (inbound_streams_.find(stream_id) != inbound_streams_.end()) {
      return false;
    }
    const bool is_peer_initiated =
        ((stream_id & 0x01u) == (is_server_ ? 0u : 1u));
    const bool is_uni = (stream_id & 0x02u) != 0;
    if (is_peer_initiated) {
      const int64_t watermark =
          is_uni ? max_retired_peer_uni_sid_ : max_retired_peer_bidi_sid_;
      return static_cast<int64_t>(stream_id) <= watermark;
    }
    return !is_uni &&
           static_cast<int64_t>(stream_id) <= max_retired_local_bidi_sid_;
  }

  void RecordInboundEvictedWatermark(uint64_t evicted_sid) {
    const bool is_peer_initiated =
        ((evicted_sid & 0x01u) == (is_server_ ? 0u : 1u));
    const bool is_uni = (evicted_sid & 0x02u) != 0;
    const int64_t sid_i64 = static_cast<int64_t>(evicted_sid);
    if (is_peer_initiated) {
      if (is_uni) {
        max_retired_peer_uni_sid_ = std::max(max_retired_peer_uni_sid_, sid_i64);
      } else {
        max_retired_peer_bidi_sid_ =
            std::max(max_retired_peer_bidi_sid_, sid_i64);
      }
    } else if (!is_uni) {
      max_retired_local_bidi_sid_ =
          std::max(max_retired_local_bidi_sid_, sid_i64);
    }
  }

  void RetireInboundStream(uint64_t stream_id) {
    bool was_active_or_new = false;
    const auto in_it = inbound_streams_.find(stream_id);
    if (in_it != inbound_streams_.end()) {
      was_active_or_new = true;
      if (in_it->second.highest_received_offset() >
          in_it->second.accounted_consumed_offset()) {
        conn_rx_consumed_total_ +=
            (in_it->second.highest_received_offset() -
             in_it->second.accounted_consumed_offset());
      }
      inbound_streams_.erase(in_it);
      MaybeReplenishConnectionMaxData();
    }
    if (announced_inbound_streams_.erase(stream_id) > 0) {
      was_active_or_new = true;
    }
    pending_max_stream_data_sids_.erase(stream_id);

    const bool newly_retired =
        !IsInboundStreamRetired(stream_id) &&
        retired_inbound_streams_.insert(stream_id).second;
    if (newly_retired) {
      retired_inbound_order_.push_back(stream_id);
      while (retired_inbound_order_.size() > 2048) {
        const uint64_t evicted = retired_inbound_order_.front();
        retired_inbound_streams_.erase(evicted);
        retired_inbound_order_.pop_front();
        RecordInboundEvictedWatermark(evicted);
      }
    }

    const bool is_peer_initiated =
        ((stream_id & 0x01u) == (is_server_ ? 0u : 1u));
    if (is_peer_initiated && (was_active_or_new || newly_retired)) {
      const bool is_uni = (stream_id & 0x02u) != 0;
      if (is_uni) {
        ++retired_peer_uni_streams_;
        const uint64_t desired =
            retired_peer_uni_streams_ + local_tp_.initial_max_streams_uni;
        if (desired > local_max_streams_uni_ &&
            (desired - local_max_streams_uni_) >=
                std::max<uint64_t>(1, local_tp_.initial_max_streams_uni / 2)) {
          local_max_streams_uni_ = desired;
          pending_max_streams_uni_ = true;
        }
      } else {
        ++retired_peer_bidi_streams_;
        const uint64_t desired =
            retired_peer_bidi_streams_ + local_tp_.initial_max_streams_bidi;
        if (desired > local_max_streams_bidi_ &&
            (desired - local_max_streams_bidi_) >=
                std::max<uint64_t>(1, local_tp_.initial_max_streams_bidi / 2)) {
          local_max_streams_bidi_ = desired;
          pending_max_streams_bidi_ = true;
        }
      }
    }
  }

  bool IsOutboundStreamRetired(uint64_t stream_id) const {
    if (retired_outbound_streams_.count(stream_id) > 0) {
      return true;
    }
    if (outbound_streams_.find(stream_id) != outbound_streams_.end()) {
      return false;
    }
    const bool is_local = ((stream_id & 0x01u) == (is_server_ ? 1u : 0u));
    const bool is_uni = (stream_id & 0x02u) != 0;
    if (is_local) {
      const int64_t watermark = is_uni ? max_retired_outbound_local_uni_sid_
                                       : max_retired_outbound_local_bidi_sid_;
      return static_cast<int64_t>(stream_id) <= watermark;
    }
    return !is_uni &&
           static_cast<int64_t>(stream_id) <= max_retired_outbound_peer_bidi_sid_;
  }

  void RecordOutboundRetired(uint64_t stream_id) {
    if (retired_outbound_streams_.insert(stream_id).second) {
      retired_outbound_order_.push_back(stream_id);
      while (retired_outbound_order_.size() > 2048) {
        const uint64_t evicted = retired_outbound_order_.front();
        retired_outbound_streams_.erase(evicted);
        retired_outbound_order_.pop_front();
        const bool is_local = ((evicted & 0x01u) == (is_server_ ? 1u : 0u));
        const bool is_uni = (evicted & 0x02u) != 0;
        const int64_t sid_i64 = static_cast<int64_t>(evicted);
        if (is_local) {
          if (is_uni) {
            max_retired_outbound_local_uni_sid_ =
                std::max(max_retired_outbound_local_uni_sid_, sid_i64);
          } else {
            max_retired_outbound_local_bidi_sid_ =
                std::max(max_retired_outbound_local_bidi_sid_, sid_i64);
          }
        } else if (!is_uni) {
          max_retired_outbound_peer_bidi_sid_ =
              std::max(max_retired_outbound_peer_bidi_sid_, sid_i64);
        }
      }
    }
  }

  void MaybeEraseCompletedOutboundStream(uint64_t stream_id) {
    const auto it = outbound_streams_.find(stream_id);
    if (it == outbound_streams_.end()) {
      return;
    }
    const OutboundStreamState& st = it->second;
    const bool fin_complete =
        st.fin_sent && st.unsent_data.empty() && st.retransmit_chunks.empty() &&
        st.in_flight_frames == 0;
    const bool reset_complete =
        st.reset && !st.reset_in_flight && st.in_flight_frames == 0;
    if (fin_complete || reset_complete) {
      outbound_streams_.erase(it);
      RecordOutboundRetired(stream_id);
    }
  }

  // ---------------- 标准 RFC 8446 TLS 1.3 握手消息构造与解析 ----------------

  std::vector<uint8_t> BuildClientHello() const {
    std::vector<uint8_t> exts;
    exts.reserve(256);

    // 1. SNI 扩展（0x0000）：仅对非 IP 字面量的域名填充。
    if (!client_sni_host_.empty()) {
      boost::system::error_code ip_ec;
      boost::asio::ip::make_address(client_sni_host_, ip_ec);
      if (ip_ec && client_sni_host_.size() <= 255) {
        std::vector<uint8_t> sni;
        AppendUint16BE(static_cast<uint16_t>(3 + client_sni_host_.size()), &sni);
        sni.push_back(0x00);
        AppendUint16BE(static_cast<uint16_t>(client_sni_host_.size()), &sni);
        sni.insert(sni.end(), client_sni_host_.begin(), client_sni_host_.end());
        AppendTlsExt(kTlsExtServerName, sni, &exts);
      }
    }

    // 2. 支持的协议版本扩展 supported_versions (0x002b) = [TLS 1.3 (0x0304)]
    const uint8_t sv_ext[] = {0x02, 0x03, 0x04};
    AppendTlsExt(kTlsExtSupportedVersions, sv_ext, &exts);

    // 3. 支持的椭圆曲线组扩展 supported_groups (0x000a) = [x25519 (0x001d)]
    const uint8_t sg_ext[] = {0x00, 0x02, 0x00, 0x1d};
    AppendTlsExt(kTlsExtSupportedGroups, sg_ext, &exts);

    // 4. 签名算法扩展 signature_algorithms (0x000d) = [ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256]
    const uint8_t sig_ext[] = {0x00, 0x04, 0x04, 0x03, 0x08, 0x04};
    AppendTlsExt(kTlsExtSignatureAlgorithms, sig_ext, &exts);

    // 5. 预共享密钥交换模式扩展 psk_key_exchange_modes (0x002d) = [psk_dhe_ke (0x01)]
    const uint8_t psk_ext[] = {0x01, 0x01};
    AppendTlsExt(kTlsExtPskKeyExchangeModes, psk_ext, &exts);

    // 6. ALPN 扩展（0x0010）
    if (!supported_alpns_.empty()) {
      std::vector<uint8_t> alpn_list;
      for (const auto& proto : supported_alpns_) {
        if (!proto.empty() && proto.size() <= 255) {
          alpn_list.push_back(static_cast<uint8_t>(proto.size()));
          alpn_list.insert(alpn_list.end(), proto.begin(), proto.end());
        }
      }
      if (!alpn_list.empty()) {
        std::vector<uint8_t> alpn_ext;
        AppendUint16BE(static_cast<uint16_t>(alpn_list.size()), &alpn_ext);
        alpn_ext.insert(alpn_ext.end(), alpn_list.begin(), alpn_list.end());
        AppendTlsExt(kTlsExtAlpn, alpn_ext, &exts);
      }
    }

    // 7. key_share 扩展（0x0033）：x25519 32 字节公钥
    std::vector<uint8_t> ks_ext;
    AppendUint16BE(36, &ks_ext);
    AppendUint16BE(kTlsGroupX25519, &ks_ext);
    AppendUint16BE(32, &ks_ext);
    ks_ext.insert(ks_ext.end(), local_x25519_pub_.begin(),
                  local_x25519_pub_.end());
    AppendTlsExt(kTlsExtKeyShare, ks_ext, &exts);

    // 8. quic_transport_parameters 扩展（0x0039）
    const auto tp_bytes = local_tp_.Encode();
    AppendTlsExt(kTlsExtQuicTransportParams, tp_bytes, &exts);

    std::vector<uint8_t> body;
    body.reserve(64 + exts.size());
    AppendUint16BE(0x0303u, &body);  // 兼容层版本号 legacy_version = TLS 1.2
    body.insert(body.end(), local_random_.begin(), local_random_.end());
    body.push_back(0x00);            // legacy_session_id 长度 = 0
    AppendUint16BE(2, &body);        // cipher_suites 字节长度 = 2
    AppendUint16BE(kTlsCipherAes128GcmSha256, &body);
    body.push_back(0x01);            // legacy_compression_methods 长度 = 1
    body.push_back(0x00);            // null 压缩
    AppendUint16BE(static_cast<uint16_t>(exts.size()), &body);
    body.insert(body.end(), exts.begin(), exts.end());
    return WrapTlsHandshakeMsg(kTlsHsClientHello, body);
  }

  std::vector<uint8_t> BuildServerHello(
      ArrayView<const uint8_t> legacy_session_id_echo,
      uint16_t selected_group,
      ArrayView<const uint8_t> server_key_share) const {
    std::vector<uint8_t> exts;
    const uint8_t sv_val[] = {0x03, 0x04};
    AppendTlsExt(kTlsExtSupportedVersions, sv_val, &exts);

    std::vector<uint8_t> ks_val;
    AppendUint16BE(selected_group, &ks_val);
    AppendUint16BE(static_cast<uint16_t>(server_key_share.size()), &ks_val);
    ks_val.insert(ks_val.end(), server_key_share.begin(),
                  server_key_share.end());
    AppendTlsExt(kTlsExtKeyShare, ks_val, &exts);

    std::vector<uint8_t> body;
    body.reserve(48 + legacy_session_id_echo.size() + exts.size());
    AppendUint16BE(0x0303u, &body);
    body.insert(body.end(), local_random_.begin(), local_random_.end());
    body.push_back(static_cast<uint8_t>(legacy_session_id_echo.size()));
    body.insert(body.end(), legacy_session_id_echo.begin(),
                legacy_session_id_echo.end());
    AppendUint16BE(kTlsCipherAes128GcmSha256, &body);
    body.push_back(0x00);
    AppendUint16BE(static_cast<uint16_t>(exts.size()), &body);
    body.insert(body.end(), exts.begin(), exts.end());
    return WrapTlsHandshakeMsg(kTlsHsServerHello, body);
  }

  std::vector<uint8_t> BuildServerEncryptedExtensions(
      bool include_alpn) const {
    std::vector<uint8_t> exts;
    if (include_alpn && !negotiated_alpn_.empty() &&
        negotiated_alpn_.size() <= 255) {
      std::vector<uint8_t> alpn_ext;
      AppendUint16BE(static_cast<uint16_t>(1 + negotiated_alpn_.size()),
                     &alpn_ext);
      alpn_ext.push_back(static_cast<uint8_t>(negotiated_alpn_.size()));
      alpn_ext.insert(alpn_ext.end(), negotiated_alpn_.begin(),
                      negotiated_alpn_.end());
      AppendTlsExt(kTlsExtAlpn, alpn_ext, &exts);
    }
    const auto tp_bytes = local_tp_.Encode();
    AppendTlsExt(kTlsExtQuicTransportParams, tp_bytes, &exts);

    std::vector<uint8_t> body;
    AppendUint16BE(static_cast<uint16_t>(exts.size()), &body);
    body.insert(body.end(), exts.begin(), exts.end());
    return WrapTlsHandshakeMsg(kTlsHsEncryptedExtensions, body);
  }

  std::vector<uint8_t> BuildServerCertificateMsg() const {
    const auto& cert_der = server_cert_->der_bytes();
    std::vector<uint8_t> entry;
    entry.reserve(5 + cert_der.size());
    AppendUint24BE(cert_der.size(), &entry);
    entry.insert(entry.end(), cert_der.begin(), cert_der.end());
    AppendUint16BE(0, &entry);  // 证书条目级扩展为空

    std::vector<uint8_t> body;
    body.reserve(4 + entry.size());
    body.push_back(0x00);  // certificate_request_context 长度 = 0
    AppendUint24BE(entry.size(), &body);
    body.insert(body.end(), entry.begin(), entry.end());
    return WrapTlsHandshakeMsg(kTlsHsCertificate, body);
  }

  bool DeriveTls13HandshakeKeys(const std::array<uint8_t, 32>& ecdhe_shared,
                                ArrayView<const uint8_t> hello_transcript) {
    const std::array<uint8_t, 32> zeros{};
    const auto empty_hash =
        QuicCryptoUtils::Sha256(ArrayView<const uint8_t>());
    std::array<uint8_t, 32> early_secret{};
    std::array<uint8_t, 32> derived_early{};
    if (!QuicCryptoUtils::HkdfExtract(zeros, zeros, &early_secret) ||
        !QuicCryptoUtils::HkdfExpandLabel(early_secret, "derived", empty_hash,
                                          derived_early.data(),
                                          derived_early.size()) ||
        !QuicCryptoUtils::HkdfExtract(derived_early, ecdhe_shared,
                                      &handshake_root_secret_)) {
      return false;
    }

    const auto hello_hash = QuicCryptoUtils::Sha256(hello_transcript);
    std::array<uint8_t, 32> c_hs{};
    std::array<uint8_t, 32> s_hs{};
    if (!QuicCryptoUtils::HkdfExpandLabel(handshake_root_secret_, "c hs traffic",
                                          hello_hash, c_hs.data(),
                                          c_hs.size()) ||
        !QuicCryptoUtils::HkdfExpandLabel(handshake_root_secret_, "s hs traffic",
                                          hello_hash, s_hs.data(),
                                          s_hs.size())) {
      return false;
    }
    QuicTrafficKeys client_hs;
    QuicTrafficKeys server_hs;
    if (!QuicCryptoUtils::DeriveTrafficKeysFromSecret(c_hs, &client_hs) ||
        !QuicCryptoUtils::DeriveTrafficKeysFromSecret(s_hs, &server_hs)) {
      return false;
    }
    if (is_server_) {
      rx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)] = client_hs;
      tx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)] = server_hs;
    } else {
      tx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)] = client_hs;
      rx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)] = server_hs;
    }
    return true;
  }

  bool DeriveApplicationSecrets(
      ArrayView<const uint8_t> full_server_transcript) {
    const std::array<uint8_t, 32> zeros{};
    const auto empty_hash =
        QuicCryptoUtils::Sha256(ArrayView<const uint8_t>());
    std::array<uint8_t, 32> derived_hs{};
    std::array<uint8_t, 32> master_root{};
    if (!QuicCryptoUtils::HkdfExpandLabel(
            handshake_root_secret_, "derived", empty_hash, derived_hs.data(),
            derived_hs.size()) ||
        !QuicCryptoUtils::HkdfExtract(derived_hs, zeros, &master_root)) {
      return false;
    }
    const auto hs_hash = QuicCryptoUtils::Sha256(full_server_transcript);
    std::array<uint8_t, 32> c_ap{};
    std::array<uint8_t, 32> s_ap{};
    if (!QuicCryptoUtils::HkdfExpandLabel(master_root, "c ap traffic", hs_hash,
                                          c_ap.data(), c_ap.size()) ||
        !QuicCryptoUtils::HkdfExpandLabel(master_root, "s ap traffic", hs_hash,
                                          s_ap.data(), s_ap.size())) {
      return false;
    }
    QuicTrafficKeys client_ap;
    QuicTrafficKeys server_ap;
    if (!QuicCryptoUtils::DeriveTrafficKeysFromSecret(c_ap, &client_ap) ||
        !QuicCryptoUtils::DeriveTrafficKeysFromSecret(s_ap, &server_ap)) {
      return false;
    }
    if (is_server_) {
      rx_keys_[LevelIndex(QuicEncryptionLevel::kOneRtt)] = client_ap;
      tx_keys_[LevelIndex(QuicEncryptionLevel::kOneRtt)] = server_ap;
    } else {
      tx_keys_[LevelIndex(QuicEncryptionLevel::kOneRtt)] = client_ap;
      rx_keys_[LevelIndex(QuicEncryptionLevel::kOneRtt)] = server_ap;
    }
    return true;
  }

  void QueueCryptoData(QuicEncryptionLevel level,
                       ArrayView<const uint8_t> bytes) {
    const size_t idx = LevelIndex(level);
    SentRetransmittable item;
    item.kind = SentRetransmittable::Kind::kCrypto;
    item.crypto_level = level;
    item.offset = crypto_tx_offset_[idx];
    item.data.assign(bytes.begin(), bytes.end());
    crypto_tx_offset_[idx] += bytes.size();
    crypto_tx_queue_[idx].push_back(std::move(item));
  }

  bool HandleServerClientHello(ArrayView<const uint8_t> raw_msg,
                               ArrayView<const uint8_t> body) {
    if (body.size() < 42) {
      return false;
    }
    size_t off = 2 + 32;  // 跳过 legacy_version(2) 与 random(32)
    const uint8_t sid_len = body[off++];
    if (sid_len > 32 || off + sid_len + 2 > body.size()) {
      return false;
    }
    const ArrayView<const uint8_t> legacy_sid = body.subview(off, sid_len);
    off += sid_len;

    const uint16_t cs_len = ReadBigEndian16(body.data() + off);
    off += 2;
    if ((cs_len % 2) != 0 || off + cs_len + 1 > body.size()) {
      return false;
    }
    bool supports_aes128_gcm = false;
    for (size_t i = 0; i < cs_len; i += 2) {
      if (ReadBigEndian16(body.data() + off + i) == kTlsCipherAes128GcmSha256) {
        supports_aes128_gcm = true;
      }
    }
    off += cs_len;
    if (!supports_aes128_gcm) {
      return false;
    }

    const uint8_t comp_len = body[off++];
    if (off + comp_len + 2 > body.size()) {
      return false;
    }
    off += comp_len;

    const uint16_t exts_len = ReadBigEndian16(body.data() + off);
    off += 2;
    if (off + exts_len > body.size()) {
      return false;
    }

    const size_t exts_end = off + exts_len;
    bool saw_alpn_ext = false;
    bool saw_tp_ext = false;
    std::vector<std::string> client_alpns;
    std::optional<QuicTransportParameters> parsed_tp;
    std::optional<std::array<uint8_t, 32>> peer_x25519;
    std::vector<uint8_t> peer_p256;

    while (off + 4 <= exts_end) {
      const uint16_t ext_type = ReadBigEndian16(body.data() + off);
      const uint16_t ext_len = ReadBigEndian16(body.data() + off + 2);
      off += 4;
      if (off + ext_len > exts_end) {
        return false;
      }
      const ArrayView<const uint8_t> edata = body.subview(off, ext_len);
      off += ext_len;

      if (ext_type == kTlsExtAlpn) {
        if (saw_alpn_ext || edata.size() < 3) {
          return false;
        }
        const uint16_t list_len = ReadBigEndian16(edata.data());
        if (2u + list_len != edata.size()) {
          return false;
        }
        saw_alpn_ext = true;
        size_t aoff = 2;
        while (aoff < 2u + list_len) {
          const uint8_t plen = edata[aoff++];
          if (plen == 0 || aoff + plen > 2u + list_len) {
            return false;
          }
          client_alpns.emplace_back(
              reinterpret_cast<const char*>(edata.data() + aoff), plen);
          aoff += plen;
        }
      } else if (ext_type == kTlsExtKeyShare && edata.size() >= 2) {
        const uint16_t ks_len = ReadBigEndian16(edata.data());
        if (2u + ks_len <= edata.size()) {
          size_t koff = 2;
          while (koff + 4 <= 2u + ks_len) {
            const uint16_t grp = ReadBigEndian16(edata.data() + koff);
            const uint16_t klen = ReadBigEndian16(edata.data() + koff + 2);
            koff += 4;
            if (koff + klen > 2u + ks_len) {
              break;
            }
            if (grp == kTlsGroupX25519 && klen == 32 &&
                !peer_x25519.has_value()) {
              std::array<uint8_t, 32> pub{};
              std::memcpy(pub.data(), edata.data() + koff, 32);
              peer_x25519 = pub;
            } else if (grp == kTlsGroupSecp256r1 && klen == 65 &&
                       peer_p256.empty()) {
              peer_p256.assign(edata.data() + koff, edata.data() + koff + 65);
            }
            koff += klen;
          }
        }
      } else if (ext_type == kTlsExtQuicTransportParams) {
        if (saw_tp_ext) {
          CloseTransportConnection(0x08u);
          events_->OnConnectionClosed(-106);
          return false;
        }
        saw_tp_ext = true;
        parsed_tp = QuicTransportParameters::Decode(edata);
      }
    }

    if (!saw_tp_ext) {
      CloseTransportConnection(0x016du);
      events_->OnConnectionClosed(-106);
      return false;
    }
    if (!parsed_tp.has_value() || parsed_tp->has_original_destination_cid ||
        (parsed_tp->has_initial_source_cid &&
         parsed_tp->initial_source_cid != peer_dcid_)) {
      CloseTransportConnection(0x08u);  // TRANSPORT_PARAMETER_ERROR
      events_->OnConnectionClosed(-106);
      return false;
    }
    if (!server_cert_) {
      return false;
    }

    std::string chosen_alpn;
    if (supported_alpns_.empty()) {
      if (!client_alpns.empty()) {
        chosen_alpn = client_alpns.front();
      }
    } else {
      for (const auto& offer : client_alpns) {
        if (std::find(supported_alpns_.begin(), supported_alpns_.end(),
                      offer) != supported_alpns_.end()) {
          chosen_alpn = offer;
          break;
        }
      }
      if (chosen_alpn.empty()) {
        RTC_LOG(kWarning) << "QUIC ALPN negotiation failed";
        CloseTransportConnection(0x0178u);
        events_->OnConnectionClosed(-120);
        return false;
      }
    }

    uint16_t selected_group = 0;
    std::vector<uint8_t> server_key_share;
    std::array<uint8_t, 32> ecdhe_shared{};
    if (peer_x25519.has_value()) {
      if (!QuicCryptoUtils::ComputeX25519SharedSecret(
              local_x25519_priv_, *peer_x25519, &ecdhe_shared)) {
        return false;
      }
      selected_group = kTlsGroupX25519;
      server_key_share.assign(local_x25519_pub_.begin(),
                              local_x25519_pub_.end());
    } else if (!peer_p256.empty()) {
      if (!ComputeServerP256KeyExchange(peer_p256, &server_key_share,
                                        &ecdhe_shared)) {
        return false;
      }
      selected_group = kTlsGroupSecp256r1;
    } else {
      return false;
    }

    negotiated_alpn_ = chosen_alpn;
    ApplyPeerTransportParameters(*parsed_tp);
    client_hello_bytes_.assign(raw_msg.begin(), raw_msg.end());
    server_hello_bytes_ =
        BuildServerHello(legacy_sid, selected_group, server_key_share);

    full_hs_transcript_ = client_hello_bytes_;
    full_hs_transcript_.insert(full_hs_transcript_.end(),
                               server_hello_bytes_.begin(),
                               server_hello_bytes_.end());
    if (!DeriveTls13HandshakeKeys(ecdhe_shared, full_hs_transcript_)) {
      return false;
    }

    const auto ee_msg = BuildServerEncryptedExtensions(saw_alpn_ext);
    const auto cert_msg = BuildServerCertificateMsg();
    full_hs_transcript_.insert(full_hs_transcript_.end(), ee_msg.begin(),
                               ee_msg.end());
    full_hs_transcript_.insert(full_hs_transcript_.end(), cert_msg.begin(),
                               cert_msg.end());

    const auto cert_thash = QuicCryptoUtils::Sha256(full_hs_transcript_);
    std::vector<uint8_t> cv_sig;
    if (!server_cert_->SignServerCertVerify(cert_thash, &cv_sig)) {
      return false;
    }
    std::vector<uint8_t> cv_body;
    cv_body.reserve(4 + cv_sig.size());
    AppendUint16BE(kTlsSigEcdsaSecp256r1Sha256, &cv_body);
    AppendUint16BE(static_cast<uint16_t>(cv_sig.size()), &cv_body);
    cv_body.insert(cv_body.end(), cv_sig.begin(), cv_sig.end());
    const auto cv_msg = WrapTlsHandshakeMsg(kTlsHsCertificateVerify, cv_body);
    full_hs_transcript_.insert(full_hs_transcript_.end(), cv_msg.begin(),
                               cv_msg.end());

    const auto cv_thash = QuicCryptoUtils::Sha256(full_hs_transcript_);
    std::array<uint8_t, 32> s_fin_key{};
    QuicCryptoUtils::HkdfExpandLabel(
        tx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].secret,
        "finished", ArrayView<const uint8_t>(), s_fin_key.data(),
        s_fin_key.size());
    std::array<uint8_t, 32> s_verify{};
    QuicCryptoUtils::HmacSha256(s_fin_key, cv_thash, &s_verify);
    const auto sfin_msg = WrapTlsHandshakeMsg(kTlsHsFinished, s_verify);
    full_hs_transcript_.insert(full_hs_transcript_.end(), sfin_msg.begin(),
                               sfin_msg.end());

    if (!DeriveApplicationSecrets(full_hs_transcript_)) {
      return false;
    }

    std::vector<uint8_t> hs_flight;
    hs_flight.reserve(ee_msg.size() + cert_msg.size() + cv_msg.size() +
                      sfin_msg.size());
    hs_flight.insert(hs_flight.end(), ee_msg.begin(), ee_msg.end());
    hs_flight.insert(hs_flight.end(), cert_msg.begin(), cert_msg.end());
    hs_flight.insert(hs_flight.end(), cv_msg.begin(), cv_msg.end());
    hs_flight.insert(hs_flight.end(), sfin_msg.begin(), sfin_msg.end());

    server_hello_sent_ = true;
    QueueCryptoData(QuicEncryptionLevel::kInitial, server_hello_bytes_);
    QueueCryptoData(QuicEncryptionLevel::kHandshake, hs_flight);
    return true;
  }

  bool HandleClientServerHello(ArrayView<const uint8_t> raw_msg,
                               ArrayView<const uint8_t> body) {
    if (body.size() < 38) {
      return false;
    }
    size_t off = 2 + 32;  // 跳过 legacy_version(2) 与 random(32)
    const uint8_t sid_len = body[off++];
    if (sid_len > 32 || off + sid_len + 3 + 2 > body.size()) {
      return false;
    }
    off += sid_len;
    const uint16_t cipher = ReadBigEndian16(body.data() + off);
    off += 2;
    const uint8_t comp = body[off++];
    if (cipher != kTlsCipherAes128GcmSha256 || comp != 0x00) {
      return false;
    }

    const uint16_t exts_len = ReadBigEndian16(body.data() + off);
    off += 2;
    if (off + exts_len > body.size()) {
      return false;
    }
    const size_t exts_end = off + exts_len;
    std::optional<std::array<uint8_t, 32>> server_x25519;
    while (off + 4 <= exts_end) {
      const uint16_t etype = ReadBigEndian16(body.data() + off);
      const uint16_t elen = ReadBigEndian16(body.data() + off + 2);
      off += 4;
      if (off + elen > exts_end) {
        return false;
      }
      const ArrayView<const uint8_t> edata = body.subview(off, elen);
      off += elen;
      if (etype == kTlsExtKeyShare && edata.size() == 36) {
        const uint16_t grp = ReadBigEndian16(edata.data());
        const uint16_t klen = ReadBigEndian16(edata.data() + 2);
        if (grp == kTlsGroupX25519 && klen == 32) {
          std::array<uint8_t, 32> pub{};
          std::memcpy(pub.data(), edata.data() + 4, 32);
          server_x25519 = pub;
        }
      }
    }
    if (!server_x25519.has_value()) {
      return false;
    }
    std::array<uint8_t, 32> ecdhe_shared{};
    if (!QuicCryptoUtils::ComputeX25519SharedSecret(
            local_x25519_priv_, *server_x25519, &ecdhe_shared)) {
      return false;
    }
    server_hello_bytes_.assign(raw_msg.begin(), raw_msg.end());
    full_hs_transcript_ = client_hello_bytes_;
    full_hs_transcript_.insert(full_hs_transcript_.end(),
                               server_hello_bytes_.begin(),
                               server_hello_bytes_.end());
    return DeriveTls13HandshakeKeys(ecdhe_shared, full_hs_transcript_);
  }

  void HandleCryptoBytes(QuicEncryptionLevel level) {
    const size_t idx = LevelIndex(level);
    std::vector<uint8_t> chunk;
    bool fin = false;
    if (crypto_rx_reassembler_[idx].ExtractContiguous(&chunk, &fin) &&
        !chunk.empty()) {
      crypto_rx_buf_[idx].insert(crypto_rx_buf_[idx].end(), chunk.begin(),
                                 chunk.end());
    }

    auto& buf = crypto_rx_buf_[idx];
    while (buf.size() >= 4) {
      const uint8_t msg_type = buf[0];
      const size_t body_len = (static_cast<size_t>(buf[1]) << 16) |
                              (static_cast<size_t>(buf[2]) << 8) |
                              static_cast<size_t>(buf[3]);
      if (body_len > 65536) {
        closed_ = true;
        events_->OnConnectionClosed(-105);
        return;
      }
      const size_t total_msg_len = 4 + body_len;
      if (total_msg_len > buf.size()) {
        break;
      }
      const std::vector<uint8_t> raw_msg(
          buf.begin(), buf.begin() + static_cast<ptrdiff_t>(total_msg_len));
      const ArrayView<const uint8_t> body(raw_msg.data() + 4, body_len);
      buf.erase(buf.begin(),
                buf.begin() + static_cast<ptrdiff_t>(total_msg_len));

      if (is_server_ && level == QuicEncryptionLevel::kInitial &&
          msg_type == kTlsHsClientHello && !server_hello_sent_) {
        if (!HandleServerClientHello(raw_msg, body)) {
          if (!closed_) {
            CloseTransportConnection(0x0128u);
            events_->OnConnectionClosed(-106);
          }
          return;
        }
      } else if (!is_server_ && level == QuicEncryptionLevel::kInitial &&
                 msg_type == kTlsHsServerHello &&
                 !rx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].valid) {
        if (!HandleClientServerHello(raw_msg, body)) {
          if (!closed_) {
            CloseTransportConnection(0x0128u);
            events_->OnConnectionClosed(-106);
          }
          return;
        }
      } else if (!is_server_ && level == QuicEncryptionLevel::kHandshake &&
                 !handshake_established_) {
        if (msg_type == kTlsHsEncryptedExtensions) {
          if (hs_got_encrypted_extensions_ || body.size() < 2) {
            CloseTransportConnection(0x010au);
            events_->OnConnectionClosed(-106);
            return;
          }
          const uint16_t exts_len = ReadBigEndian16(body.data());
          if (2u + exts_len != body.size()) {
            CloseTransportConnection(0x0132u);
            events_->OnConnectionClosed(-106);
            return;
          }
          bool saw_alpn = false;
          bool saw_tp = false;
          std::optional<QuicTransportParameters> srv_tp;
          size_t eoff = 2;
          while (eoff + 4 <= 2u + exts_len) {
            const uint16_t etype = ReadBigEndian16(body.data() + eoff);
            const uint16_t elen = ReadBigEndian16(body.data() + eoff + 2);
            eoff += 4;
            if (eoff + elen > 2u + exts_len) {
              CloseTransportConnection(0x0132u);
              events_->OnConnectionClosed(-106);
              return;
            }
            const ArrayView<const uint8_t> edata = body.subview(eoff, elen);
            eoff += elen;
            if (etype == kTlsExtAlpn) {
              if (saw_alpn || edata.size() < 4) {
                CloseTransportConnection(0x0132u);
                events_->OnConnectionClosed(-106);
                return;
              }
              const uint16_t list_len = ReadBigEndian16(edata.data());
              const uint8_t plen = edata[2];
              if (2u + list_len != edata.size() || plen == 0 ||
                  1u + plen != list_len) {
                CloseTransportConnection(0x0132u);
                events_->OnConnectionClosed(-106);
                return;
              }
              std::string srv_alpn(
                  reinterpret_cast<const char*>(edata.data() + 3), plen);
              if (!supported_alpns_.empty() &&
                  std::find(supported_alpns_.begin(), supported_alpns_.end(),
                            srv_alpn) == supported_alpns_.end()) {
                CloseTransportConnection(0x0178u);
                events_->OnConnectionClosed(-120);
                return;
              }
              negotiated_alpn_ = std::move(srv_alpn);
              saw_alpn = true;
            } else if (etype == kTlsExtQuicTransportParams) {
              if (saw_tp) {
                CloseTransportConnection(0x08u);
                events_->OnConnectionClosed(-106);
                return;
              }
              saw_tp = true;
              srv_tp = QuicTransportParameters::Decode(edata);
            }
          }
          if (eoff != 2u + exts_len) {
            CloseTransportConnection(0x0132u);
            events_->OnConnectionClosed(-106);
            return;
          }
          if (!supported_alpns_.empty() && !saw_alpn) {
            CloseTransportConnection(0x0178u);
            events_->OnConnectionClosed(-120);
            return;
          }
          if (!saw_tp) {
            CloseTransportConnection(0x016du);
            events_->OnConnectionClosed(-106);
            return;
          }
          if (!srv_tp.has_value() || !srv_tp->has_original_destination_cid ||
              srv_tp->original_destination_cid != initial_dcid_ ||
              (srv_tp->has_initial_source_cid &&
               srv_tp->initial_source_cid != peer_dcid_)) {
            CloseTransportConnection(0x08u);  // TRANSPORT_PARAMETER_ERROR
            events_->OnConnectionClosed(-106);
            return;
          }
          ApplyPeerTransportParameters(*srv_tp);
          hs_got_encrypted_extensions_ = true;
          full_hs_transcript_.insert(full_hs_transcript_.end(), raw_msg.begin(),
                                     raw_msg.end());
        } else if (msg_type == kTlsHsCertificateRequest) {
          if (!hs_got_encrypted_extensions_ || hs_got_certificate_ ||
              hs_got_cert_request_) {
            CloseTransportConnection(0x010au);
            events_->OnConnectionClosed(-106);
            return;
          }
          if (body.size() < 3) {
            CloseTransportConnection(0x0132u);
            events_->OnConnectionClosed(-106);
            return;
          }
          const uint8_t ctx_len = body[0];
          if (1u + ctx_len + 2u > body.size()) {
            CloseTransportConnection(0x0132u);
            events_->OnConnectionClosed(-106);
            return;
          }
          const uint16_t cr_exts_len =
              ReadBigEndian16(body.data() + 1u + ctx_len);
          if (1u + ctx_len + 2u + cr_exts_len != body.size()) {
            CloseTransportConnection(0x0132u);
            events_->OnConnectionClosed(-106);
            return;
          }
          cert_req_context_.assign(body.data() + 1, body.data() + 1 + ctx_len);
          hs_got_cert_request_ = true;
          full_hs_transcript_.insert(full_hs_transcript_.end(), raw_msg.begin(),
                                     raw_msg.end());
        } else if (msg_type == kTlsHsCertificate) {
          if (!hs_got_encrypted_extensions_ || hs_got_certificate_) {
            CloseTransportConnection(0x010au);
            events_->OnConnectionClosed(-107);
            return;
          }
          peer_cert_chain_der_.clear();
          peer_leaf_cert_der_.clear();
          bool cert_framing_ok = false;
          if (body.size() >= 4) {
            const uint8_t ctx_len = body[0];
            if (ctx_len == 0 && 4u <= body.size()) {
              const size_t list_len = (static_cast<size_t>(body[1]) << 16) |
                                      (static_cast<size_t>(body[2]) << 8) |
                                      static_cast<size_t>(body[3]);
              if (4u + list_len == body.size()) {
                size_t coff = 4u;
                cert_framing_ok = true;
                while (coff < body.size()) {
                  if (coff + 3u > body.size() ||
                      peer_cert_chain_der_.size() >= 16) {
                    cert_framing_ok = false;
                    break;
                  }
                  const size_t cert_len =
                      (static_cast<size_t>(body[coff]) << 16) |
                      (static_cast<size_t>(body[coff + 1]) << 8) |
                      static_cast<size_t>(body[coff + 2]);
                  coff += 3u;
                  if (cert_len == 0 || coff + cert_len + 2u > body.size()) {
                    cert_framing_ok = false;
                    break;
                  }
                  peer_cert_chain_der_.emplace_back(
                      body.data() + coff, body.data() + coff + cert_len);
                  coff += cert_len;
                  const uint16_t cext_len = ReadBigEndian16(body.data() + coff);
                  coff += 2u;
                  if (coff + cext_len > body.size()) {
                    cert_framing_ok = false;
                    break;
                  }
                  coff += cext_len;
                }
              }
            }
          }
          if (!cert_framing_ok || peer_cert_chain_der_.empty()) {
            CloseTransportConnection(0x012au);
            events_->OnConnectionClosed(-107);
            return;
          }
          uint64_t tls_alert = 0x012au;
          if (!VerifyServerCertificateChain(
                  peer_cert_chain_der_, tls_verify_cfg_, client_sni_host_,
                  &tls_alert)) {
            CloseTransportConnection(tls_alert);
            events_->OnConnectionClosed(-107);
            return;
          }
          peer_leaf_cert_der_ = peer_cert_chain_der_.front();
          hs_got_certificate_ = true;
          full_hs_transcript_.insert(full_hs_transcript_.end(), raw_msg.begin(),
                                     raw_msg.end());
        } else if (msg_type == kTlsHsCertificateVerify) {
          if (!hs_got_certificate_ || hs_got_cert_verify_ || body.size() < 4) {
            CloseTransportConnection(0x010au);
            events_->OnConnectionClosed(-107);
            return;
          }
          const uint16_t scheme = ReadBigEndian16(body.data());
          const uint16_t sig_len = ReadBigEndian16(body.data() + 2);
          if (4u + sig_len != body.size()) {
            CloseTransportConnection(0x0132u);
            events_->OnConnectionClosed(-107);
            return;
          }
          const auto thash = QuicCryptoUtils::Sha256(full_hs_transcript_);
          if (!QuicServerCertContext::VerifyServerCertVerify(
                  peer_leaf_cert_der_, scheme, body.subview(4, sig_len),
                  thash)) {
            RTC_LOG(kError) << "QUIC TLS 1.3 CertificateVerify failed";
            CloseTransportConnection(0x0133u);
            events_->OnConnectionClosed(-107);
            return;
          }
          hs_got_cert_verify_ = true;
          full_hs_transcript_.insert(full_hs_transcript_.end(), raw_msg.begin(),
                                     raw_msg.end());
        } else if (msg_type == kTlsHsFinished) {
          if (!hs_got_encrypted_extensions_ || !hs_got_certificate_ ||
              !hs_got_cert_verify_ || !peer_tp_received_ || body.size() != 32) {
            CloseTransportConnection(0x010au);
            events_->OnConnectionClosed(-102);
            return;
          }
          const auto thash = QuicCryptoUtils::Sha256(full_hs_transcript_);
          std::array<uint8_t, 32> s_fin_key{};
          QuicCryptoUtils::HkdfExpandLabel(
              rx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].secret,
              "finished", ArrayView<const uint8_t>(), s_fin_key.data(),
              s_fin_key.size());
          std::array<uint8_t, 32> expected_mac{};
          QuicCryptoUtils::HmacSha256(s_fin_key, thash, &expected_mac);
          if (CRYPTO_memcmp(expected_mac.data(), body.data(), 32) != 0) {
            RTC_LOG(kError) << "QUIC ServerFinished HMAC verification failed";
            CloseTransportConnection(0x0133u);
            events_->OnConnectionClosed(-102);
            return;
          }
          full_hs_transcript_.insert(full_hs_transcript_.end(), raw_msg.begin(),
                                     raw_msg.end());
          if (!DeriveApplicationSecrets(full_hs_transcript_)) {
            CloseTransportConnection(0x0150u);
            events_->OnConnectionClosed(-102);
            return;
          }

          // RFC 8446 第 4.4.2 节：若服务端发送了 CertificateRequest，须在 ClientFinished
          // 之前发送空客户端 Certificate 消息并纳入客户端 Finished 转录哈希。
          if (hs_got_cert_request_) {
            std::vector<uint8_t> cli_cert_body;
            cli_cert_body.reserve(4 + cert_req_context_.size());
            cli_cert_body.push_back(
                static_cast<uint8_t>(cert_req_context_.size()));
            cli_cert_body.insert(cli_cert_body.end(), cert_req_context_.begin(),
                                 cert_req_context_.end());
            AppendUint24BE(0, &cli_cert_body);
            const auto cli_cert_msg =
                WrapTlsHandshakeMsg(kTlsHsCertificate, cli_cert_body);
            full_hs_transcript_.insert(full_hs_transcript_.end(),
                                       cli_cert_msg.begin(),
                                       cli_cert_msg.end());
            QueueCryptoData(QuicEncryptionLevel::kHandshake, cli_cert_msg);
          }

          const auto full_hash = QuicCryptoUtils::Sha256(full_hs_transcript_);
          std::array<uint8_t, 32> c_fin_key{};
          QuicCryptoUtils::HkdfExpandLabel(
              tx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].secret,
              "finished", ArrayView<const uint8_t>(), c_fin_key.data(),
              c_fin_key.size());
          std::array<uint8_t, 32> client_verify{};
          QuicCryptoUtils::HmacSha256(c_fin_key, full_hash, &client_verify);
          const auto cfin_msg =
              WrapTlsHandshakeMsg(kTlsHsFinished, client_verify);
          QueueCryptoData(QuicEncryptionLevel::kHandshake, cfin_msg);

          handshake_established_ = true;
          events_->OnHandshakeEstablished();
          if (closed_) {
            return;
          }
        } else {
          CloseTransportConnection(0x010au);
          events_->OnConnectionClosed(-106);
          return;
        }
      } else if (is_server_ && level == QuicEncryptionLevel::kHandshake &&
                 msg_type == kTlsHsFinished && !handshake_established_) {
        if (body.size() != 32) {
          CloseTransportConnection(0x0132u);
          events_->OnConnectionClosed(-103);
          return;
        }
        const auto full_hash = QuicCryptoUtils::Sha256(full_hs_transcript_);
        std::array<uint8_t, 32> c_fin_key{};
        QuicCryptoUtils::HkdfExpandLabel(
            rx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].secret,
            "finished", ArrayView<const uint8_t>(), c_fin_key.data(),
            c_fin_key.size());
        std::array<uint8_t, 32> expected_mac{};
        QuicCryptoUtils::HmacSha256(c_fin_key, full_hash, &expected_mac);
        if (CRYPTO_memcmp(expected_mac.data(), body.data(), 32) != 0) {
          RTC_LOG(kError) << "QUIC ClientFinished HMAC verification failed";
          CloseTransportConnection(0x0133u);
          events_->OnConnectionClosed(-103);
          return;
        }

        handshake_established_ = true;
        peer_address_validated_ = true;
        pending_handshake_done_ = true;
        // RFC 9001 第 4.9.2 节：服务端确认握手完成后立即丢弃 Handshake 密钥空间。
        DiscardPacketSpace(QuicEncryptionLevel::kHandshake);
        events_->OnHandshakeEstablished();
        if (closed_) {
          return;
        }
      } else if (!is_server_ && level == QuicEncryptionLevel::kOneRtt &&
                 handshake_established_ && msg_type == kTlsHsNewSessionTicket) {
        // RFC 8446 第 4.6.1 节与 RFC 9001 第 4.6 节：安全消费并忽略 1-RTT 会话票据消息。
        continue;
      } else {
        CloseTransportConnection(0x010au);
        events_->OnConnectionClosed(-106);
        return;
      }
    }
  }

  // ---------------- 帧解析与丢包/拥塞恢复 ----------------

  bool ProcessFrames(QuicEncryptionLevel level,
                     ArrayView<const uint8_t> payload,
                     Timestamp now,
                     bool* out_ack_eliciting,
                     bool* out_non_probing) {
    *out_ack_eliciting = false;
    *out_non_probing = false;
    size_t off = 0;
    while (off < payload.size()) {
      if (payload[off] == kFramePadding) {
        ++off;
        continue;
      }

      const size_t type_start = off;
      uint64_t frame_type = 0;
      if (!QuicVarInt::Read(payload, &off, &frame_type)) {
        return false;
      }

      if (frame_type != kFramePathChallenge &&
          frame_type != kFramePathResponse &&
          frame_type != kFrameNewConnectionId) {
        *out_non_probing = true;
      }

      // RFC 9000 第 12.4 节：Initial 与 Handshake 包空间严禁承载 1-RTT 应用帧。
      if (level != QuicEncryptionLevel::kOneRtt &&
          frame_type != kFramePing && frame_type != kFrameAck &&
          frame_type != kFrameAckEcn && frame_type != kFrameCrypto &&
          frame_type != kFrameConnectionCloseQuic) {
        CloseTransportConnection(0x0au);
        events_->OnConnectionClosed(-105);
        return false;
      }

      if (frame_type == kFramePing) {
        *out_ack_eliciting = true;
      } else if (frame_type == kFrameAck || frame_type == kFrameAckEcn) {
        off = type_start;
        uint64_t ack_delay_us = 0;
        std::vector<QuicAckRangeSet::Range> ranges;
        const uint64_t ack_exp =
            (level == QuicEncryptionLevel::kOneRtt && peer_tp_received_)
                ? peer_tp_.ack_delay_exponent
                : 3;
        if (!QuicAckRangeSet::DecodeAckFrame(payload, &off, &ack_delay_us,
                                             &ranges, ack_exp)) {
          return false;
        }
        if (!OnAckReceived(level, ack_delay_us, ranges, now)) {
          return false;
        }
      } else if (frame_type == kFrameCrypto) {
        *out_ack_eliciting = true;
        uint64_t crypto_off = 0;
        uint64_t crypto_len = 0;
        if (!QuicVarInt::Read(payload, &off, &crypto_off) ||
            !QuicVarInt::Read(payload, &off, &crypto_len) ||
            crypto_len > payload.size() - off) {
          return false;
        }
        constexpr uint64_t kMaxCryptoStreamBytes = 256 * 1024;
        if (crypto_off > kMaxCryptoStreamBytes ||
            crypto_len > kMaxCryptoStreamBytes ||
            crypto_off + crypto_len > kMaxCryptoStreamBytes) {
          CloseTransportConnection(0x0du);  // CRYPTO_BUFFER_EXCEEDED
          events_->OnConnectionClosed(-105);
          return false;
        }
        uint64_t newly_crypto = 0;
        uint64_t crypto_err = 0;
        if (!crypto_rx_reassembler_[LevelIndex(level)].ValidateAndAccountReceive(
                crypto_off, static_cast<size_t>(crypto_len), false,
                &newly_crypto, &crypto_err)) {
          if (crypto_err != 0) {
            CloseTransportConnection(0x0du);
            events_->OnConnectionClosed(-105);
          }
          return false;
        }
        crypto_rx_reassembler_[LevelIndex(level)].InsertChunk(
            crypto_off, payload.subview(off, static_cast<size_t>(crypto_len)),
            false);
        off += static_cast<size_t>(crypto_len);
        HandleCryptoBytes(level);
        if (closed_) {
          return false;
        }
        if (level == QuicEncryptionLevel::kInitial &&
            rx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].valid &&
            !crypto_rx_buf_[LevelIndex(QuicEncryptionLevel::kHandshake)]
                 .empty()) {
          HandleCryptoBytes(QuicEncryptionLevel::kHandshake);
          if (closed_) {
            return false;
          }
        }
      } else if (frame_type >= kFrameStreamBase &&
                 frame_type <= (kFrameStreamBase | 0x07u)) {
        *out_ack_eliciting = true;
        uint64_t stream_id = 0;
        if (!QuicVarInt::Read(payload, &off, &stream_id)) {
          return false;
        }
        uint64_t stream_off = 0;
        if ((frame_type & kFrameStreamOffBit) != 0 &&
            !QuicVarInt::Read(payload, &off, &stream_off)) {
          return false;
        }
        uint64_t stream_len = payload.size() - off;
        if ((frame_type & kFrameStreamLenBit) != 0) {
          if (!QuicVarInt::Read(payload, &off, &stream_len) ||
              stream_len > payload.size() - off) {
            return false;
          }
        }
        const bool fin = (frame_type & kFrameStreamFinBit) != 0;
        const ArrayView<const uint8_t> sdata =
            payload.subview(off, static_cast<size_t>(stream_len));
        off += static_cast<size_t>(stream_len);

        const bool is_peer_initiated =
            ((stream_id & 0x01u) == (is_server_ ? 0u : 1u));
        const bool is_uni = (stream_id & 0x02u) != 0;
        if (!is_peer_initiated) {
          if (is_uni || (stream_id >> 2) >= local_opened_bidi_count_) {
            CloseTransportConnection(0x05u);  // STREAM_STATE_ERROR
            events_->OnConnectionClosed(-105);
            return false;
          }
        } else {
          const uint64_t stream_idx = stream_id >> 2;
          const uint64_t max_streams =
              is_uni ? local_max_streams_uni_ : local_max_streams_bidi_;
          if (stream_idx >= max_streams) {
            CloseTransportConnection(0x04u);  // STREAM_LIMIT_ERROR
            events_->OnConnectionClosed(-105);
            return false;
          }
        }

        if (IsInboundStreamRetired(stream_id)) {
          continue;
        }

        auto& rx_buf = inbound_streams_[stream_id];
        rx_buf.ConfigureFlowControlWindow(InitialLocalReceiveStreamWindow(stream_id));
        uint64_t newly_rx_bytes = 0;
        uint64_t fc_err = 0;
        if (!rx_buf.ValidateAndAccountReceive(stream_off, sdata.size(), fin,
                                              &newly_rx_bytes, &fc_err)) {
          if (fc_err != 0) {
            CloseTransportConnection(fc_err);
            events_->OnConnectionClosed(-105);
          }
          return false;
        }
        if (newly_rx_bytes > local_max_data_ ||
            conn_rx_highest_total_ > local_max_data_ - newly_rx_bytes) {
          CloseTransportConnection(0x03u);  // FLOW_CONTROL_ERROR
          events_->OnConnectionClosed(-105);
          return false;
        }
        conn_rx_highest_total_ += newly_rx_bytes;

        if (rx_buf.is_stop_sending_requested()) {
          if (fin) {
            rx_buf.RecordFinalOffset(stream_off + sdata.size());
          }
          if (rx_buf.highest_received_offset() >
              rx_buf.accounted_consumed_offset()) {
            conn_rx_consumed_total_ +=
                (rx_buf.highest_received_offset() -
                 rx_buf.accounted_consumed_offset());
            rx_buf.set_accounted_consumed_offset(
                rx_buf.highest_received_offset());
            MaybeReplenishConnectionMaxData();
          }
          if (fin || rx_buf.final_offset().has_value()) {
            RetireInboundStream(stream_id);
          }
          continue;
        }

        if (is_peer_initiated &&
            announced_inbound_streams_.insert(stream_id).second) {
          events_->OnPeerStreamOpened(stream_id, is_uni);
          if (closed_) {
            return false;
          }
          if (IsInboundStreamRetired(stream_id)) {
            continue;
          }
        }

        auto rx_it = inbound_streams_.find(stream_id);
        if (rx_it == inbound_streams_.end()) {
          continue;
        }
        if (rx_it->second.is_stop_sending_requested()) {
          if (fin) {
            rx_it->second.RecordFinalOffset(stream_off + sdata.size());
          }
          if (rx_it->second.highest_received_offset() >
              rx_it->second.accounted_consumed_offset()) {
            conn_rx_consumed_total_ +=
                (rx_it->second.highest_received_offset() -
                 rx_it->second.accounted_consumed_offset());
            rx_it->second.set_accounted_consumed_offset(
                rx_it->second.highest_received_offset());
            MaybeReplenishConnectionMaxData();
          }
          if (fin || rx_it->second.final_offset().has_value()) {
            RetireInboundStream(stream_id);
          }
          continue;
        }

        rx_it->second.InsertChunk(stream_off, sdata, fin);
        std::vector<uint8_t> ordered;
        bool deliver_fin = false;
        if (rx_it->second.ExtractContiguous(&ordered, &deliver_fin)) {
          if (rx_it->second.next_deliver_offset() >
              rx_it->second.accounted_consumed_offset()) {
            conn_rx_consumed_total_ +=
                (rx_it->second.next_deliver_offset() -
                 rx_it->second.accounted_consumed_offset());
            rx_it->second.set_accounted_consumed_offset(
                rx_it->second.next_deliver_offset());
            MaybeReplenishConnectionMaxData();
          }
          events_->OnPeerStreamData(stream_id, ordered, deliver_fin);
          if (closed_) {
            return false;
          }
        }
        rx_it = inbound_streams_.find(stream_id);
        if (deliver_fin) {
          RetireInboundStream(stream_id);
        } else if (rx_it != inbound_streams_.end() &&
                   rx_it->second.has_pending_reset_at() &&
                   (rx_it->second.is_stop_sending_requested() ||
                    rx_it->second.next_deliver_offset() >=
                        rx_it->second.reliable_reset_size())) {
          const uint64_t rst_err = rx_it->second.reset_app_error_code();
          RetireInboundStream(stream_id);
          events_->OnPeerStreamReset(stream_id, rst_err);
          if (closed_) {
            return false;
          }
        } else if (rx_it != inbound_streams_.end() &&
                   !rx_it->second.is_complete() &&
                   !rx_it->second.is_stop_sending_requested() &&
                   !rx_it->second.has_pending_reset_at() &&
                   rx_it->second.window_size() > 0 &&
                   (rx_it->second.max_receive_offset() -
                    rx_it->second.next_deliver_offset()) <=
                       rx_it->second.window_size() / 2) {
          rx_it->second.set_max_receive_offset(
              rx_it->second.next_deliver_offset() + rx_it->second.window_size());
          pending_max_stream_data_sids_.insert(stream_id);
        }
      } else if (frame_type == kFrameResetStream ||
                 frame_type == kFrameResetStreamAt) {
        *out_ack_eliciting = true;
        uint64_t stream_id = 0;
        uint64_t app_err = 0;
        uint64_t final_size = 0;
        uint64_t reliable_size = 0;
        if (!QuicVarInt::Read(payload, &off, &stream_id) ||
            !QuicVarInt::Read(payload, &off, &app_err) ||
            !QuicVarInt::Read(payload, &off, &final_size)) {
          return false;
        }
        if (frame_type == kFrameResetStreamAt) {
          if (!local_tp_.reset_stream_at_supported) {
            CloseTransportConnection(0x0au);
            events_->OnConnectionClosed(-105);
            return false;
          }
          if (!QuicVarInt::Read(payload, &off, &reliable_size)) {
            return false;
          }
          if (reliable_size > final_size) {
            CloseTransportConnection(0x07u);  // FRAME_ENCODING_ERROR
            events_->OnConnectionClosed(-105);
            return false;
          }
        }
        const bool is_peer_initiated =
            ((stream_id & 0x01u) == (is_server_ ? 0u : 1u));
        const bool is_uni = (stream_id & 0x02u) != 0;
        if (!is_peer_initiated) {
          if (is_uni || (stream_id >> 2) >= local_opened_bidi_count_) {
            CloseTransportConnection(0x05u);
            events_->OnConnectionClosed(-105);
            return false;
          }
        } else {
          const uint64_t stream_idx = stream_id >> 2;
          const uint64_t max_streams =
              is_uni ? local_max_streams_uni_ : local_max_streams_bidi_;
          if (stream_idx >= max_streams) {
            CloseTransportConnection(0x04u);
            events_->OnConnectionClosed(-105);
            return false;
          }
        }

        if (IsInboundStreamRetired(stream_id)) {
          continue;
        }

        auto& rx_buf = inbound_streams_[stream_id];
        rx_buf.ConfigureFlowControlWindow(InitialLocalReceiveStreamWindow(stream_id));
        const uint64_t max_stream_win = rx_buf.max_receive_offset();
        const uint64_t prev_highest = rx_buf.highest_received_offset();
        if (final_size > max_stream_win) {
          CloseTransportConnection(0x03u);
          events_->OnConnectionClosed(-105);
          return false;
        }
        if ((rx_buf.final_offset().has_value() &&
             *rx_buf.final_offset() != final_size) ||
            final_size < prev_highest) {
          CloseTransportConnection(0x06u);  // FINAL_SIZE_ERROR
          events_->OnConnectionClosed(-105);
          return false;
        }
        const uint64_t newly_rx =
            (final_size > prev_highest) ? (final_size - prev_highest) : 0;
        if (newly_rx > local_max_data_ ||
            conn_rx_highest_total_ > local_max_data_ - newly_rx) {
          CloseTransportConnection(0x03u);
          events_->OnConnectionClosed(-105);
          return false;
        }
        conn_rx_highest_total_ += newly_rx;
        rx_buf.RecordFinalOffset(final_size);
        rx_buf.SetPendingResetAt(reliable_size, app_err);

        if (!rx_buf.is_stop_sending_requested() &&
            rx_buf.reliable_reset_size() > 0) {
          if (is_peer_initiated &&
              announced_inbound_streams_.insert(stream_id).second) {
            events_->OnPeerStreamOpened(stream_id, is_uni);
            if (closed_) {
              return false;
            }
          }
          auto rx_it = inbound_streams_.find(stream_id);
          if (rx_it != inbound_streams_.end() &&
              !rx_it->second.is_stop_sending_requested()) {
            std::vector<uint8_t> ordered;
            bool deliver_fin = false;
            if (rx_it->second.ExtractContiguousUpTo(
                    rx_it->second.reliable_reset_size(), &ordered,
                    &deliver_fin) &&
                !ordered.empty()) {
              if (rx_it->second.next_deliver_offset() >
                  rx_it->second.accounted_consumed_offset()) {
                conn_rx_consumed_total_ +=
                    (rx_it->second.next_deliver_offset() -
                     rx_it->second.accounted_consumed_offset());
                rx_it->second.set_accounted_consumed_offset(
                    rx_it->second.next_deliver_offset());
                MaybeReplenishConnectionMaxData();
              }
              events_->OnPeerStreamData(stream_id, ordered, false);
              if (closed_) {
                return false;
              }
            }
          }
        }

        auto rx_it = inbound_streams_.find(stream_id);
        if (rx_it != inbound_streams_.end() &&
            (rx_it->second.is_stop_sending_requested() ||
             rx_it->second.next_deliver_offset() >=
                 rx_it->second.reliable_reset_size())) {
          const uint64_t rst_err = rx_it->second.reset_app_error_code();
          RetireInboundStream(stream_id);
          events_->OnPeerStreamReset(stream_id, rst_err);
          if (closed_) {
            return false;
          }
        }
      } else if (frame_type == kFrameStopSending) {
        *out_ack_eliciting = true;
        uint64_t stream_id = 0;
        uint64_t app_err = 0;
        if (!QuicVarInt::Read(payload, &off, &stream_id) ||
            !QuicVarInt::Read(payload, &off, &app_err)) {
          return false;
        }
        const bool is_peer_initiated =
            ((stream_id & 0x01u) == (is_server_ ? 0u : 1u));
        const bool is_uni = (stream_id & 0x02u) != 0;
        if (is_peer_initiated) {
          if (is_uni || (stream_id >> 2) >= local_max_streams_bidi_) {
            CloseTransportConnection(0x05u);
            events_->OnConnectionClosed(-105);
            return false;
          }
        } else {
          const uint64_t opened_cnt =
              is_uni ? local_opened_uni_count_ : local_opened_bidi_count_;
          if ((stream_id >> 2) >= opened_cnt) {
            CloseTransportConnection(0x05u);
            events_->OnConnectionClosed(-105);
            return false;
          }
        }
        if (!IsOutboundStreamRetired(stream_id)) {
          QueueResetStreamNoFlush(stream_id, app_err,
                                  /*allow_unopened_peer_bidi=*/true);
        }
        events_->OnPeerStopSending(stream_id, app_err);
        if (closed_) {
          return false;
        }
      } else if (frame_type == kFrameDatagram ||
                 frame_type == kFrameDatagramLen) {
        *out_ack_eliciting = true;
        if (local_tp_.max_datagram_frame_size == 0) {
          CloseTransportConnection(0x0au);
          events_->OnConnectionClosed(-105);
          return false;
        }
        uint64_t dgram_len = payload.size() - off;
        if (frame_type == kFrameDatagramLen) {
          if (!QuicVarInt::Read(payload, &off, &dgram_len) ||
              dgram_len > payload.size() - off) {
            return false;
          }
        }
        const ArrayView<const uint8_t> dgram_slice =
            payload.subview(off, static_cast<size_t>(dgram_len));
        off += static_cast<size_t>(dgram_len);
        events_->OnPeerDatagramReceived(dgram_slice);
        if (closed_) {
          return false;
        }
      } else if (frame_type == kFrameNewToken) {
        *out_ack_eliciting = true;
        if (is_server_) {
          CloseTransportConnection(0x0au);
          events_->OnConnectionClosed(-105);
          return false;
        }
        uint64_t tok_len = 0;
        if (!QuicVarInt::Read(payload, &off, &tok_len) ||
            tok_len > payload.size() - off) {
          return false;
        }
        off += static_cast<size_t>(tok_len);
      } else if (frame_type == kFrameMaxData ||
                 frame_type == kFrameMaxStreamsBidi ||
                 frame_type == kFrameMaxStreamsUni ||
                 frame_type == kFrameDataBlocked ||
                 frame_type == kFrameStreamsBlockedBidi ||
                 frame_type == kFrameStreamsBlockedUni ||
                 frame_type == kFrameRetireConnectionId) {
        *out_ack_eliciting = true;
        uint64_t val = 0;
        if (!QuicVarInt::Read(payload, &off, &val)) {
          return false;
        }
        if (frame_type == kFrameMaxData) {
          peer_max_data_ = std::max(peer_max_data_, val);
        } else if (frame_type == kFrameMaxStreamsBidi) {
          peer_max_streams_bidi_ = std::max(peer_max_streams_bidi_, val);
        } else if (frame_type == kFrameMaxStreamsUni) {
          peer_max_streams_uni_ = std::max(peer_max_streams_uni_, val);
        }
      } else if (frame_type == kFrameMaxStreamData ||
                 frame_type == kFrameStreamDataBlocked) {
        *out_ack_eliciting = true;
        uint64_t sid = 0;
        uint64_t max_sdata = 0;
        if (!QuicVarInt::Read(payload, &off, &sid) ||
            !QuicVarInt::Read(payload, &off, &max_sdata)) {
          return false;
        }
        if (frame_type == kFrameMaxStreamData) {
          if (!CanSendOnStream(sid)) {
            CloseTransportConnection(0x05u);
            events_->OnConnectionClosed(-105);
            return false;
          }
          const bool is_local = ((sid & 0x01u) == (is_server_ ? 1u : 0u));
          if (is_local) {
            const bool is_uni = (sid & 0x02u) != 0;
            const uint64_t opened_cnt =
                is_uni ? local_opened_uni_count_ : local_opened_bidi_count_;
            if ((sid >> 2) >= opened_cnt) {
              CloseTransportConnection(0x05u);
              events_->OnConnectionClosed(-105);
              return false;
            }
          }
          const auto st_it = outbound_streams_.find(sid);
          if (st_it != outbound_streams_.end()) {
            if (!st_it->second.flow_limit_initialized) {
              st_it->second.peer_max_stream_data = InitialPeerStreamMaxData(sid);
              st_it->second.flow_limit_initialized = true;
            }
            st_it->second.peer_max_stream_data =
                std::max(st_it->second.peer_max_stream_data, max_sdata);
          }
        } else if (!CanReceiveOnStream(sid)) {
          CloseTransportConnection(0x05u);
          events_->OnConnectionClosed(-105);
          return false;
        }
      } else if (frame_type == kFrameNewConnectionId) {
        *out_ack_eliciting = true;
        uint64_t seq_no = 0;
        uint64_t retire_prior = 0;
        if (!QuicVarInt::Read(payload, &off, &seq_no) ||
            !QuicVarInt::Read(payload, &off, &retire_prior) ||
            retire_prior > seq_no ||
            off + 1 > payload.size()) {
          CloseTransportConnection(0x07u);  // FRAME_ENCODING_ERROR
          events_->OnConnectionClosed(-105);
          return false;
        }
        const uint8_t cid_len = payload[off++];
        if (cid_len < 1 || cid_len > kQuicMaxCidLength ||
            off + cid_len + 16 > payload.size()) {
          return false;
        }
        QuicCid new_cid(payload.data() + off, cid_len);
        off += cid_len + 16;

        if (seq_no >= max_retire_prior_to_ &&
            peer_cids_.size() <
                std::max<size_t>(8, static_cast<size_t>(
                                        local_tp_.active_connection_id_limit) *
                                        2)) {
          peer_cids_[seq_no] = new_cid;
        }
        if (peer_dcid_.empty()) {
          peer_dcid_ = new_cid;
          active_peer_cid_seq_ = seq_no;
        }
        if (retire_prior > max_retire_prior_to_) {
          max_retire_prior_to_ = retire_prior;
          for (auto cid_it = peer_cids_.begin(); cid_it != peer_cids_.end();) {
            if (cid_it->first < max_retire_prior_to_) {
              if (pending_retire_cids_.size() < 32) {
                pending_retire_cids_.push_back(cid_it->first);
              }
              cid_it = peer_cids_.erase(cid_it);
            } else {
              ++cid_it;
            }
          }
          if (active_peer_cid_seq_ < max_retire_prior_to_ &&
              !peer_cids_.empty()) {
            active_peer_cid_seq_ = peer_cids_.begin()->first;
            peer_dcid_ = peer_cids_.begin()->second;
          }
        }
      } else if (frame_type == kFramePathChallenge) {
        *out_ack_eliciting = true;
        if (off + 8 > payload.size()) {
          return false;
        }
        std::array<uint8_t, 8> ch{};
        std::memcpy(ch.data(), payload.data() + off, 8);
        off += 8;
        if (pending_path_responses_.size() < 16) {
          pending_path_responses_.push_back(ch);
        }
      } else if (frame_type == kFramePathResponse) {
        *out_ack_eliciting = true;
        if (off + 8 > payload.size()) {
          return false;
        }
        off += 8;
      } else if (frame_type == kFrameHandshakeDone) {
        if (is_server_) {
          CloseTransportConnection(0x0au);
          events_->OnConnectionClosed(-105);
          return false;
        }
        *out_ack_eliciting = true;
        DiscardPacketSpace(QuicEncryptionLevel::kHandshake);
      } else if (frame_type == kFrameConnectionCloseQuic ||
                 frame_type == kFrameConnectionCloseApp) {
        uint64_t err_code = 0;
        uint64_t offending_frame = 0;
        std::string reason;
        if (!QuicVarInt::Read(payload, &off, &err_code)) {
          return false;
        }
        if (frame_type == kFrameConnectionCloseQuic &&
            !QuicVarInt::Read(payload, &off, &offending_frame)) {
          return false;
        }
        if (!QuicVarInt::ReadString(payload, &off, &reason)) {
          return false;
        }
        closed_ = true;
        events_->OnConnectionClosed(static_cast<int>(err_code));
        return true;
      } else {
        return false;
      }
    }
    return true;
  }

  bool OnAckReceived(QuicEncryptionLevel level,
                     uint64_t ack_delay_us,
                     const std::vector<QuicAckRangeSet::Range>& ranges,
                     Timestamp now) {
    if (ranges.empty()) {
      return true;
    }
    const size_t idx = LevelIndex(level);
    const uint64_t largest_acked = ranges.front().largest;
    if (largest_acked >= next_tx_pn_[idx]) {
      // RFC 9000 第 13.1 节：对未发送过的包号进行确认属于 PROTOCOL_VIOLATION (0x0a)。
      RTC_LOG(kWarning) << "QUIC PROTOCOL_VIOLATION: peer ACKed unsent pn="
                        << largest_acked << " (next_tx_pn=" << next_tx_pn_[idx]
                        << ")";
      CloseTransportConnection(0x0au);
      events_->OnConnectionClosed(-105);
      return false;
    }
    largest_acked_pn_[idx] = std::max<int64_t>(
        largest_acked_pn_[idx], static_cast<int64_t>(largest_acked));

    auto& sent_map = sent_packets_[idx];
    const auto largest_it = sent_map.find(largest_acked);
    if (largest_it != sent_map.end() && largest_it->second.ack_eliciting) {
      const TimeDelta latest_rtt =
          std::max(TimeDelta::Micros(500), now - largest_it->second.sent_time);
      const uint64_t max_ack_delay_us =
          peer_tp_received_ ? (peer_tp_.max_ack_delay_ms * 1000ULL) : 25'000ULL;
      const uint64_t capped_ack_delay_us =
          std::min<uint64_t>(ack_delay_us, max_ack_delay_us);
      UpdateRtt(latest_rtt,
                level == QuicEncryptionLevel::kOneRtt
                    ? TimeDelta::Micros(static_cast<int64_t>(capped_ack_delay_us))
                    : TimeDelta::Zero());
    }

    const size_t prior_in_flight = bytes_in_flight_;
    size_t newly_acked_bytes = 0;
    uint32_t newly_acked_pkts = 0;
    std::vector<QuicAckedPacket> acked_vec;
    // ranges 在解码时按降序排列；此处逆序遍历以确保 acked_vec 按包号严格升序送入 BBR/CUBIC/Copa。
    for (auto rit = ranges.rbegin(); rit != ranges.rend(); ++rit) {
      const auto& range = *rit;
      auto it = sent_map.lower_bound(range.smallest);
      while (it != sent_map.end() && it->first <= range.largest) {
        if (it->second.in_flight) {
          bytes_in_flight_ =
              (bytes_in_flight_ >= it->second.sent_bytes)
                  ? (bytes_in_flight_ - it->second.sent_bytes)
                  : 0;
          newly_acked_bytes += it->second.sent_bytes;
          ++newly_acked_pkts;
          conn_delivered_bytes_ += it->second.sent_bytes;
          conn_delivered_time_us_ = now.us();
          conn_first_sent_time_us_ = it->second.sent_time.us();

          QuicAckedPacket ap;
          ap.packet_number = it->second.cc_seq;
          ap.bytes = it->second.sent_bytes;
          ap.sent_time_us = it->second.sent_time.us();
          ap.prior_in_flight_bytes = it->second.prior_in_flight_bytes;
          ap.delivered_bytes_at_send = it->second.delivered_bytes_at_send;
          ap.delivered_time_us_at_send = it->second.delivered_time_us_at_send;
          ap.first_sent_time_us_at_send = it->second.first_sent_time_us_at_send;
          ap.is_app_limited = it->second.is_app_limited;
          acked_vec.push_back(ap);
        }
        for (const auto& frm : it->second.frames) {
          if (frm.kind == SentRetransmittable::Kind::kStream) {
            const auto st_it =
                outbound_streams_.find(frm.stream_chunk.stream_id);
            if (st_it != outbound_streams_.end()) {
              if (st_it->second.in_flight_frames > 0) {
                --st_it->second.in_flight_frames;
              }
              MaybeEraseCompletedOutboundStream(frm.stream_chunk.stream_id);
            }
          } else if (frm.kind == SentRetransmittable::Kind::kResetStream) {
            const auto st_it =
                outbound_streams_.find(frm.reset_info.stream_id);
            if (st_it != outbound_streams_.end()) {
              st_it->second.reset_in_flight = false;
              MaybeEraseCompletedOutboundStream(frm.reset_info.stream_id);
            }
          }
        }
        it = sent_map.erase(it);
      }
    }

    if (newly_acked_bytes > 0) {
      pto_count_ = 0;
      UpdateDeliveryRateAndLossWindow(newly_acked_bytes, newly_acked_pkts, 0,
                                      now);
    }

    std::vector<QuicLostPacket> lost_vec =
        DetectLostPacketsInSpace(level, now);

    if ((!acked_vec.empty() || !lost_vec.empty()) && cc_) {
      QuicRttSample rtt_sample;
      rtt_sample.latest_rtt_us = latest_rtt_.us();
      rtt_sample.smoothed_rtt_us = smoothed_rtt_.us();
      rtt_sample.min_rtt_us =
          min_rtt_.IsFinite() ? min_rtt_.us() : smoothed_rtt_.us();
      rtt_sample.rttvar_us = rttvar_.us();
      cc_->OnCongestionEvent(now.us(), prior_in_flight, bytes_in_flight_,
                             rtt_sample, acked_vec, lost_vec);
    }
    return true;
  }

  void UpdateRtt(TimeDelta latest_rtt, TimeDelta ack_delay) {
    latest_rtt_ = latest_rtt;
    if (!min_rtt_.IsFinite() || latest_rtt < min_rtt_) {
      min_rtt_ = latest_rtt;
    }
    TimeDelta adjusted_rtt = latest_rtt;
    if (latest_rtt >= min_rtt_ + ack_delay) {
      adjusted_rtt = latest_rtt - ack_delay;
    }
    if (!has_rtt_sample_) {
      has_rtt_sample_ = true;
      smoothed_rtt_ = adjusted_rtt;
      rttvar_ = adjusted_rtt * 0.5;
    } else {
      const int64_t diff_us =
          std::abs((smoothed_rtt_ - adjusted_rtt).us());
      rttvar_ = TimeDelta::Micros((3 * rttvar_.us() + diff_us) / 4);
      smoothed_rtt_ =
          TimeDelta::Micros((7 * smoothed_rtt_.us() + adjusted_rtt.us()) / 8);
    }
  }

  void UpdateDeliveryRateAndLossWindow(size_t acked_bytes,
                                       uint32_t acked_pkts,
                                       uint32_t lost_pkts,
                                       Timestamp now) {
    if (!rate_window_start_.IsFinite()) {
      rate_window_start_ = now;
    }
    rate_window_acked_bytes_ += acked_bytes;
    const TimeDelta win_min = std::max(smoothed_rtt_, TimeDelta::Millis(20));
    const TimeDelta win_elapsed = now - rate_window_start_;
    if (win_elapsed >= win_min && rate_window_acked_bytes_ > 0) {
      const int64_t sample_bps =
          (static_cast<int64_t>(rate_window_acked_bytes_) * 8'000'000) /
          std::max<int64_t>(1, win_elapsed.us());
      delivery_rate_bps_ =
          (delivery_rate_bps_ == 0)
              ? sample_bps
              : ((delivery_rate_bps_ * 3 + sample_bps * 5) / 8);
      rate_window_acked_bytes_ = 0;
      rate_window_start_ = now;
    }

    window_acked_pkts_ += acked_pkts;
    window_lost_pkts_ += lost_pkts;
    const uint32_t total_win = window_acked_pkts_ + window_lost_pkts_;
    if (lost_pkts > 0 && total_win >= 8) {
      const double inst =
          static_cast<double>(window_lost_pkts_) / static_cast<double>(total_win);
      recent_loss_ratio_ = std::max(recent_loss_ratio_, inst);
    }
    if (total_win >= 48) {
      const double sample =
          static_cast<double>(window_lost_pkts_) / static_cast<double>(total_win);
      recent_loss_ratio_ = 0.5 * recent_loss_ratio_ + 0.5 * sample;
      window_acked_pkts_ = 0;
      window_lost_pkts_ = 0;
    }
  }

  void DetectLostPacketsAllSpaces(Timestamp now) {
    for (QuicEncryptionLevel lvl :
         {QuicEncryptionLevel::kInitial, QuicEncryptionLevel::kHandshake,
          QuicEncryptionLevel::kOneRtt}) {
      const size_t prior_in_flight = bytes_in_flight_;
      auto lost_vec = DetectLostPacketsInSpace(lvl, now);
      if (!lost_vec.empty() && cc_) {
        QuicRttSample rtt_sample{
            latest_rtt_.us(), smoothed_rtt_.us(),
            min_rtt_.IsFinite() ? min_rtt_.us() : smoothed_rtt_.us(),
            rttvar_.us()};
        cc_->OnCongestionEvent(now.us(), prior_in_flight, bytes_in_flight_,
                               rtt_sample, {}, lost_vec);
      }
    }
  }

  std::vector<QuicLostPacket> DetectLostPacketsInSpace(
      QuicEncryptionLevel level,
      Timestamp now) {
    std::vector<QuicLostPacket> lost_vec;
    const size_t idx = LevelIndex(level);
    if (largest_acked_pn_[idx] < 0) {
      return lost_vec;
    }
    const uint64_t largest_acked =
        static_cast<uint64_t>(largest_acked_pn_[idx]);
    const TimeDelta max_rtt = std::max(latest_rtt_, smoothed_rtt_);
    const TimeDelta loss_delay =
        std::max(TimeDelta::Millis(2),
                 TimeDelta::Micros((max_rtt.us() * 9) / 8));

    auto& sent_map = sent_packets_[idx];
    uint32_t newly_lost_pkts = 0;

    const uint64_t pkt_reordering_thresh = std::clamp<uint64_t>(
        3 + static_cast<uint64_t>(std::max<int64_t>(0, rttvar_.ms()) / 5), 3,
        20);
    for (auto it = sent_map.begin(); it != sent_map.end();) {
      if (it->first > largest_acked) {
        break;
      }
      const bool pkt_threshold_lost =
          (largest_acked >= it->first + pkt_reordering_thresh);
      const bool time_threshold_lost =
          ((now - it->second.sent_time) >=
           (loss_delay + rttvar_));
      if (pkt_threshold_lost || time_threshold_lost) {
        if (it->second.in_flight) {
          bytes_in_flight_ =
              (bytes_in_flight_ >= it->second.sent_bytes)
                  ? (bytes_in_flight_ - it->second.sent_bytes)
                  : 0;
          ++total_packets_lost_;
          ++newly_lost_pkts;
          lost_vec.push_back(QuicLostPacket{
              it->second.cc_seq, it->second.sent_bytes,
              it->second.sent_time.us()});
        }
        RequeueRetransmittables(std::move(it->second.frames));
        it = sent_map.erase(it);
      } else {
        ++it;
      }
    }

    if (newly_lost_pkts > 0) {
      UpdateDeliveryRateAndLossWindow(0, 0, newly_lost_pkts, now);
    }
    return lost_vec;
  }

  TimeDelta ComputePtoDuration() const {
    const TimeDelta max_ack_delay =
        handshake_established_
            ? TimeDelta::Millis(static_cast<int64_t>(
                  peer_tp_received_ ? peer_tp_.max_ack_delay_ms : 25))
            : TimeDelta::Millis(5);
    const TimeDelta base =
        smoothed_rtt_ +
        std::max(rttvar_ * 4, TimeDelta::Millis(1)) +
        max_ack_delay;
    const uint32_t shift = std::min<uint32_t>(pto_count_, 6);
    const TimeDelta cap = std::max(TimeDelta::Millis(2000), base);
    return std::min(cap, base * (int64_t{1} << shift));
  }

  void RequeueOldestInFlightForPto() {
    for (QuicEncryptionLevel lvl :
         {QuicEncryptionLevel::kInitial, QuicEncryptionLevel::kHandshake,
          QuicEncryptionLevel::kOneRtt}) {
      auto& sent_map = sent_packets_[LevelIndex(lvl)];
      for (auto it = sent_map.begin(); it != sent_map.end(); ++it) {
        if (it->second.ack_eliciting && !it->second.frames.empty()) {
          // RFC 9002 第 6.2.4 节：PTO 超时仅重排待探测载荷而不从 sent_packets_ 抹除原包记录，
          // 确保链路 RTT 突增时原包随后到达的 ACK 仍能准确采样最新 RTT 并归零 pto_count_。
          RequeueRetransmittables(std::move(it->second.frames));
          it->second.frames.clear();
          break;
        }
      }
    }
  }

  void RequeueRetransmittables(std::vector<SentRetransmittable>&& frames) {
    for (auto& item : frames) {
      item.is_retransmit = true;
      switch (item.kind) {
        case SentRetransmittable::Kind::kCrypto:
          crypto_tx_queue_[LevelIndex(item.crypto_level)].push_front(
              std::move(item));
          break;
        case SentRetransmittable::Kind::kStream: {
          const uint64_t sid = item.stream_chunk.stream_id;
          const auto st_it = outbound_streams_.find(sid);
          if (st_it != outbound_streams_.end()) {
            if (st_it->second.in_flight_frames > 0) {
              --st_it->second.in_flight_frames;
            }
            if (!st_it->second.reset) {
              st_it->second.retransmit_chunks.push_front(
                  std::move(item.stream_chunk));
            } else {
              MaybeEraseCompletedOutboundStream(sid);
            }
          }
          break;
        }
        case SentRetransmittable::Kind::kResetStream:
          pending_resets_.push_front(item.reset_info);
          break;
        case SentRetransmittable::Kind::kStopSending:
          pending_stop_sendings_.push_front(item.stop_sending_info);
          break;
        case SentRetransmittable::Kind::kHandshakeDone:
          pending_handshake_done_ = true;
          break;
        case SentRetransmittable::Kind::kMaxData:
          pending_max_data_ = true;
          pending_max_data_retransmit_ = true;
          break;
        case SentRetransmittable::Kind::kMaxStreamData: {
          const auto in_it = inbound_streams_.find(item.ctrl_stream_id);
          if (in_it != inbound_streams_.end() && !in_it->second.is_complete()) {
            pending_max_stream_data_sids_.insert(item.ctrl_stream_id);
          }
          break;
        }
        case SentRetransmittable::Kind::kMaxStreamsBidi:
          pending_max_streams_bidi_ = true;
          break;
        case SentRetransmittable::Kind::kMaxStreamsUni:
          pending_max_streams_uni_ = true;
          break;
        case SentRetransmittable::Kind::kRetireConnectionId:
          pending_retire_cids_.push_front(item.ctrl_value);
          break;
      }
    }
  }

  // ---------------- 出站数据包组装与优先级调度器 ----------------

  std::vector<uint8_t> BuildUnmaskedHeaderPrefix(QuicEncryptionLevel level) const {
    std::vector<uint8_t> prefix;
    if (level == QuicEncryptionLevel::kOneRtt) {
      prefix.push_back(0x43u);
      prefix.insert(prefix.end(), peer_dcid_.begin(), peer_dcid_.end());
      return prefix;
    }

    const uint8_t long_type =
        (level == QuicEncryptionLevel::kInitial) ? 0x00u : 0x02u;
    prefix.push_back(static_cast<uint8_t>(0xC0u | (long_type << 4) | 0x03u));
    uint8_t ver[4];
    WriteBigEndian32(ver, kQuicVersion1);
    prefix.insert(prefix.end(), ver, ver + 4);
    prefix.push_back(static_cast<uint8_t>(peer_dcid_.size()));
    prefix.insert(prefix.end(), peer_dcid_.begin(), peer_dcid_.end());
    prefix.push_back(static_cast<uint8_t>(local_scid_.size()));
    prefix.insert(prefix.end(), local_scid_.begin(), local_scid_.end());
    if (level == QuicEncryptionLevel::kInitial) {
      prefix.push_back(0x00u);  // 令牌长度（Token Length）= 0
    }
    return prefix;
  }

  size_t AntiAmplificationBudgetBytes() const {
    if (!is_server_ || peer_address_validated_) {
      return std::numeric_limits<size_t>::max();
    }
    const size_t limit = pre_hs_rx_bytes_ * 3;
    return (limit > pre_hs_tx_bytes_) ? (limit - pre_hs_tx_bytes_) : 0;
  }

  void PushBackUnsentRetransmittables(std::vector<SentRetransmittable>&& frames) {
    for (auto it = frames.rbegin(); it != frames.rend(); ++it) {
      auto& item = *it;
      switch (item.kind) {
        case SentRetransmittable::Kind::kCrypto:
          crypto_tx_queue_[LevelIndex(item.crypto_level)].push_front(
              std::move(item));
          break;
        case SentRetransmittable::Kind::kStream: {
          const uint64_t sid = item.stream_chunk.stream_id;
          const auto st_it = outbound_streams_.find(sid);
          if (st_it != outbound_streams_.end()) {
            if (st_it->second.in_flight_frames > 0) {
              --st_it->second.in_flight_frames;
            }
            if (!st_it->second.reset) {
              st_it->second.retransmit_chunks.push_front(
                  std::move(item.stream_chunk));
            }
          }
          break;
        }
        case SentRetransmittable::Kind::kResetStream:
          pending_resets_.push_front(item.reset_info);
          break;
        case SentRetransmittable::Kind::kStopSending:
          pending_stop_sendings_.push_front(item.stop_sending_info);
          break;
        case SentRetransmittable::Kind::kHandshakeDone:
          pending_handshake_done_ = true;
          break;
        case SentRetransmittable::Kind::kMaxData:
          pending_max_data_ = true;
          break;
        case SentRetransmittable::Kind::kMaxStreamData:
          pending_max_stream_data_sids_.insert(item.ctrl_stream_id);
          break;
        case SentRetransmittable::Kind::kMaxStreamsBidi:
          pending_max_streams_bidi_ = true;
          break;
        case SentRetransmittable::Kind::kMaxStreamsUni:
          pending_max_streams_uni_ = true;
          break;
        case SentRetransmittable::Kind::kRetireConnectionId:
          pending_retire_cids_.push_front(item.ctrl_value);
          break;
      }
    }
  }

  bool EmitSinglePacket(QuicEncryptionLevel level,
                        ArrayView<const uint8_t> frames_payload,
                        bool ack_eliciting,
                        std::vector<SentRetransmittable>&& tracked_frames,
                        Timestamp now,
                        size_t custom_min_dgram = 0) {
    const size_t idx = LevelIndex(level);
    if (!tx_keys_[idx].valid || frames_payload.empty()) {
      PushBackUnsentRetransmittables(std::move(tracked_frames));
      return false;
    }

    const auto hdr_prefix = BuildUnmaskedHeaderPrefix(level);
    size_t min_dgram = custom_min_dgram;
    if (!is_server_ && level == QuicEncryptionLevel::kInitial) {
      min_dgram = std::max(min_dgram, kQuicMinClientInitialSize);
    }

    const uint64_t pn = next_tx_pn_[idx];
    const auto wire_pkt = QuicCryptoUtils::ProtectPacket(
        tx_keys_[idx], pn, hdr_prefix, level != QuicEncryptionLevel::kOneRtt,
        frames_payload, min_dgram);
    if (wire_pkt.empty()) {
      PushBackUnsentRetransmittables(std::move(tracked_frames));
      return false;
    }

    // RFC 9000 第 8.1 节：对端地址验证完成前严格执行 3 倍抗放大上限，若预算不足则无损回退待发帧，绝不丢弃 CRYPTO 数据。
    if (is_server_ && !peer_address_validated_ &&
        wire_pkt.size() > AntiAmplificationBudgetBytes()) {
      PushBackUnsentRetransmittables(std::move(tracked_frames));
      return false;
    }
    ++next_tx_pn_[idx];

    const size_t prior_in_flight = bytes_in_flight_;
    const size_t cur_cwnd =
        cc_ ? cc_->GetCongestionWindowBytes() : (10 * kQuicMaxDatagramSize);
    if (prior_in_flight == 0 && ack_eliciting) {
      conn_first_sent_time_us_ = now.us();
      conn_delivered_time_us_ = now.us();
    }

    const uint64_t cc_seq = next_cc_seq_++;
    bool contains_retransmit = false;
    for (const auto& frm : tracked_frames) {
      if (frm.is_retransmit) {
        contains_retransmit = true;
        break;
      }
    }

    SentPacketInfo info;
    info.pn = pn;
    info.cc_seq = cc_seq;
    info.sent_time = now;
    info.sent_bytes = wire_pkt.size();
    info.prior_in_flight_bytes = prior_in_flight;
    info.delivered_bytes_at_send = conn_delivered_bytes_;
    info.delivered_time_us_at_send =
        (conn_delivered_time_us_ > 0) ? conn_delivered_time_us_ : now.us();
    info.first_sent_time_us_at_send =
        (conn_first_sent_time_us_ > 0) ? conn_first_sent_time_us_ : now.us();
    info.is_app_limited =
        (prior_in_flight + 3 * kQuicMaxDatagramSize < cur_cwnd) &&
        (prior_in_flight * 2 < cur_cwnd);
    info.ack_eliciting = ack_eliciting;
    info.in_flight = ack_eliciting;
    info.frames = std::move(tracked_frames);
    if (info.in_flight) {
      bytes_in_flight_ += info.sent_bytes;
      last_ack_eliciting_tx_time_ = now;
    }
    if (cc_) {
      cc_->OnPacketSent(now.us(), cc_seq, info.sent_bytes, info.in_flight,
                        prior_in_flight);
    }
    ++total_packets_sent_;
    if (contains_retransmit) {
      ++total_packets_retransmitted_;
    }
    if (info.ack_eliciting || info.in_flight) {
      sent_packets_[idx].emplace(pn, std::move(info));
    }
    if (is_server_ && !peer_address_validated_) {
      pre_hs_tx_bytes_ += wire_pkt.size();
    }

    events_->SendUdpDatagram(wire_pkt);
    return true;
  }

  bool FlushInitialOrHandshakeSpace(QuicEncryptionLevel level,
                                    Timestamp now,
                                    bool force_ping_probe) {
    const size_t idx = LevelIndex(level);
    if (!tx_keys_[idx].valid) {
      return false;
    }

    const auto hdr_prefix = BuildUnmaskedHeaderPrefix(level);
    const size_t base_wire_overhead =
        hdr_prefix.size() + 2 + 4 + kQuicAeadTagLength;

    bool emitted_any_ack_eliciting = false;
    bool emitted_any = false;
    while (ack_sets_[idx].needs_ack() || !crypto_tx_queue_[idx].empty() ||
           force_ping_probe) {
      const size_t amp_budget = AntiAmplificationBudgetBytes();
      if (amp_budget < base_wire_overhead + 16) {
        break;
      }
      const size_t max_pt_by_amp =
          (amp_budget == std::numeric_limits<size_t>::max())
              ? 980
              : std::min<size_t>(980, amp_budget - base_wire_overhead);

      std::vector<uint8_t> payload;
      std::vector<SentRetransmittable> tracked;
      bool ack_eliciting = false;
      bool consumed_ack = false;

      if (ack_sets_[idx].needs_ack()) {
        const uint64_t delay_us =
            last_rx_pn_time_[idx].IsFinite()
                ? static_cast<uint64_t>(
                      std::max<int64_t>(0, (now - last_rx_pn_time_[idx]).us()))
                : 0;
        ack_sets_[idx].EncodeAckFrame(delay_us, &payload);
        if (payload.size() > max_pt_by_amp) {
          break;
        }
        ack_sets_[idx].ClearAckNeeded();
        consumed_ack = true;
      }

      while (!crypto_tx_queue_[idx].empty() &&
             payload.size() + 12 < max_pt_by_amp && payload.size() < 950) {
        const size_t max_chunk = max_pt_by_amp - payload.size() - 10;
        if (max_chunk == 0) {
          break;
        }
        auto item = std::move(crypto_tx_queue_[idx].front());
        crypto_tx_queue_[idx].pop_front();
        if (item.data.size() > max_chunk) {
          SentRetransmittable rem;
          rem.kind = SentRetransmittable::Kind::kCrypto;
          rem.is_retransmit = item.is_retransmit;
          rem.crypto_level = level;
          rem.offset = item.offset + max_chunk;
          rem.data.assign(item.data.begin() + static_cast<ptrdiff_t>(max_chunk),
                          item.data.end());
          item.data.resize(max_chunk);
          crypto_tx_queue_[idx].push_front(std::move(rem));
        }

        QuicVarInt::Append(kFrameCrypto, &payload);
        QuicVarInt::Append(item.offset, &payload);
        QuicVarInt::Append(item.data.size(), &payload);
        payload.insert(payload.end(), item.data.begin(), item.data.end());
        ack_eliciting = true;
        tracked.push_back(std::move(item));
      }

      if (force_ping_probe) {
        force_ping_probe = false;
        if (!ack_eliciting) {
          QuicVarInt::Append(kFramePing, &payload);
          ack_eliciting = true;
          ++total_packets_retransmitted_;
        }
      }

      if (payload.empty()) {
        break;
      }

      size_t min_dgram = 0;
      if (is_server_ && level == QuicEncryptionLevel::kInitial &&
          ack_eliciting) {
        size_t hs_queued_wire = 0;
        const size_t hs_idx = LevelIndex(QuicEncryptionLevel::kHandshake);
        if (tx_keys_[hs_idx].valid) {
          for (const auto& q : crypto_tx_queue_[hs_idx]) {
            hs_queued_wire += q.data.size() + 64;
          }
        }
        if (amp_budget >= kQuicMinClientInitialSize + hs_queued_wire) {
          min_dgram = kQuicMinClientInitialSize;
        } else if (amp_budget > hs_queued_wire + base_wire_overhead + payload.size()) {
          min_dgram = std::min(kQuicMinClientInitialSize,
                               amp_budget - hs_queued_wire);
        }
      }

      if (!EmitSinglePacket(level, payload, ack_eliciting, std::move(tracked),
                            now, min_dgram)) {
        if (consumed_ack) {
          ack_sets_[idx].SetAckNeeded();
        }
        break;
      }
      emitted_any = true;
      if (ack_eliciting) {
        emitted_any_ack_eliciting = true;
      }
    }
    if (emitted_any && !is_server_ && level == QuicEncryptionLevel::kHandshake &&
        rx_keys_[LevelIndex(QuicEncryptionLevel::kInitial)].valid) {
      // RFC 9001 第 4.9.1 节：客户端发送首个 Handshake 包后立即丢弃 Initial 密钥空间。
      DiscardPacketSpace(QuicEncryptionLevel::kInitial);
    }
    return emitted_any_ack_eliciting;
  }

  bool IsOutboundStreamAllowedByPeerLimit(uint64_t stream_id) const {
    const bool is_local_initiated =
        ((stream_id & 0x01u) == (is_server_ ? 1u : 0u));
    if (!is_local_initiated) {
      return true;
    }
    const uint64_t stream_idx = stream_id >> 2;
    const bool is_uni = (stream_id & 0x02u) != 0;
    return is_uni ? (stream_idx < peer_max_streams_uni_)
                  : (stream_idx < peer_max_streams_bidi_);
  }

  OutboundStreamState* SelectHighestPriorityReadyStream() {
    OutboundStreamState* best = nullptr;
    const uint64_t conn_avail =
        (peer_max_data_ > conn_tx_data_sent_)
            ? (peer_max_data_ - conn_tx_data_sent_)
            : 0;
    for (auto& [sid, st] : outbound_streams_) {
      (void)sid;
      if (st.reset) {
        continue;
      }
      if (!st.flow_limit_initialized) {
        st.peer_max_stream_data = InitialPeerStreamMaxData(st.stream_id);
        st.flow_limit_initialized = true;
      }
      const bool has_rtx = !st.retransmit_chunks.empty();
      const bool stream_allowed = IsOutboundStreamAllowedByPeerLimit(st.stream_id);
      const uint64_t stream_avail =
          (st.peer_max_stream_data > st.next_send_offset)
              ? (st.peer_max_stream_data - st.next_send_offset)
              : 0;
      const bool can_send_new_bytes =
          stream_allowed && !st.unsent_data.empty() && conn_avail > 0 &&
          stream_avail > 0;
      const bool can_send_fin_only =
          stream_allowed && st.unsent_data.empty() && st.fin_queued &&
          !st.fin_sent;
      const bool has_work = has_rtx || can_send_new_bytes || can_send_fin_only;
      if (!has_work) {
        continue;
      }
      if (best == nullptr) {
        best = &st;
        continue;
      }
      // 优先调度重传数据，其次按更小的优先级数值（更高优先级），再按更大的 send_order 排序。
      const bool st_has_rtx = !st.retransmit_chunks.empty();
      const bool best_has_rtx = !best->retransmit_chunks.empty();
      if (st_has_rtx != best_has_rtx) {
        if (st_has_rtx) {
          best = &st;
        }
        continue;
      }
      if (st.priority != best->priority) {
        if (st.priority < best->priority) {
          best = &st;
        }
        continue;
      }
      if (st.send_order != best->send_order) {
        if (st.send_order > best->send_order) {
          best = &st;
        }
        continue;
      }
      if (st.stream_id < best->stream_id) {
        best = &st;
      }
    }
    return best;
  }

  static void EncodeStreamFrame(const StreamChunk& chunk,
                                std::vector<uint8_t>* out) {
    uint64_t ftype = kFrameStreamBase | kFrameStreamLenBit;
    if (chunk.offset > 0) {
      ftype |= kFrameStreamOffBit;
    }
    if (chunk.fin) {
      ftype |= kFrameStreamFinBit;
    }
    QuicVarInt::Append(ftype, out);
    QuicVarInt::Append(chunk.stream_id, out);
    if (chunk.offset > 0) {
      QuicVarInt::Append(chunk.offset, out);
    }
    QuicVarInt::Append(chunk.data.size(), out);
    out->insert(out->end(), chunk.data.begin(), chunk.data.end());
  }

  void RefillQuicPacingTokens(Timestamp now) {
    const int64_t pace_bps =
        cc_ ? cc_->GetPacingRateBps(smoothed_rtt_.us()) : 1'500'000;
    const int64_t rate_bytes_per_sec = std::max<int64_t>(6'000, pace_bps / 8);
    // 遵循 RFC 9002 第 7.7 节：在 <250 kbps 超窄带链路上将突发上限收紧为单包 1*MSS，
    // 在常规链路上按 10ms 发送速率动态缩放至 [2*MSS, 10*MSS]。
    const int64_t min_burst =
        (pace_bps < 250'000) ? static_cast<int64_t>(kQuicMaxDatagramSize)
                             : static_cast<int64_t>(2 * kQuicMaxDatagramSize);
    const int64_t max_burst_bytes = std::clamp<int64_t>(
        rate_bytes_per_sec / 100, min_burst,
        static_cast<int64_t>(10 * kQuicMaxDatagramSize));
    if (!last_pacing_refill_.IsFinite()) {
      last_pacing_refill_ = now;
      pacing_tokens_bytes_ = max_burst_bytes;
      return;
    }
    const int64_t delta_us =
        std::clamp<int64_t>((now - last_pacing_refill_).us(), 0, 500'000);
    last_pacing_refill_ = now;
    if (delta_us <= 0) {
      return;
    }
    const int64_t total_byte_us =
        rate_bytes_per_sec * delta_us + pacing_subbyte_rem_;
    const int64_t add_bytes = total_byte_us / 1'000'000;
    pacing_subbyte_rem_ = total_byte_us % 1'000'000;
    pacing_tokens_bytes_ =
        std::min(max_burst_bytes, pacing_tokens_bytes_ + add_bytes);
  }

  void FlushOneRttSpace(Timestamp now, bool pto_probe) {
    const size_t idx = LevelIndex(QuicEncryptionLevel::kOneRtt);
    if (!handshake_established_ || !tx_keys_[idx].valid) {
      return;
    }

    if (peer_tp_received_ && peer_tp_.max_datagram_frame_size == 0) {
      pending_datagrams_.clear();
    }

    RefillQuicPacingTokens(now);

    size_t packets_emitted = 0;
    while (packets_emitted < 64) {
      const size_t cur_cwnd =
          cc_ ? cc_->GetCongestionWindowBytes() : (10 * kQuicMaxDatagramSize);
      const bool has_pacing_budget =
          pto_probe || (pacing_tokens_bytes_ >= static_cast<int64_t>(kQuicMaxDatagramSize)) ||
          (bytes_in_flight_ == 0);
      const bool can_send_in_flight =
          has_pacing_budget &&
          (pto_probe || (bytes_in_flight_ + kQuicMaxDatagramSize <= cur_cwnd) ||
           bytes_in_flight_ == 0);

      const bool need_ack = ack_sets_[idx].needs_ack();
      const bool has_fc_updates =
          pending_max_data_ || !pending_max_stream_data_sids_.empty() ||
          pending_max_streams_bidi_ || pending_max_streams_uni_ ||
          !pending_retire_cids_.empty();
      OutboundStreamState* ready_stream =
          can_send_in_flight ? SelectHighestPriorityReadyStream() : nullptr;
      const bool has_ctrl_frames =
          can_send_in_flight &&
          (pending_handshake_done_ || !pending_path_responses_.empty() ||
           !pending_resets_.empty() || !pending_stop_sendings_.empty() ||
           !pending_datagrams_.empty());

      if (!need_ack && !has_fc_updates && !has_ctrl_frames &&
          ready_stream == nullptr && !pto_probe) {
        break;
      }

      std::vector<uint8_t> payload;
      payload.reserve(kQuicMaxDatagramSize);
      std::vector<SentRetransmittable> tracked;
      bool ack_eliciting = false;
      const size_t kMaxPlaintextBudget =
          kQuicMaxDatagramSize -
          (1 + peer_dcid_.size() + 4 + kQuicAeadTagLength);

      if (need_ack) {
        const uint64_t delay_us =
            last_rx_pn_time_[idx].IsFinite()
                ? static_cast<uint64_t>(
                      std::max<int64_t>(0, (now - last_rx_pn_time_[idx]).us()))
                : 0;
        ack_sets_[idx].EncodeAckFrame(delay_us, &payload);
        ack_sets_[idx].ClearAckNeeded();
      }

      if (pending_max_data_ && payload.size() + 10 <= kMaxPlaintextBudget) {
        pending_max_data_ = false;
        QuicVarInt::Append(kFrameMaxData, &payload);
        QuicVarInt::Append(local_max_data_, &payload);
        SentRetransmittable item;
        item.kind = SentRetransmittable::Kind::kMaxData;
        item.is_retransmit = pending_max_data_retransmit_;
        pending_max_data_retransmit_ = false;
        item.ctrl_value = local_max_data_;
        tracked.push_back(std::move(item));
        ack_eliciting = true;
      }

      if (pending_max_streams_bidi_ &&
          payload.size() + 10 <= kMaxPlaintextBudget) {
        pending_max_streams_bidi_ = false;
        QuicVarInt::Append(kFrameMaxStreamsBidi, &payload);
        QuicVarInt::Append(local_max_streams_bidi_, &payload);
        SentRetransmittable item;
        item.kind = SentRetransmittable::Kind::kMaxStreamsBidi;
        item.ctrl_value = local_max_streams_bidi_;
        tracked.push_back(std::move(item));
        ack_eliciting = true;
      }

      if (pending_max_streams_uni_ &&
          payload.size() + 10 <= kMaxPlaintextBudget) {
        pending_max_streams_uni_ = false;
        QuicVarInt::Append(kFrameMaxStreamsUni, &payload);
        QuicVarInt::Append(local_max_streams_uni_, &payload);
        SentRetransmittable item;
        item.kind = SentRetransmittable::Kind::kMaxStreamsUni;
        item.ctrl_value = local_max_streams_uni_;
        tracked.push_back(std::move(item));
        ack_eliciting = true;
      }

      while (!pending_max_stream_data_sids_.empty() &&
             payload.size() + 18 <= kMaxPlaintextBudget) {
        const uint64_t sid = *pending_max_stream_data_sids_.begin();
        pending_max_stream_data_sids_.erase(pending_max_stream_data_sids_.begin());
        const auto in_it = inbound_streams_.find(sid);
        if (in_it == inbound_streams_.end() || in_it->second.is_complete()) {
          continue;
        }
        const uint64_t max_off = in_it->second.max_receive_offset();
        QuicVarInt::Append(kFrameMaxStreamData, &payload);
        QuicVarInt::Append(sid, &payload);
        QuicVarInt::Append(max_off, &payload);
        SentRetransmittable item;
        item.kind = SentRetransmittable::Kind::kMaxStreamData;
        item.ctrl_stream_id = sid;
        item.ctrl_value = max_off;
        tracked.push_back(std::move(item));
        ack_eliciting = true;
      }

      while (!pending_retire_cids_.empty() &&
             payload.size() + 10 <= kMaxPlaintextBudget) {
        const uint64_t seq = pending_retire_cids_.front();
        pending_retire_cids_.pop_front();
        QuicVarInt::Append(kFrameRetireConnectionId, &payload);
        QuicVarInt::Append(seq, &payload);
        SentRetransmittable item;
        item.kind = SentRetransmittable::Kind::kRetireConnectionId;
        item.ctrl_value = seq;
        tracked.push_back(std::move(item));
        ack_eliciting = true;
      }

      while (can_send_in_flight && !pending_path_responses_.empty() &&
             payload.size() + 10 <= kMaxPlaintextBudget) {
        const auto pr = pending_path_responses_.front();
        pending_path_responses_.pop_front();
        QuicVarInt::Append(kFramePathResponse, &payload);
        payload.insert(payload.end(), pr.begin(), pr.end());
        ack_eliciting = true;
      }

      if (can_send_in_flight && pending_handshake_done_ &&
          payload.size() + 2 <= kMaxPlaintextBudget) {
        pending_handshake_done_ = false;
        QuicVarInt::Append(kFrameHandshakeDone, &payload);
        SentRetransmittable item;
        item.kind = SentRetransmittable::Kind::kHandshakeDone;
        tracked.push_back(std::move(item));
        ack_eliciting = true;
      }

      while (can_send_in_flight && !pending_resets_.empty() &&
             payload.size() + 28 <= kMaxPlaintextBudget) {
        const PendingReset rst = pending_resets_.front();
        pending_resets_.pop_front();
        QuicVarInt::Append(kFrameResetStream, &payload);
        QuicVarInt::Append(rst.stream_id, &payload);
        QuicVarInt::Append(rst.app_error_code, &payload);
        QuicVarInt::Append(rst.final_size, &payload);

        SentRetransmittable item;
        item.kind = SentRetransmittable::Kind::kResetStream;
        item.reset_info = rst;
        tracked.push_back(std::move(item));
        ack_eliciting = true;
      }

      while (can_send_in_flight && !pending_stop_sendings_.empty() &&
             payload.size() + 20 <= kMaxPlaintextBudget) {
        const PendingStopSending ss = pending_stop_sendings_.front();
        pending_stop_sendings_.pop_front();
        QuicVarInt::Append(kFrameStopSending, &payload);
        QuicVarInt::Append(ss.stream_id, &payload);
        QuicVarInt::Append(ss.app_error_code, &payload);

        SentRetransmittable item;
        item.kind = SentRetransmittable::Kind::kStopSending;
        item.stop_sending_info = ss;
        tracked.push_back(std::move(item));
        ack_eliciting = true;
      }

      // RFC 9221 不可靠数据报帧（0x31）：参与拥塞控制与 RTT 采样，但丢包后绝不重传。
      while (can_send_in_flight && !pending_datagrams_.empty()) {
        const auto& dg = pending_datagrams_.front();
        if (payload.size() + 4 + dg.size() > kMaxPlaintextBudget) {
          if (payload.empty()) {
            pending_datagrams_.pop_front();
            continue;
          }
          break;
        }
        QuicVarInt::Append(kFrameDatagramLen, &payload);
        QuicVarInt::Append(dg.size(), &payload);
        payload.insert(payload.end(), dg.begin(), dg.end());
        pending_datagrams_.pop_front();
        ack_eliciting = true;
      }

      while (can_send_in_flight &&
             payload.size() + 32 < kMaxPlaintextBudget) {
        OutboundStreamState* st = SelectHighestPriorityReadyStream();
        if (st == nullptr) {
          break;
        }
        const size_t max_data_slice = kMaxPlaintextBudget - payload.size() - 24;
        StreamChunk chunk;
        chunk.stream_id = st->stream_id;
        bool chunk_is_retransmit = false;

        if (!st->retransmit_chunks.empty()) {
          chunk_is_retransmit = true;
          chunk = std::move(st->retransmit_chunks.front());
          st->retransmit_chunks.pop_front();
          if (chunk.data.size() > max_data_slice) {
            StreamChunk rem;
            rem.stream_id = chunk.stream_id;
            rem.offset = chunk.offset + max_data_slice;
            rem.data.assign(
                chunk.data.begin() + static_cast<ptrdiff_t>(max_data_slice),
                chunk.data.end());
            rem.fin = chunk.fin;
            chunk.data.resize(max_data_slice);
            chunk.fin = false;
            st->retransmit_chunks.push_front(std::move(rem));
          }
        } else {
          const uint64_t conn_avail =
              (peer_max_data_ > conn_tx_data_sent_)
                  ? (peer_max_data_ - conn_tx_data_sent_)
                  : 0;
          const uint64_t stream_avail =
              (st->peer_max_stream_data > st->next_send_offset)
                  ? (st->peer_max_stream_data - st->next_send_offset)
                  : 0;
          const uint64_t fc_avail = std::min(conn_avail, stream_avail);
          chunk.offset = st->next_send_offset;
          const size_t take = std::min(
              {st->unsent_data.size(), max_data_slice,
               static_cast<size_t>(std::min<uint64_t>(fc_avail, max_data_slice))});
          chunk.data.assign(
              st->unsent_data.begin(),
              st->unsent_data.begin() + static_cast<ptrdiff_t>(take));
          st->unsent_data.erase(
              st->unsent_data.begin(),
              st->unsent_data.begin() + static_cast<ptrdiff_t>(take));
          st->next_send_offset += take;
          conn_tx_data_sent_ += take;
          if (st->unsent_data.empty() && st->fin_queued && !st->fin_sent) {
            chunk.fin = true;
            st->fin_sent = true;
          }
        }

        EncodeStreamFrame(chunk, &payload);
        ++st->in_flight_frames;
        SentRetransmittable item;
        item.kind = SentRetransmittable::Kind::kStream;
        item.is_retransmit = chunk_is_retransmit;
        item.stream_chunk = std::move(chunk);
        tracked.push_back(std::move(item));
        ack_eliciting = true;
      }

      if (payload.empty() && pto_probe) {
        QuicVarInt::Append(kFramePing, &payload);
        ack_eliciting = true;
        ++total_packets_retransmitted_;
      }

      if (payload.empty()) {
        break;
      }

      const size_t approx_wire_len = payload.size() + 28;
      EmitSinglePacket(QuicEncryptionLevel::kOneRtt, payload, ack_eliciting,
                       std::move(tracked), now);
      if (ack_eliciting && !pto_probe) {
        pacing_tokens_bytes_ = std::max<int64_t>(
            -static_cast<int64_t>(kQuicMaxDatagramSize),
            pacing_tokens_bytes_ - static_cast<int64_t>(approx_wire_len));
      }
      ++packets_emitted;
      if (pto_probe) {
        break;
      }
    }
  }

  void FlushPackets(Timestamp now, bool pto_probe) {
    bool sent_pre_hs =
        FlushInitialOrHandshakeSpace(QuicEncryptionLevel::kInitial, now, false);
    if (FlushInitialOrHandshakeSpace(QuicEncryptionLevel::kHandshake, now,
                                     false)) {
      sent_pre_hs = true;
    }
    if (pto_probe && !handshake_established_ && !sent_pre_hs) {
      // RFC 9002 第 6.2.2.1 与 6.2.4 节：握手完成前 PTO 触发但重传队列为空时发送 PING 探测包。
      if (tx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].valid) {
        FlushInitialOrHandshakeSpace(QuicEncryptionLevel::kHandshake, now,
                                     true);
      } else if (tx_keys_[LevelIndex(QuicEncryptionLevel::kInitial)].valid) {
        FlushInitialOrHandshakeSpace(QuicEncryptionLevel::kInitial, now, true);
      }
    }
    FlushOneRttSpace(now, pto_probe);
  }

  Clock* const clock_;
  const bool is_server_;
  const QuicCid local_scid_;
  QuicCid peer_dcid_;
  const QuicCid initial_dcid_;
  bool peer_scid_learned_ = false;
  const std::vector<std::string> supported_alpns_;
  std::string negotiated_alpn_;
  QuicSessionEvents* const events_;
  std::shared_ptr<QuicServerCertContext> server_cert_;
  std::string client_sni_host_;
  QuicTlsVerifyConfig tls_verify_cfg_;

  QuicTransportParameters local_tp_;
  QuicTransportParameters peer_tp_;
  bool peer_tp_received_ = false;

  // RFC 9000 双向流量控制、并发流数限制与对端连接 ID 轮换状态。
  uint64_t local_max_data_ = 16 * 1024 * 1024;
  uint64_t conn_rx_highest_total_ = 0;
  uint64_t conn_rx_consumed_total_ = 0;
  uint64_t local_max_streams_bidi_ = 256;
  uint64_t local_max_streams_uni_ = 16384;
  uint64_t retired_peer_bidi_streams_ = 0;
  uint64_t retired_peer_uni_streams_ = 0;
  uint64_t local_opened_bidi_count_ = 0;
  uint64_t local_opened_uni_count_ = 0;

  uint64_t peer_max_data_ = 16 * 1024 * 1024;
  uint64_t conn_tx_data_sent_ = 0;
  uint64_t peer_max_streams_bidi_ = 256;
  uint64_t peer_max_streams_uni_ = 16384;

  bool pending_max_data_ = false;
  bool pending_max_data_retransmit_ = false;
  bool pending_max_streams_bidi_ = false;
  bool pending_max_streams_uni_ = false;
  std::set<uint64_t> pending_max_stream_data_sids_;
  std::map<uint64_t, QuicCid> peer_cids_;
  uint64_t active_peer_cid_seq_ = 0;
  uint64_t max_retire_prior_to_ = 0;
  std::deque<uint64_t> pending_retire_cids_;

  std::array<uint8_t, 32> initial_secret_{};
  std::array<uint8_t, 32> handshake_root_secret_{};
  std::array<uint8_t, 32> local_x25519_priv_{};
  std::array<uint8_t, 32> local_x25519_pub_{};
  std::array<uint8_t, 32> local_random_{};

  std::vector<uint8_t> client_hello_bytes_;
  std::vector<uint8_t> server_hello_bytes_;
  std::vector<uint8_t> peer_leaf_cert_der_;
  std::vector<std::vector<uint8_t>> peer_cert_chain_der_;
  std::vector<uint8_t> cert_req_context_;
  std::vector<uint8_t> full_hs_transcript_;

  bool server_hello_sent_ = false;
  bool hs_got_encrypted_extensions_ = false;
  bool hs_got_cert_request_ = false;
  bool hs_got_certificate_ = false;
  bool hs_got_cert_verify_ = false;
  bool handshake_established_ = false;
  bool peer_address_validated_ = false;
  bool has_authenticated_rx_ = false;
  bool has_highest_1rtt_pn_ = false;
  uint64_t highest_1rtt_pn_ = 0;
  bool pending_handshake_done_ = false;
  bool closed_ = false;
  size_t pre_hs_rx_bytes_ = 0;
  size_t pre_hs_tx_bytes_ = 0;

  QuicTrafficKeys rx_keys_[3]{};
  QuicTrafficKeys tx_keys_[3]{};
  uint64_t next_tx_pn_[3]{0, 0, 0};
  int64_t largest_acked_pn_[3]{-1, -1, -1};
  QuicAckRangeSet ack_sets_[3]{};
  Timestamp last_rx_pn_time_[3]{Timestamp::MinusInfinity(),
                                Timestamp::MinusInfinity(),
                                Timestamp::MinusInfinity()};

  uint64_t crypto_tx_offset_[3]{0, 0, 0};
  std::deque<SentRetransmittable> crypto_tx_queue_[3]{};
  QuicStreamReceiveBuffer crypto_rx_reassembler_[3]{};
  std::vector<uint8_t> crypto_rx_buf_[3]{};

  std::map<uint64_t, SentPacketInfo> sent_packets_[3]{};
  std::map<uint64_t, OutboundStreamState> outbound_streams_;
  std::set<uint64_t> retired_outbound_streams_;
  std::deque<uint64_t> retired_outbound_order_;
  int64_t max_retired_outbound_local_uni_sid_ = -1;
  int64_t max_retired_outbound_local_bidi_sid_ = -1;
  int64_t max_retired_outbound_peer_bidi_sid_ = -1;
  std::deque<PendingReset> pending_resets_;
  std::deque<PendingStopSending> pending_stop_sendings_;
  std::deque<std::array<uint8_t, 8>> pending_path_responses_;
  std::deque<std::vector<uint8_t>> pending_datagrams_;
  std::map<uint64_t, QuicStreamReceiveBuffer> inbound_streams_;
  std::set<uint64_t> announced_inbound_streams_;
  std::set<uint64_t> retired_inbound_streams_;
  std::deque<uint64_t> retired_inbound_order_;
  int64_t max_retired_peer_uni_sid_ = -1;
  int64_t max_retired_peer_bidi_sid_ = -1;
  int64_t max_retired_local_bidi_sid_ = -1;

  // RFC 9002 RTT 测量、PTO 与拥塞控制器状态。
  bool has_rtt_sample_ = false;
  TimeDelta latest_rtt_ = TimeDelta::Millis(30);
  TimeDelta smoothed_rtt_ = TimeDelta::Millis(30);
  TimeDelta rttvar_ = TimeDelta::Millis(15);
  TimeDelta min_rtt_ = Timestamp::MinusInfinity() - Timestamp::Zero();
  uint32_t pto_count_ = 0;
  Timestamp last_ack_eliciting_tx_time_ = Timestamp::MinusInfinity();
  Timestamp last_rx_time_ = Timestamp::MinusInfinity();

  std::unique_ptr<IQuicCongestionController> cc_;
  size_t bytes_in_flight_ = 0;
  uint64_t conn_delivered_bytes_ = 0;
  int64_t conn_delivered_time_us_ = 0;
  int64_t conn_first_sent_time_us_ = 0;
  uint64_t next_cc_seq_ = 1;
  uint64_t total_packets_sent_ = 0;
  uint64_t total_packets_lost_ = 0;
  uint64_t total_packets_retransmitted_ = 0;

  Timestamp rate_window_start_ = Timestamp::MinusInfinity();
  size_t rate_window_acked_bytes_ = 0;
  int64_t delivery_rate_bps_ = 0;
  uint32_t window_acked_pkts_ = 0;
  uint32_t window_lost_pkts_ = 0;
  double recent_loss_ratio_ = 0.0;

  Timestamp last_pacing_refill_ = Timestamp::MinusInfinity();
  int64_t pacing_tokens_bytes_ = static_cast<int64_t>(10 * kQuicMaxDatagramSize);
  int64_t pacing_subbyte_rem_ = 0;
};

}  // namespace

// ======================= AsioQuicClientEngine 客户端引擎实现 =======================

class AsioQuicClientEngine::Impl final
    : public QuicSessionEvents,
      public std::enable_shared_from_this<AsioQuicClientEngine::Impl> {
 public:
  Impl(Clock* clock,
       TaskQueueBoost* network_queue,
       std::unique_ptr<IQuicCongestionController> initial_cc)
      : clock_(clock),
        network_queue_(network_queue),
        net_checker_(network_queue),
        socket_(network_queue->io_context()),
        rx_buf_(65536),
        pending_cc_(std::move(initial_cc)),
        safety_(PendingTaskSafetyFlag::CreateDetached()) {
    cached_snapshot_.timestamp = clock_->CurrentTime();
    if (pending_cc_) {
      cached_snapshot_.active_cc_name = pending_cc_->Name();
    }
  }

  void SetObserver(IMoqQuicEngineObserver* observer) {
    observer_.store(observer, std::memory_order_release);
  }

  void SetTlsVerifyConfig(bool verify_peer,
                          std::string ca_cert_path,
                          std::string pinned_cert_sha256) {
    QuicTlsVerifyConfig cfg{verify_peer, std::move(ca_cert_path),
                            std::move(pinned_cert_sha256)};
    {
      std::lock_guard<std::mutex> lock(snap_mutex_);
      tls_verify_cfg_ = cfg;
    }
    if (!network_queue_->IsStopped()) {
      auto self = shared_from_this();
      network_queue_->PostTask(SafeTask(safety_.flag(), [self, cfg]() {
        RTC_DCHECK_RUN_ON(&self->net_checker_);
        if (self->core_) {
          self->core_->SetTlsVerifyConfig(cfg);
        }
      }));
    }
  }

  void SetSimulatedDropRates(double tx_drop, double rx_drop) {
    tx_drop_prob_.store(tx_drop, std::memory_order_release);
    rx_drop_prob_.store(rx_drop, std::memory_order_release);
  }

  int SetCongestionController(
      std::unique_ptr<IQuicCongestionController> controller) {
    if (!controller) {
      return RTC_ERR_INVALID_ARG;
    }
    if (network_queue_->IsStopped()) {
      return RTC_ERR_NOT_INITIALIZED;
    }
    auto shared_cc =
        std::make_shared<std::unique_ptr<IQuicCongestionController>>(
            std::move(controller));
    auto self = shared_from_this();
    network_queue_->PostTask(SafeTask(safety_.flag(), [self, shared_cc]() {
      RTC_DCHECK_RUN_ON(&self->net_checker_);
      if (self->core_ && !self->core_->is_closed()) {
        self->core_->HotSwapCongestionController(std::move(*shared_cc),
                                                 self->clock_->CurrentTime());
        self->UpdateCachedSnapshot();
      } else {
        self->pending_cc_ = std::move(*shared_cc);
        if (self->pending_cc_) {
          std::lock_guard<std::mutex> lock(self->snap_mutex_);
          self->cached_snapshot_.active_cc_name = self->pending_cc_->Name();
        }
      }
    }));
    return RTC_OK;
  }

  int Connect(const std::string& host, uint16_t port, const std::string& alpn) {
    if (host.empty() || port == 0) {
      return RTC_ERR_INVALID_ARG;
    }
    if (network_queue_->IsStopped()) {
      return RTC_ERR_NOT_INITIALIZED;
    }
    {
      std::lock_guard<std::mutex> lock(api_stream_mutex_);
      api_closed_ = false;
      api_handshake_done_ = false;
      api_closed_sids_.clear();
      api_buffered_bytes_.clear();
    }
    max_dgram_payload_.store(kQuicMaxDatagramSize - 32,
                             std::memory_order_release);
    {
      std::lock_guard<std::mutex> lock(snap_mutex_);
      cached_alpn_.clear();
    }

    auto self = shared_from_this();
    network_queue_->PostTask(
        SafeTask(safety_.flag(), [self, host, port, alpn]() {
          RTC_DCHECK_RUN_ON(&self->net_checker_);
          std::string clean_host = host;
          if (clean_host.size() >= 2 && clean_host.front() == '[' &&
              clean_host.back() == ']') {
            clean_host = clean_host.substr(1, clean_host.size() - 2);
          }

          // IP 字面量（如 127.0.0.1 / ::1）同步直连快路径，彻底消除异步解析空窗。
          boost::system::error_code ip_ec;
          const auto literal_addr =
              boost::asio::ip::make_address(clean_host, ip_ec);
          if (!ip_ec) {
            self->FinishEndpointSetupAndStartHandshake(
                boost::asio::ip::udp::endpoint(literal_addr, port), clean_host,
                alpn);
            return;
          }

          self->resolver_ = std::make_unique<boost::asio::ip::udp::resolver>(
              self->network_queue_->io_context());
          self->resolver_->async_resolve(
              clean_host, std::to_string(port),
              SafeTask(
                  self->safety_.flag(),
                  [self, host, clean_host, port, alpn](
                      const boost::system::error_code& ec,
                      boost::asio::ip::udp::resolver::results_type endpoints) {
                    RTC_DCHECK_RUN_ON(&self->net_checker_);
                    if (ec || endpoints.begin() == endpoints.end()) {
                      RTC_LOG(kError)
                          << "QUIC DNS/endpoint resolve failed for " << host
                          << ":" << port << " (" << ec.message() << ")";
                      {
                        std::lock_guard<std::mutex> lock(
                            self->api_stream_mutex_);
                        self->api_closed_ = true;
                      }
                      self->pending_ops_.clear();
                      if (auto* obs =
                              self->observer_.load(std::memory_order_acquire)) {
                        obs->OnQuicDisconnected(-101);
                      }
                      return;
                    }
                    boost::asio::ip::udp::endpoint chosen_ep =
                        *endpoints.begin();
                    for (const auto& entry : endpoints) {
                      if (entry.endpoint().address().is_v4()) {
                        chosen_ep = entry.endpoint();
                        break;
                      }
                    }
                    self->FinishEndpointSetupAndStartHandshake(
                        chosen_ep, clean_host, alpn);
                  }));
        }));
    return 0;
  }

  void Close(uint64_t app_error_code) {
    {
      std::lock_guard<std::mutex> lock(api_stream_mutex_);
      api_closed_ = true;
      api_closed_sids_.clear();
      api_buffered_bytes_.clear();
    }
    if (network_queue_->IsStopped()) {
      return;
    }
    network_queue_->Invoke([this, app_error_code]() {
      RTC_DCHECK_RUN_ON(&net_checker_);
      safety_.flag()->SetNotAlive();
      safety_.Reset(PendingTaskSafetyFlag::CreateDetached());
      pending_ops_.clear();
      if (resolver_) {
        resolver_->cancel();
        resolver_.reset();
      }
      auto local_core = std::move(core_);
      if (local_core && !local_core->is_closed()) {
        local_core->CloseConnection(app_error_code);
      }
      boost::system::error_code ec;
      socket_.close(ec);
      next_bidi_id_.store(0, std::memory_order_relaxed);
      next_uni_id_.store(2, std::memory_order_relaxed);
    });
  }

  uint64_t OpenBidirectionalStream() {
    const uint64_t id = next_bidi_id_.fetch_add(4, std::memory_order_relaxed);
    auto self = shared_from_this();
    network_queue_->PostTask(SafeTask(safety_.flag(), [self, id]() {
      RTC_DCHECK_RUN_ON(&self->net_checker_);
      if (self->core_) {
        self->core_->RegisterOutboundStream(
            id, 0, std::numeric_limits<int64_t>::max());
      } else {
        PendingPreConnectOp op;
        op.kind = PendingPreConnectOp::Kind::kRegisterStream;
        op.stream_id = id;
        op.priority = 0;
        op.send_order = std::numeric_limits<int64_t>::max();
        self->EnqueuePreConnectOp(std::move(op));
      }
    }));
    return id;
  }

  uint64_t OpenUnidirectionalStream(uint8_t publisher_priority,
                                    int64_t send_order) {
    const uint64_t id = next_uni_id_.fetch_add(4, std::memory_order_relaxed);
    auto self = shared_from_this();
    network_queue_->PostTask(
        SafeTask(safety_.flag(), [self, id, publisher_priority, send_order]() {
          RTC_DCHECK_RUN_ON(&self->net_checker_);
          if (self->core_) {
            self->core_->RegisterOutboundStream(id, publisher_priority,
                                                send_order);
          } else {
            PendingPreConnectOp op;
            op.kind = PendingPreConnectOp::Kind::kRegisterStream;
            op.stream_id = id;
            op.priority = publisher_priority;
            op.send_order = send_order;
            self->EnqueuePreConnectOp(std::move(op));
          }
        }));
    return id;
  }

  int WriteStream(uint64_t stream_id, ArrayView<const uint8_t> data, bool fin) {
    if (network_queue_->IsStopped()) {
      return RTC_ERR_NOT_INITIALIZED;
    }
    // 客户端严禁向服务端发起的单向流（0x03）写入数据。
    if ((stream_id & 0x03u) == 0x03u) {
      return RTC_ERR_INVALID_ARG;
    }
    constexpr size_t kMaxOutboundStreamBufferBytes = 16 * 1024 * 1024;
    {
      std::lock_guard<std::mutex> lock(api_stream_mutex_);
      if (api_closed_) {
        return RTC_ERR_NOT_CONNECTED;
      }
      if (api_closed_sids_.count(stream_id) > 0) {
        return RTC_ERR_INVALID_ARG;
      }
      size_t& cur_buf = api_buffered_bytes_[stream_id];
      if (data.size() > kMaxOutboundStreamBufferBytes ||
          cur_buf > kMaxOutboundStreamBufferBytes - data.size()) {
        return RTC_ERR_NO_MEMORY;
      }
      cur_buf += data.size();
      if (fin) {
        RecordApiClosedSidLocked(stream_id);
      }
    }

    std::vector<uint8_t> copy(data.begin(), data.end());
    auto self = shared_from_this();
    network_queue_->PostTask(SafeTask(
        safety_.flag(), [self, stream_id, buf = std::move(copy), fin]() {
          RTC_DCHECK_RUN_ON(&self->net_checker_);
          if (self->core_) {
            self->core_->WriteStream(stream_id, buf, fin);
            self->SyncApiStreamBytes(stream_id);
            self->UpdateCachedSnapshot();
          } else {
            PendingPreConnectOp op;
            op.kind = PendingPreConnectOp::Kind::kWriteStream;
            op.stream_id = stream_id;
            op.data = buf;
            op.fin = fin;
            self->EnqueuePreConnectOp(std::move(op));
          }
        }));
    return static_cast<int>(data.size());
  }

  void ResetStream(uint64_t stream_id, uint64_t app_error_code) {
    if ((stream_id & 0x03u) == 0x03u) {
      return;
    }
    {
      std::lock_guard<std::mutex> lock(api_stream_mutex_);
      RecordApiClosedSidLocked(stream_id);
      api_buffered_bytes_.erase(stream_id);
    }
    auto self = shared_from_this();
    network_queue_->PostTask(
        SafeTask(safety_.flag(), [self, stream_id, app_error_code]() {
          RTC_DCHECK_RUN_ON(&self->net_checker_);
          if (self->core_) {
            self->core_->ResetStream(stream_id, app_error_code);
          } else {
            PendingPreConnectOp op;
            op.kind = PendingPreConnectOp::Kind::kResetStream;
            op.stream_id = stream_id;
            op.app_error_code = app_error_code;
            self->EnqueuePreConnectOp(std::move(op));
          }
        }));
  }

  void StopSending(uint64_t stream_id, uint64_t app_error_code) {
    // 客户端本地单向流（0x02）不存在接收端，不可发送 STOP_SENDING。
    if ((stream_id & 0x03u) == 0x02u) {
      return;
    }
    auto self = shared_from_this();
    network_queue_->PostTask(
        SafeTask(safety_.flag(), [self, stream_id, app_error_code]() {
          RTC_DCHECK_RUN_ON(&self->net_checker_);
          if (self->core_) {
            self->core_->StopSending(stream_id, app_error_code);
          } else {
            PendingPreConnectOp op;
            op.kind = PendingPreConnectOp::Kind::kStopSending;
            op.stream_id = stream_id;
            op.app_error_code = app_error_code;
            self->EnqueuePreConnectOp(std::move(op));
          }
        }));
  }

  int SendDatagram(ArrayView<const uint8_t> data) {
    {
      std::lock_guard<std::mutex> lock(api_stream_mutex_);
      if (api_closed_) {
        return RTC_ERR_NOT_CONNECTED;
      }
    }
    const size_t max_sz = max_datagram_size();
    if (max_sz == 0) {
      return RTC_ERR_PROTOCOL;
    }
    if (data.size() > max_sz) {
      return RTC_ERR_INVALID_ARG;
    }
    std::vector<uint8_t> copy(data.begin(), data.end());
    auto self = shared_from_this();
    network_queue_->PostTask(
        SafeTask(safety_.flag(), [self, buf = std::move(copy)]() {
          RTC_DCHECK_RUN_ON(&self->net_checker_);
          if (self->core_) {
            self->core_->SendDatagram(buf);
            self->UpdateCachedSnapshot();
          } else {
            PendingPreConnectOp op;
            op.kind = PendingPreConnectOp::Kind::kSendDatagram;
            op.data = buf;
            self->EnqueuePreConnectOp(std::move(op));
          }
        }));
    return RTC_OK;
  }

  size_t max_datagram_size() const {
    return max_dgram_payload_.load(std::memory_order_acquire);
  }

  std::string negotiated_alpn() const {
    std::lock_guard<std::mutex> lock(snap_mutex_);
    return cached_alpn_;
  }

  QuicCongestionSnapshot GetCongestionSnapshot() const {
    std::lock_guard<std::mutex> lock(snap_mutex_);
    return cached_snapshot_;
  }

  // QuicSessionEvents 接口重写：
  void SendUdpDatagram(ArrayView<const uint8_t> bytes) override {
    if (!socket_.is_open()) {
      return;
    }
    if (ShouldSimulateDrop(tx_drop_prob_.load(std::memory_order_relaxed))) {
      return;
    }
    boost::system::error_code ec;
    socket_.send_to(boost::asio::buffer(bytes.data(), bytes.size()),
                    remote_endpoint_, 0, ec);
  }

  void OnHandshakeEstablished() override {
    RTC_LOG(kInfo) << "AsioQuicClientEngine QUIC v1 1-RTT handshake established"
                   << " with " << remote_endpoint_.address().to_string() << ":"
                   << remote_endpoint_.port();
    {
      std::lock_guard<std::mutex> lock(api_stream_mutex_);
      api_handshake_done_ = true;
    }
    UpdateCachedSnapshot();
    if (auto* obs = observer_.load(std::memory_order_acquire)) {
      obs->OnQuicConnected();
    }
  }

  void OnConnectionClosed(int error_code) override {
    {
      std::lock_guard<std::mutex> lock(api_stream_mutex_);
      api_closed_ = true;
      api_buffered_bytes_.clear();
    }
    if (auto* obs = observer_.load(std::memory_order_acquire)) {
      obs->OnQuicDisconnected(error_code);
    }
  }

  void OnPeerStreamOpened(uint64_t stream_id, bool unidirectional) override {
    if (auto* obs = observer_.load(std::memory_order_acquire)) {
      obs->OnStreamOpened(stream_id, unidirectional);
    }
  }

  void OnPeerStreamData(uint64_t stream_id,
                        ArrayView<const uint8_t> data,
                        bool fin) override {
    if (auto* obs = observer_.load(std::memory_order_acquire)) {
      obs->OnStreamData(stream_id, data, fin);
    }
  }

  void OnPeerStreamReset(uint64_t stream_id, uint64_t app_error_code) override {
    if (auto* obs = observer_.load(std::memory_order_acquire)) {
      obs->OnStreamReset(stream_id, app_error_code);
    }
  }

  void OnPeerStopSending(uint64_t stream_id, uint64_t app_error_code) override {
    {
      std::lock_guard<std::mutex> lock(api_stream_mutex_);
      RecordApiClosedSidLocked(stream_id);
      api_buffered_bytes_.erase(stream_id);
    }
    if (auto* obs = observer_.load(std::memory_order_acquire)) {
      obs->OnStreamStopSending(stream_id, app_error_code);
    }
  }

  void OnPeerDatagramReceived(ArrayView<const uint8_t> data) override {
    if (auto* obs = observer_.load(std::memory_order_acquire)) {
      obs->OnDatagramReceived(data);
    }
  }

 private:
  struct PendingPreConnectOp {
    enum class Kind : uint8_t {
      kRegisterStream,
      kWriteStream,
      kResetStream,
      kStopSending,
      kSendDatagram,
    };
    Kind kind = Kind::kWriteStream;
    uint64_t stream_id = 0;
    uint8_t priority = 0;
    int64_t send_order = 0;
    uint64_t app_error_code = 0;
    bool fin = false;
    std::vector<uint8_t> data;
  };

  void EnqueuePreConnectOp(PendingPreConnectOp&& op) {
    if (pending_ops_.size() < 4096) {
      pending_ops_.push_back(std::move(op));
    }
  }

  void RecordApiClosedSidLocked(uint64_t sid) {
    if (api_closed_sids_.insert(sid).second) {
      api_closed_sid_order_.push_back(sid);
      while (api_closed_sid_order_.size() > 2048) {
        api_closed_sids_.erase(api_closed_sid_order_.front());
        api_closed_sid_order_.pop_front();
      }
    }
  }

  void SyncApiStreamBytes(uint64_t sid) {
    if (!core_) {
      return;
    }
    const size_t rem = core_->GetStreamUnsentBytes(sid);
    std::lock_guard<std::mutex> lock(api_stream_mutex_);
    if (rem == 0) {
      api_buffered_bytes_.erase(sid);
    } else {
      api_buffered_bytes_[sid] = rem;
    }
  }

  void FinishEndpointSetupAndStartHandshake(
      const boost::asio::ip::udp::endpoint& target_ep,
      const std::string& clean_host,
      const std::string& alpn) {
    RTC_DCHECK_RUN_ON(&net_checker_);
    remote_endpoint_ = target_ep;

    boost::system::error_code sock_ec;
    if (socket_.is_open()) {
      boost::system::error_code close_ec;
      socket_.close(close_ec);
    }
    const auto proto = remote_endpoint_.protocol();
    socket_.open(proto, sock_ec);
    if (!sock_ec) {
      socket_.bind(boost::asio::ip::udp::endpoint(proto, 0), sock_ec);
    }
    if (sock_ec) {
      RTC_LOG(kError) << "QUIC client UDP socket open/bind failed: "
                      << sock_ec.message();
      {
        std::lock_guard<std::mutex> lock(api_stream_mutex_);
        api_closed_ = true;
      }
      pending_ops_.clear();
      if (auto* obs = observer_.load(std::memory_order_acquire)) {
        obs->OnQuicDisconnected(-104);
      }
      return;
    }

    QuicTlsVerifyConfig verify_cfg;
    {
      std::lock_guard<std::mutex> lock(snap_mutex_);
      verify_cfg = tls_verify_cfg_;
    }

    const QuicCid local_scid = QuicCryptoUtils::GenerateRandomCid();
    const QuicCid init_dcid = QuicCryptoUtils::GenerateRandomCid();
    core_ = std::make_shared<QuicSessionCore>(
        clock_, /*is_server=*/false, local_scid, init_dcid, SplitAlpnList(alpn),
        this, std::move(pending_cc_), nullptr, clean_host,
        std::move(verify_cfg));

    // 按序重放在 DNS 解析完成前排队的流打开与写入请求，确保零丢数据。
    auto ops = std::move(pending_ops_);
    pending_ops_.clear();
    for (auto& op : ops) {
      switch (op.kind) {
        case PendingPreConnectOp::Kind::kRegisterStream:
          core_->RegisterOutboundStream(op.stream_id, op.priority,
                                        op.send_order);
          break;
        case PendingPreConnectOp::Kind::kWriteStream:
          core_->WriteStream(op.stream_id, op.data, op.fin);
          SyncApiStreamBytes(op.stream_id);
          break;
        case PendingPreConnectOp::Kind::kResetStream:
          core_->ResetStream(op.stream_id, op.app_error_code);
          break;
        case PendingPreConnectOp::Kind::kStopSending:
          core_->StopSending(op.stream_id, op.app_error_code);
          break;
        case PendingPreConnectOp::Kind::kSendDatagram:
          core_->SendDatagram(op.data);
          break;
      }
    }

    StartReceiveLoop();
    core_->StartClientHandshake();
    UpdateCachedSnapshot();
    SchedulePeriodicTick();
  }

  void StartReceiveLoop() {
    if (!socket_.is_open() || !safety_.flag()->alive()) {
      return;
    }
    auto self = shared_from_this();
    auto flag = safety_.flag();
    socket_.async_receive_from(
        boost::asio::buffer(rx_buf_), sender_endpoint_,
        [self, flag](const boost::system::error_code& ec, size_t nbytes) {
          if (!flag->alive() ||
              ec == boost::asio::error::operation_aborted ||
              !self->socket_.is_open()) {
            return;
          }
          if (!ec && nbytes > 0 &&
              !ShouldSimulateDrop(
                  self->rx_drop_prob_.load(std::memory_order_relaxed)) &&
              self->core_) {
            // 持栈上局部 shared_ptr，确保上层回调在栈内同步重入 Close() 时绝不发生 UAF。
            auto core_ref = self->core_;
            core_ref->ProcessUdpDatagram(
                ArrayView<const uint8_t>(self->rx_buf_.data(), nbytes),
                self->clock_->CurrentTime());
            self->UpdateCachedSnapshot();
          }
          if (flag->alive() && self->socket_.is_open()) {
            self->StartReceiveLoop();
          }
        });
  }

  void SchedulePeriodicTick() {
    auto self = shared_from_this();
    network_queue_->PostDelayedTask(
        SafeTask(safety_.flag(),
                 [self]() {
                   RTC_DCHECK_RUN_ON(&self->net_checker_);
                   auto core_ref = self->core_;
                   if (core_ref && !core_ref->is_closed()) {
                     core_ref->OnPeriodicTimer(self->clock_->CurrentTime());
                     self->UpdateCachedSnapshot();
                     if (self->core_ && !self->core_->is_closed()) {
                       self->SchedulePeriodicTick();
                     }
                   }
                 }),
        TimeDelta::Millis(5));
  }

  void UpdateCachedSnapshot() {
    if (!core_) {
      return;
    }
    const QuicCongestionSnapshot snap =
        core_->GetCongestionSnapshot(clock_->CurrentTime());
    max_dgram_payload_.store(core_->max_datagram_payload_size(),
                             std::memory_order_release);
    {
      std::lock_guard<std::mutex> lock(api_stream_mutex_);
      for (auto it = api_buffered_bytes_.begin();
           it != api_buffered_bytes_.end();) {
        const size_t rem = core_->GetStreamUnsentBytes(it->first);
        if (rem == 0) {
          it = api_buffered_bytes_.erase(it);
        } else {
          it->second = rem;
          ++it;
        }
      }
    }
    std::lock_guard<std::mutex> lock(snap_mutex_);
    cached_snapshot_ = snap;
    cached_alpn_ = core_->negotiated_alpn();
  }

  Clock* const clock_;
  TaskQueueBoost* const network_queue_;
  SequenceChecker net_checker_;
  std::unique_ptr<boost::asio::ip::udp::resolver> resolver_;
  boost::asio::ip::udp::socket socket_;
  boost::asio::ip::udp::endpoint remote_endpoint_;
  boost::asio::ip::udp::endpoint sender_endpoint_;
  std::vector<uint8_t> rx_buf_;

  std::shared_ptr<QuicSessionCore> core_;
  std::deque<PendingPreConnectOp> pending_ops_;
  std::unique_ptr<IQuicCongestionController> pending_cc_;
  std::atomic<IMoqQuicEngineObserver*> observer_{nullptr};
  std::atomic<uint64_t> next_bidi_id_{0};
  std::atomic<uint64_t> next_uni_id_{2};
  std::atomic<double> tx_drop_prob_{0.0};
  std::atomic<double> rx_drop_prob_{0.0};
  std::atomic<size_t> max_dgram_payload_{kQuicMaxDatagramSize - 32};

  mutable std::mutex api_stream_mutex_;
  bool api_closed_ = false;
  bool api_handshake_done_ = false;
  std::set<uint64_t> api_closed_sids_;
  std::deque<uint64_t> api_closed_sid_order_;
  std::map<uint64_t, size_t> api_buffered_bytes_;

  mutable std::mutex snap_mutex_;
  QuicTlsVerifyConfig tls_verify_cfg_;
  QuicCongestionSnapshot cached_snapshot_;
  std::string cached_alpn_;
  ScopedTaskSafety safety_;
};

AsioQuicClientEngine::AsioQuicClientEngine(
    Clock* clock,
    TaskQueueBoost* network_queue,
    std::unique_ptr<IQuicCongestionController> initial_cc)
    : impl_(std::make_shared<Impl>(clock,
                                   network_queue,
                                   std::move(initial_cc))) {}

AsioQuicClientEngine::~AsioQuicClientEngine() { impl_->Close(0); }

void AsioQuicClientEngine::SetObserver(IMoqQuicEngineObserver* observer) {
  impl_->SetObserver(observer);
}

int AsioQuicClientEngine::Connect(const std::string& host,
                                  uint16_t port,
                                  const std::string& alpn) {
  return impl_->Connect(host, port, alpn);
}

void AsioQuicClientEngine::Close(uint64_t app_error_code) {
  impl_->Close(app_error_code);
}

uint64_t AsioQuicClientEngine::OpenBidirectionalStream() {
  return impl_->OpenBidirectionalStream();
}

uint64_t AsioQuicClientEngine::OpenUnidirectionalStream(
    uint8_t publisher_priority,
    int64_t send_order) {
  return impl_->OpenUnidirectionalStream(publisher_priority, send_order);
}

int AsioQuicClientEngine::WriteStream(uint64_t stream_id,
                                      ArrayView<const uint8_t> data,
                                      bool fin) {
  return impl_->WriteStream(stream_id, data, fin);
}

void AsioQuicClientEngine::ResetStream(uint64_t stream_id,
                                       uint64_t app_error_code) {
  impl_->ResetStream(stream_id, app_error_code);
}

void AsioQuicClientEngine::StopSending(uint64_t stream_id,
                                       uint64_t app_error_code) {
  impl_->StopSending(stream_id, app_error_code);
}

int AsioQuicClientEngine::SendDatagram(ArrayView<const uint8_t> data) {
  return impl_->SendDatagram(data);
}

size_t AsioQuicClientEngine::max_datagram_size() const {
  return impl_->max_datagram_size();
}

std::string AsioQuicClientEngine::negotiated_alpn() const {
  return impl_->negotiated_alpn();
}

QuicCongestionSnapshot AsioQuicClientEngine::GetCongestionSnapshot() const {
  return impl_->GetCongestionSnapshot();
}

int AsioQuicClientEngine::SetCongestionController(
    std::unique_ptr<IQuicCongestionController> controller) {
  return impl_->SetCongestionController(std::move(controller));
}

void AsioQuicClientEngine::SetTlsVerifyConfig(
    bool verify_peer,
    std::string ca_cert_path,
    std::string pinned_cert_sha256) {
  impl_->SetTlsVerifyConfig(verify_peer, std::move(ca_cert_path),
                            std::move(pinned_cert_sha256));
}

void AsioQuicClientEngine::SetSimulatedDropRates(double tx_drop_prob,
                                                 double rx_drop_prob) {
  impl_->SetSimulatedDropRates(tx_drop_prob, rx_drop_prob);
}

// ======================= AsioQuicServer 服务端引擎实现 =======================

class AsioQuicServer::ServerImpl
    : public std::enable_shared_from_this<AsioQuicServer::ServerImpl> {
 public:
  ServerImpl(Clock* clock,
             TaskQueueBoost* network_queue,
             IQuicServerVisitor* visitor,
             std::string bind_ip,
             std::vector<std::string> supported_alpns)
      : clock_(clock),
        network_queue_(network_queue),
        net_checker_(network_queue),
        visitor_(visitor),
        bind_ip_(std::move(bind_ip)),
        supported_alpns_(std::move(supported_alpns)),
        server_cert_(QuicServerCertContext::GenerateEphemeralP256()),
        socket_(network_queue->io_context()),
        rx_buf_(65536),
        safety_(PendingTaskSafetyFlag::CreateDetached()) {}

  std::array<uint8_t, 32> certificate_sha256() const {
    return server_cert_ ? server_cert_->sha256() : std::array<uint8_t, 32>{};
  }

  std::string certificate_sha256_hex() const {
    return server_cert_ ? server_cert_->sha256_hex() : std::string{};
  }

  bool Start(uint16_t udp_port, uint16_t* out_bound_port) {
    bool ok = false;
    network_queue_->Invoke([this, udp_port, out_bound_port, &ok]() {
      RTC_DCHECK_RUN_ON(&net_checker_);
      boost::system::error_code ec;
      const auto addr = boost::asio::ip::make_address(bind_ip_, ec);
      if (ec) {
        return;
      }
      socket_.open(addr.is_v6() ? boost::asio::ip::udp::v6()
                                : boost::asio::ip::udp::v4(),
                   ec);
      if (ec) {
        return;
      }
      socket_.bind(boost::asio::ip::udp::endpoint(addr, udp_port), ec);
      if (ec) {
        socket_.close(ec);
        return;
      }
      *out_bound_port = socket_.local_endpoint(ec).port();
      ok = !ec;
      if (ok) {
        StartReceiveLoop();
        SchedulePeriodicTick();
      }
    });
    return ok;
  }

  void Stop() {
    if (network_queue_->IsStopped()) {
      return;
    }
    network_queue_->Invoke([this]() {
      RTC_DCHECK_RUN_ON(&net_checker_);
      safety_.flag()->SetNotAlive();
      for (auto& [cid, sess] : sessions_by_scid_) {
        (void)cid;
        sess->CloseFromServer(0);
      }
      sessions_by_scid_.clear();
      sessions_by_initial_dcid_.clear();
      boost::system::error_code ec;
      socket_.close(ec);
    });
  }

  void SetSimulatedDropRates(double rx_drop, double tx_drop) {
    rx_drop_prob_.store(rx_drop, std::memory_order_release);
    tx_drop_prob_.store(tx_drop, std::memory_order_release);
  }

  void SetCongestionControllerFactory(
      std::shared_ptr<IQuicCongestionControllerFactory> factory) {
    if (!factory || network_queue_->IsStopped()) {
      return;
    }
    auto self = shared_from_this();
    network_queue_->PostTask(SafeTask(safety_.flag(), [self, factory]() {
      RTC_DCHECK_RUN_ON(&self->net_checker_);
      self->cc_factory_ = factory;
      const Timestamp now = self->clock_->CurrentTime();
      for (auto& [cid, sess] : self->sessions_by_scid_) {
        (void)cid;
        sess->HotSwapCc(factory->Create(kQuicMaxDatagramSize), now);
      }
    }));
  }

  void SendFromSession(const boost::asio::ip::udp::endpoint& peer_ep,
                       ArrayView<const uint8_t> bytes) {
    RTC_DCHECK_RUN_ON(&net_checker_);
    if (!socket_.is_open()) {
      return;
    }
    if (ShouldSimulateDrop(tx_drop_prob_.load(std::memory_order_relaxed))) {
      return;
    }
    boost::system::error_code ec;
    socket_.send_to(boost::asio::buffer(bytes.data(), bytes.size()), peer_ep, 0,
                    ec);
  }

 private:
  class ServerSession final
      : public QuicServerSessionHandle,
        public QuicSessionEvents,
        public std::enable_shared_from_this<ServerSession> {
   public:
    ServerSession(uint64_t id,
                  ServerImpl* parent,
                  QuicCid server_scid,
                  QuicCid client_initial_dcid,
                  const boost::asio::ip::udp::endpoint& peer_ep,
                  std::unique_ptr<IQuicCongestionController> initial_cc)
        : id_(id),
          parent_(parent),
          server_scid_(server_scid),
          client_initial_dcid_(client_initial_dcid),
          peer_endpoint_(peer_ep),
          core_(parent->clock_,
                /*is_server=*/true,
                server_scid,
                client_initial_dcid,
                parent->supported_alpns_,
                this,
                std::move(initial_cc),
                parent->server_cert_) {
      cached_snapshot_.timestamp = parent_->clock_->CurrentTime();
    }

    void HotSwapCc(std::unique_ptr<IQuicCongestionController> next_cc,
                   Timestamp now) {
      if (!core_.is_closed()) {
        core_.HotSwapCongestionController(std::move(next_cc), now);
        UpdateCachedSnapshot();
      }
    }

    uint64_t session_id() const override { return id_; }

    std::string negotiated_alpn() const override {
      std::lock_guard<std::mutex> lock(snap_mutex_);
      return cached_alpn_;
    }

    uint64_t OpenBidirectionalStream() override {
      const uint64_t sid =
          next_bidi_id_.fetch_add(4, std::memory_order_relaxed);
      auto self = shared_from_this();
      parent_->network_queue_->PostTask(
          SafeTask(parent_->safety_.flag(), [self, sid]() {
            RTC_DCHECK_RUN_ON(&self->parent_->net_checker_);
            if (!self->core_.is_closed()) {
              self->core_.RegisterOutboundStream(
                  sid, 0, std::numeric_limits<int64_t>::max());
            }
          }));
      return sid;
    }

    uint64_t OpenUnidirectionalStream(uint8_t publisher_priority,
                                      int64_t send_order) override {
      const uint64_t sid = next_uni_id_.fetch_add(4, std::memory_order_relaxed);
      auto self = shared_from_this();
      parent_->network_queue_->PostTask(SafeTask(
          parent_->safety_.flag(),
          [self, sid, publisher_priority, send_order]() {
            RTC_DCHECK_RUN_ON(&self->parent_->net_checker_);
            if (!self->core_.is_closed()) {
              self->core_.RegisterOutboundStream(sid, publisher_priority,
                                                 send_order);
            }
          }));
      return sid;
    }

    int WriteStream(uint64_t stream_id,
                    ArrayView<const uint8_t> data,
                    bool fin) override {
      if (parent_->network_queue_->IsStopped()) {
        return RTC_ERR_NOT_INITIALIZED;
      }
      // 服务端严禁向客户端发起的单向流（0x02）写入数据。
      if ((stream_id & 0x03u) == 0x02u) {
        return RTC_ERR_INVALID_ARG;
      }
      constexpr size_t kMaxOutboundStreamBufferBytes = 16 * 1024 * 1024;
      {
        std::lock_guard<std::mutex> lock(api_stream_mutex_);
        if (api_closed_) {
          return RTC_ERR_NOT_CONNECTED;
        }
        if (api_closed_sids_.count(stream_id) > 0) {
          return RTC_ERR_INVALID_ARG;
        }
        size_t& cur_buf = api_buffered_bytes_[stream_id];
        if (data.size() > kMaxOutboundStreamBufferBytes ||
            cur_buf > kMaxOutboundStreamBufferBytes - data.size()) {
          return RTC_ERR_NO_MEMORY;
        }
        cur_buf += data.size();
        if (fin) {
          RecordApiClosedSidLocked(stream_id);
        }
      }
      std::vector<uint8_t> copy(data.begin(), data.end());
      auto self = shared_from_this();
      parent_->network_queue_->PostTask(SafeTask(
          parent_->safety_.flag(),
          [self, stream_id, buf = std::move(copy), fin]() {
            RTC_DCHECK_RUN_ON(&self->parent_->net_checker_);
            if (!self->core_.is_closed()) {
              self->core_.WriteStream(stream_id, buf, fin);
              self->UpdateCachedSnapshot();
            }
          }));
      return static_cast<int>(data.size());
    }

    void ResetStream(uint64_t stream_id, uint64_t app_error_code) override {
      if ((stream_id & 0x03u) == 0x02u) {
        return;
      }
      {
        std::lock_guard<std::mutex> lock(api_stream_mutex_);
        RecordApiClosedSidLocked(stream_id);
        api_buffered_bytes_.erase(stream_id);
      }
      auto self = shared_from_this();
      parent_->network_queue_->PostTask(SafeTask(
          parent_->safety_.flag(), [self, stream_id, app_error_code]() {
            RTC_DCHECK_RUN_ON(&self->parent_->net_checker_);
            if (!self->core_.is_closed()) {
              self->core_.ResetStream(stream_id, app_error_code);
            }
          }));
    }

    void StopSending(uint64_t stream_id, uint64_t app_error_code) override {
      if ((stream_id & 0x03u) == 0x03u) {
        return;
      }
      auto self = shared_from_this();
      parent_->network_queue_->PostTask(SafeTask(
          parent_->safety_.flag(), [self, stream_id, app_error_code]() {
            RTC_DCHECK_RUN_ON(&self->parent_->net_checker_);
            if (!self->core_.is_closed()) {
              self->core_.StopSending(stream_id, app_error_code);
            }
          }));
    }

    int SendDatagram(ArrayView<const uint8_t> data) override {
      {
        std::lock_guard<std::mutex> lock(api_stream_mutex_);
        if (api_closed_) {
          return RTC_ERR_NOT_CONNECTED;
        }
      }
      const size_t max_sz = max_datagram_size();
      if (max_sz == 0) {
        return RTC_ERR_PROTOCOL;
      }
      if (data.size() > max_sz) {
        return RTC_ERR_INVALID_ARG;
      }
      std::vector<uint8_t> copy(data.begin(), data.end());
      auto self = shared_from_this();
      parent_->network_queue_->PostTask(
          SafeTask(parent_->safety_.flag(), [self, buf = std::move(copy)]() {
            RTC_DCHECK_RUN_ON(&self->parent_->net_checker_);
            if (!self->core_.is_closed()) {
              self->core_.SendDatagram(buf);
              self->UpdateCachedSnapshot();
            }
          }));
      return RTC_OK;
    }

    size_t max_datagram_size() const override {
      return max_dgram_payload_.load(std::memory_order_acquire);
    }

    void Close(uint64_t app_error_code) override {
      {
        std::lock_guard<std::mutex> lock(api_stream_mutex_);
        api_closed_ = true;
        api_buffered_bytes_.clear();
      }
      auto self = shared_from_this();
      parent_->network_queue_->PostTask(
          SafeTask(parent_->safety_.flag(), [self, app_error_code]() {
            RTC_DCHECK_RUN_ON(&self->parent_->net_checker_);
            self->CloseFromServer(app_error_code);
          }));
    }

    QuicCongestionSnapshot GetCongestionSnapshot() const override {
      std::lock_guard<std::mutex> lock(snap_mutex_);
      return cached_snapshot_;
    }

    void CloseFromServer(uint64_t app_error_code) {
      {
        std::lock_guard<std::mutex> lock(api_stream_mutex_);
        api_closed_ = true;
        api_buffered_bytes_.clear();
      }
      if (!core_.is_closed()) {
        core_.CloseConnection(app_error_code);
      }
    }

    void ProcessDatagram(const boost::asio::ip::udp::endpoint& sender_ep,
                         ArrayView<const uint8_t> datagram,
                         Timestamp now) {
      current_rx_sender_ep_ = sender_ep;
      core_.ProcessUdpDatagram(datagram, now);
      UpdateCachedSnapshot();
    }

    void OnTimer(Timestamp now) {
      core_.OnPeriodicTimer(now);
      UpdateCachedSnapshot();
    }

    bool is_closed() const { return core_.is_closed(); }
    bool has_authenticated_rx() const { return core_.has_authenticated_rx(); }
    const QuicCid& server_scid() const { return server_scid_; }
    const QuicCid& client_initial_dcid() const { return client_initial_dcid_; }

    // QuicSessionEvents 接口重写：
    void SendUdpDatagram(ArrayView<const uint8_t> bytes) override {
      parent_->SendFromSession(peer_endpoint_, bytes);
    }

    void OnHighestOneRttNonProbingPacket() override {
      peer_endpoint_ = current_rx_sender_ep_;
    }

    void OnHandshakeEstablished() override {
      UpdateCachedSnapshot();
      RTC_LOG(kInfo) << "AsioQuicServer session=" << id_
                     << " QUIC v1 handshake established (ALPN="
                     << core_.negotiated_alpn() << ") from "
                     << peer_endpoint_.address().to_string() << ":"
                     << peer_endpoint_.port();
      if (parent_->visitor_ != nullptr) {
        parent_->visitor_->OnServerSessionConnected(shared_from_this());
      }
    }

    void OnConnectionClosed(int error_code) override {
      {
        std::lock_guard<std::mutex> lock(api_stream_mutex_);
        api_closed_ = true;
        api_buffered_bytes_.clear();
      }
      if (!disconnect_notified_ && parent_->visitor_ != nullptr) {
        disconnect_notified_ = true;
        parent_->visitor_->OnServerSessionDisconnected(id_, error_code);
      }
    }

    void OnPeerStreamOpened(uint64_t stream_id, bool unidirectional) override {
      if (parent_->visitor_ != nullptr) {
        parent_->visitor_->OnServerStreamOpened(id_, stream_id, unidirectional);
      }
    }

    void OnPeerStreamData(uint64_t stream_id,
                          ArrayView<const uint8_t> data,
                          bool fin) override {
      if (parent_->visitor_ != nullptr) {
        parent_->visitor_->OnServerStreamData(id_, stream_id, data, fin);
      }
    }

    void OnPeerStreamReset(uint64_t stream_id,
                           uint64_t app_error_code) override {
      if (parent_->visitor_ != nullptr) {
        parent_->visitor_->OnServerStreamReset(id_, stream_id, app_error_code);
      }
    }

    void OnPeerStopSending(uint64_t stream_id,
                           uint64_t app_error_code) override {
      {
        std::lock_guard<std::mutex> lock(api_stream_mutex_);
        RecordApiClosedSidLocked(stream_id);
        api_buffered_bytes_.erase(stream_id);
      }
      if (parent_->visitor_ != nullptr) {
        parent_->visitor_->OnServerStreamStopSending(id_, stream_id,
                                                     app_error_code);
      }
    }

    void OnPeerDatagramReceived(ArrayView<const uint8_t> data) override {
      if (parent_->visitor_ != nullptr) {
        parent_->visitor_->OnServerDatagramReceived(id_, data);
      }
    }

   private:
    void RecordApiClosedSidLocked(uint64_t sid) {
      if (api_closed_sids_.insert(sid).second) {
        api_closed_sid_order_.push_back(sid);
        while (api_closed_sid_order_.size() > 2048) {
          api_closed_sids_.erase(api_closed_sid_order_.front());
          api_closed_sid_order_.pop_front();
        }
      }
    }

    void UpdateCachedSnapshot() {
      const QuicCongestionSnapshot snap =
          core_.GetCongestionSnapshot(parent_->clock_->CurrentTime());
      max_dgram_payload_.store(core_.max_datagram_payload_size(),
                               std::memory_order_release);
      {
        std::lock_guard<std::mutex> lock(api_stream_mutex_);
        for (auto it = api_buffered_bytes_.begin();
             it != api_buffered_bytes_.end();) {
          const size_t rem = core_.GetStreamUnsentBytes(it->first);
          if (rem == 0) {
            it = api_buffered_bytes_.erase(it);
          } else {
            it->second = rem;
            ++it;
          }
        }
      }
      std::lock_guard<std::mutex> lock(snap_mutex_);
      cached_snapshot_ = snap;
      cached_alpn_ = core_.negotiated_alpn();
    }

    const uint64_t id_;
    ServerImpl* const parent_;
    const QuicCid server_scid_;
    const QuicCid client_initial_dcid_;
    boost::asio::ip::udp::endpoint peer_endpoint_;
    boost::asio::ip::udp::endpoint current_rx_sender_ep_;
    QuicSessionCore core_;
    bool disconnect_notified_ = false;
    std::atomic<uint64_t> next_bidi_id_{1};
    std::atomic<uint64_t> next_uni_id_{3};
    std::atomic<size_t> max_dgram_payload_{kQuicMaxDatagramSize - 32};
    mutable std::mutex api_stream_mutex_;
    bool api_closed_ = false;
    std::set<uint64_t> api_closed_sids_;
    std::deque<uint64_t> api_closed_sid_order_;
    std::map<uint64_t, size_t> api_buffered_bytes_;
    mutable std::mutex snap_mutex_;
    QuicCongestionSnapshot cached_snapshot_;
    std::string cached_alpn_;
  };

  void StartReceiveLoop() {
    if (!socket_.is_open() || !safety_.flag()->alive()) {
      return;
    }
    auto self = shared_from_this();
    auto flag = safety_.flag();
    socket_.async_receive_from(
        boost::asio::buffer(rx_buf_), sender_endpoint_,
        [self, flag](const boost::system::error_code& ec, size_t nbytes) {
          if (!flag->alive() ||
              ec == boost::asio::error::operation_aborted ||
              !self->socket_.is_open()) {
            return;
          }
          if (!ec && nbytes > 0 &&
              !ShouldSimulateDrop(
                  self->rx_drop_prob_.load(std::memory_order_relaxed))) {
            self->RouteIncomingDatagram(
                self->sender_endpoint_,
                ArrayView<const uint8_t>(self->rx_buf_.data(), nbytes));
          }
          if (flag->alive() && self->socket_.is_open()) {
            self->StartReceiveLoop();
          }
        });
  }

  void RouteIncomingDatagram(const boost::asio::ip::udp::endpoint& sender_ep,
                             ArrayView<const uint8_t> datagram) {
    RTC_DCHECK_RUN_ON(&net_checker_);
    bool is_long = false;
    QuicEncryptionLevel level = QuicEncryptionLevel::kOneRtt;
    QuicCid dcid{};
    QuicCid scid{};
    size_t pkt_len = 0;
    if (!QuicCryptoUtils::InspectHeaderIds(datagram, &is_long, &level, &dcid,
                                           &scid, &pkt_len)) {
      return;
    }

    const Timestamp now = clock_->CurrentTime();
    auto scid_it = sessions_by_scid_.find(dcid);
    if (scid_it != sessions_by_scid_.end()) {
      auto sess = scid_it->second;
      sess->ProcessDatagram(sender_ep, datagram, now);
      if (sess->is_closed()) {
        sessions_by_initial_dcid_.erase(sess->client_initial_dcid());
        sessions_by_scid_.erase(sess->server_scid());
      }
      return;
    }

    auto init_it = sessions_by_initial_dcid_.find(dcid);
    if (init_it != sessions_by_initial_dcid_.end()) {
      auto sess = init_it->second;
      sess->ProcessDatagram(sender_ep, datagram, now);
      if (sess->is_closed()) {
        sessions_by_initial_dcid_.erase(sess->client_initial_dcid());
        sessions_by_scid_.erase(sess->server_scid());
      }
      return;
    }

    // RFC 9000 第 14.1 节：强制要求客户端 Initial 数据包所在的 UDP 数据报至少为 1200 字节，
    // 以防止流量放大攻击；同时限制并发会话上界防止状态耗尽。
    if (!is_long || level != QuicEncryptionLevel::kInitial ||
        datagram.size() < kQuicMinClientInitialSize ||
        sessions_by_scid_.size() >= 1024) {
      return;
    }

    const uint64_t new_id = ++next_session_id_;
    const QuicCid server_scid = QuicCryptoUtils::GenerateRandomCid();
    std::unique_ptr<IQuicCongestionController> init_cc =
        cc_factory_ ? cc_factory_->Create(kQuicMaxDatagramSize) : nullptr;
    auto session = std::make_shared<ServerSession>(
        new_id, this, server_scid, dcid, sender_ep, std::move(init_cc));
    sessions_by_scid_.emplace(server_scid, session);
    sessions_by_initial_dcid_.emplace(dcid, session);
    session->ProcessDatagram(sender_ep, datagram, now);
    if (!session->has_authenticated_rx() || session->is_closed()) {
      sessions_by_initial_dcid_.erase(dcid);
      sessions_by_scid_.erase(server_scid);
    }
  }

  void SchedulePeriodicTick() {
    auto self = shared_from_this();
    network_queue_->PostDelayedTask(
        SafeTask(safety_.flag(),
                 [self]() {
                   RTC_DCHECK_RUN_ON(&self->net_checker_);
                   const Timestamp now = self->clock_->CurrentTime();
                   std::vector<std::shared_ptr<ServerSession>> snapshot;
                   snapshot.reserve(self->sessions_by_scid_.size());
                   for (const auto& [cid, s] : self->sessions_by_scid_) {
                     (void)cid;
                     snapshot.push_back(s);
                   }
                   for (const auto& s : snapshot) {
                     s->OnTimer(now);
                     if (s->is_closed()) {
                       self->sessions_by_initial_dcid_.erase(
                           s->client_initial_dcid());
                       self->sessions_by_scid_.erase(s->server_scid());
                     }
                   }
                   self->SchedulePeriodicTick();
                 }),
        TimeDelta::Millis(5));
  }

  Clock* const clock_;
  TaskQueueBoost* const network_queue_;
  SequenceChecker net_checker_;
  IQuicServerVisitor* const visitor_;
  const std::string bind_ip_;
  const std::vector<std::string> supported_alpns_;
  std::shared_ptr<QuicServerCertContext> server_cert_;
  boost::asio::ip::udp::socket socket_;
  boost::asio::ip::udp::endpoint sender_endpoint_;
  std::vector<uint8_t> rx_buf_;

  uint64_t next_session_id_ = 0;
  std::shared_ptr<IQuicCongestionControllerFactory> cc_factory_;
  std::map<QuicCid, std::shared_ptr<ServerSession>> sessions_by_scid_;
  std::map<QuicCid, std::shared_ptr<ServerSession>> sessions_by_initial_dcid_;
  std::atomic<double> rx_drop_prob_{0.0};
  std::atomic<double> tx_drop_prob_{0.0};
  ScopedTaskSafety safety_;
};

AsioQuicServer::AsioQuicServer(Clock* clock,
                               TaskQueueBoost* network_queue,
                               IQuicServerVisitor* visitor,
                               std::string bind_ip,
                               std::string expected_alpn)
    : impl_(std::make_shared<ServerImpl>(
          clock,
          network_queue,
          visitor,
          std::move(bind_ip),
          SplitAlpnList(expected_alpn))) {}

AsioQuicServer::AsioQuicServer(Clock* clock,
                               TaskQueueBoost* network_queue,
                               IQuicServerVisitor* visitor,
                               std::string bind_ip,
                               std::vector<std::string> supported_alpns)
    : impl_(std::make_shared<ServerImpl>(clock,
                                         network_queue,
                                         visitor,
                                         std::move(bind_ip),
                                         std::move(supported_alpns))) {}

AsioQuicServer::~AsioQuicServer() { Stop(); }

bool AsioQuicServer::Start(uint16_t udp_port) {
  return impl_->Start(udp_port, &local_port_);
}

void AsioQuicServer::Stop() { impl_->Stop(); }

std::array<uint8_t, 32> AsioQuicServer::certificate_sha256() const {
  return impl_->certificate_sha256();
}

std::string AsioQuicServer::certificate_sha256_hex() const {
  return impl_->certificate_sha256_hex();
}

void AsioQuicServer::SetSimulatedDropRates(double rx_drop_prob,
                                           double tx_drop_prob) {
  impl_->SetSimulatedDropRates(rx_drop_prob, tx_drop_prob);
}

void AsioQuicServer::SetCongestionControllerFactory(
    std::shared_ptr<IQuicCongestionControllerFactory> factory) {
  impl_->SetCongestionControllerFactory(std::move(factory));
}

}  // namespace rtc