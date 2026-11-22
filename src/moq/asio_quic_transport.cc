#include "moq/asio_quic_transport.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <random>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

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
constexpr uint64_t kFrameStreamBase = 0x08;
constexpr uint64_t kFrameStreamFinBit = 0x01;
constexpr uint64_t kFrameStreamLenBit = 0x02;
constexpr uint64_t kFrameStreamOffBit = 0x04;
constexpr uint64_t kFrameMaxData = 0x10;
constexpr uint64_t kFrameMaxStreamData = 0x11;
constexpr uint64_t kFrameConnectionCloseQuic = 0x1c;
constexpr uint64_t kFrameConnectionCloseApp = 0x1d;
constexpr uint64_t kFrameHandshakeDone = 0x1e;

// QUIC CRYPTO 帧内承载的握手消息标签。
constexpr uint8_t kCryptoMsgClientHello = 0x01;
constexpr uint8_t kCryptoMsgServerHello = 0x02;
constexpr uint8_t kCryptoMsgServerEncryptedExtFinished = 0x14;
constexpr uint8_t kCryptoMsgClientFinished = 0x15;

// RFC 9000 第 18 节定义的传输参数 ID。
constexpr uint64_t kTpOriginalDestinationCid = 0x00;
constexpr uint64_t kTpMaxIdleTimeout = 0x01;
constexpr uint64_t kTpInitialMaxData = 0x04;
constexpr uint64_t kTpInitialMaxStreamDataBidiLocal = 0x05;
constexpr uint64_t kTpInitialMaxStreamDataBidiRemote = 0x06;
constexpr uint64_t kTpInitialMaxStreamDataUni = 0x07;
constexpr uint64_t kTpInitialMaxStreamsBidi = 0x08;
constexpr uint64_t kTpInitialMaxStreamsUni = 0x09;
constexpr uint64_t kTpInitialSourceCid = 0x0f;

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
  out.reserve(64);
  if (has_original_destination_cid) {
    AppendTpBytes(kTpOriginalDestinationCid, original_destination_cid, &out);
  }
  AppendTpVarInt(kTpMaxIdleTimeout, max_idle_timeout_ms, &out);
  AppendTpVarInt(kTpInitialMaxData, initial_max_data, &out);
  AppendTpVarInt(kTpInitialMaxStreamDataBidiLocal,
                 initial_max_stream_data_bidi_local, &out);
  AppendTpVarInt(kTpInitialMaxStreamDataBidiRemote,
                 initial_max_stream_data_bidi_remote, &out);
  AppendTpVarInt(kTpInitialMaxStreamDataUni, initial_max_stream_data_uni, &out);
  AppendTpVarInt(kTpInitialMaxStreamsBidi, initial_max_streams_bidi, &out);
  AppendTpVarInt(kTpInitialMaxStreamsUni, initial_max_streams_uni, &out);
  AppendTpBytes(kTpInitialSourceCid, initial_source_cid, &out);
  return out;
}

std::optional<QuicTransportParameters> QuicTransportParameters::Decode(
    ArrayView<const uint8_t> data) {
  QuicTransportParameters tp;
  size_t off = 0;
  while (off < data.size()) {
    uint64_t id = 0;
    uint64_t len = 0;
    if (!QuicVarInt::Read(data, &off, &id) ||
        !QuicVarInt::Read(data, &off, &len) || off + len > data.size()) {
      return std::nullopt;
    }
    const ArrayView<const uint8_t> val_slice =
        data.subview(off, static_cast<size_t>(len));
    size_t voff = 0;
    switch (id) {
      case kTpOriginalDestinationCid:
        if (val_slice.size() == kQuicCidLength) {
          std::memcpy(tp.original_destination_cid.data(), val_slice.data(),
                      kQuicCidLength);
          tp.has_original_destination_cid = true;
        }
        break;
      case kTpMaxIdleTimeout:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.max_idle_timeout_ms)) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxData:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.initial_max_data)) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxStreamDataBidiLocal:
        if (!QuicVarInt::Read(val_slice, &voff,
                              &tp.initial_max_stream_data_bidi_local)) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxStreamDataBidiRemote:
        if (!QuicVarInt::Read(val_slice, &voff,
                              &tp.initial_max_stream_data_bidi_remote)) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxStreamDataUni:
        if (!QuicVarInt::Read(val_slice, &voff,
                              &tp.initial_max_stream_data_uni)) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxStreamsBidi:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.initial_max_streams_bidi)) {
          return std::nullopt;
        }
        break;
      case kTpInitialMaxStreamsUni:
        if (!QuicVarInt::Read(val_slice, &voff, &tp.initial_max_streams_uni)) {
          return std::nullopt;
        }
        break;
      case kTpInitialSourceCid:
        if (val_slice.size() == kQuicCidLength) {
          std::memcpy(tp.initial_source_cid.data(), val_slice.data(),
                      kQuicCidLength);
        }
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
                                  size_t* out_total_packet_len) {
  if (datagram.size() < 1 + kQuicCidLength + 4 + kQuicAeadTagLength) {
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
    *out_level = QuicEncryptionLevel::kOneRtt;
    std::memcpy(out_dcid->data(), datagram.data() + 1, kQuicCidLength);
    *out_scid = QuicCid{};
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
  if (dcid_len != kQuicCidLength || off + dcid_len + 1 > datagram.size()) {
    return std::nullopt;
  }
  std::memcpy(out_dcid->data(), datagram.data() + off, kQuicCidLength);
  off += kQuicCidLength;

  const uint8_t scid_len = datagram[off++];
  if (scid_len != kQuicCidLength || off + scid_len > datagram.size()) {
    return std::nullopt;
  }
  std::memcpy(out_scid->data(), datagram.data() + off, kQuicCidLength);
  off += kQuicCidLength;

  if (*out_level == QuicEncryptionLevel::kInitial) {
    uint64_t token_len = 0;
    if (!QuicVarInt::Read(datagram, &off, &token_len) ||
        off + token_len > datagram.size()) {
      return std::nullopt;
    }
    off += static_cast<size_t>(token_len);
  }

  uint64_t rem_len = 0;
  if (!QuicVarInt::Read(datagram, &off, &rem_len) ||
      off + rem_len > datagram.size() || rem_len < 1 + kQuicAeadTagLength) {
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
                                 int64_t largest_authenticated_pn) {
  if (!keys.valid) {
    return std::nullopt;
  }

  bool is_long = false;
  QuicEncryptionLevel level = QuicEncryptionLevel::kOneRtt;
  QuicCid dcid{};
  QuicCid scid{};
  size_t total_pkt_len = 0;
  if (!InspectHeaderIds(datagram, &is_long, &level, &dcid, &scid,
                        &total_pkt_len)) {
    return std::nullopt;
  }

  const ArrayView<const uint8_t> pkt = datagram.subview(0, total_pkt_len);
  size_t pn_offset = 0;
  if (!is_long) {
    pn_offset = 1 + kQuicCidLength;
  } else {
    pn_offset = 5 + 1 + kQuicCidLength + 1 + kQuicCidLength;
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
        ranges_.erase(ranges_.begin());
      }
      return;
    }
  }
  ranges_.push_back(Range{pn, pn});
  if (ranges_.size() > 32) {
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
                                     std::vector<Range>* out_ranges) {
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

  *out_ack_delay_us = raw_ack_delay << 3;
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

void QuicStreamReceiveBuffer::InsertChunk(uint64_t offset,
                                          ArrayView<const uint8_t> data,
                                          bool fin) {
  if (reset_ || fin_delivered_) {
    return;
  }
  if (fin) {
    final_offset_ = offset + data.size();
  }
  if (data.empty()) {
    return;
  }
  const uint64_t chunk_end = offset + data.size();
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
  if (it == chunks_.end() || it->second.size() < trimmed.size()) {
    chunks_[trimmed_offset].assign(trimmed.begin(), trimmed.end());
  }
}

bool QuicStreamReceiveBuffer::ExtractContiguous(std::vector<uint8_t>* out_data,
                                                bool* out_fin) {
  out_data->clear();
  *out_fin = false;
  if (reset_ || fin_delivered_) {
    return false;
  }

  while (!chunks_.empty()) {
    auto it = chunks_.begin();
    if (it->first > next_deliver_offset_) {
      break;
    }
    const uint64_t chunk_end = it->first + it->second.size();
    if (chunk_end > next_deliver_offset_) {
      const size_t start_idx =
          static_cast<size_t>(next_deliver_offset_ - it->first);
      out_data->insert(out_data->end(),
                       it->second.begin() + static_cast<ptrdiff_t>(start_idx),
                       it->second.end());
      next_deliver_offset_ = chunk_end;
    }
    chunks_.erase(it);
  }

  if (final_offset_.has_value() && next_deliver_offset_ >= *final_offset_) {
    *out_fin = true;
    fin_delivered_ = true;
  }
  return !out_data->empty() || *out_fin;
}

void QuicStreamReceiveBuffer::Reset() {
  reset_ = true;
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
};

class QuicSessionCore {
 public:
  QuicSessionCore(
      Clock* clock,
      bool is_server,
      QuicCid local_scid,
      QuicCid initial_dcid,
      std::string alpn,
      QuicSessionEvents* events,
      std::unique_ptr<IQuicCongestionController> initial_cc = nullptr)
      : clock_(clock),
        is_server_(is_server),
        local_scid_(local_scid),
        peer_dcid_(initial_dcid),
        initial_dcid_(initial_dcid),
        alpn_(std::move(alpn)),
        events_(events),
        cc_(initial_cc ? std::move(initial_cc)
                       : CreateBuiltinQuicCongestionController(
                             RTC_QUIC_CC_BBR, kQuicMaxDatagramSize)) {
    local_tp_.initial_source_cid = local_scid_;
    if (is_server_) {
      local_tp_.original_destination_cid = initial_dcid_;
      local_tp_.has_original_destination_cid = true;
    }

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
    const QuicEncryptionLevel lvl =
        tx_keys_[LevelIndex(QuicEncryptionLevel::kOneRtt)].valid
            ? QuicEncryptionLevel::kOneRtt
            : QuicEncryptionLevel::kInitial;
    std::vector<uint8_t> close_frame;
    QuicVarInt::Append(lvl == QuicEncryptionLevel::kOneRtt
                           ? kFrameConnectionCloseApp
                           : kFrameConnectionCloseQuic,
                       &close_frame);
    QuicVarInt::Append(app_error_code, &close_frame);
    if (lvl != QuicEncryptionLevel::kOneRtt) {
      QuicVarInt::Append(0, &close_frame);
    }
    QuicVarInt::Append(0, &close_frame);
    EmitSinglePacket(lvl, close_frame, false, std::vector<SentRetransmittable>{},
                     clock_->CurrentTime());
    closed_ = true;
  }

  void RegisterOutboundStream(uint64_t stream_id,
                              uint8_t publisher_priority,
                              int64_t send_order) {
    auto& st = outbound_streams_[stream_id];
    st.stream_id = stream_id;
    st.priority = publisher_priority;
    st.send_order = send_order;
  }

  int WriteStream(uint64_t stream_id, ArrayView<const uint8_t> data, bool fin) {
    if (closed_) {
      return -1;
    }
    auto& st = outbound_streams_[stream_id];
    st.stream_id = stream_id;
    if (st.reset) {
      return -1;
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

  void ResetStream(uint64_t stream_id, uint64_t app_error_code) {
    if (closed_) {
      return;
    }
    auto& st = outbound_streams_[stream_id];
    if (st.reset) {
      return;
    }
    st.reset = true;
    st.unsent_data.clear();
    st.retransmit_chunks.clear();

    PendingReset rst;
    rst.stream_id = stream_id;
    rst.app_error_code = app_error_code;
    rst.final_size = st.next_send_offset;
    pending_resets_.push_back(rst);
    FlushPackets(clock_->CurrentTime(), false);
  }

  void ProcessUdpDatagram(ArrayView<const uint8_t> datagram, Timestamp now) {
    if (closed_) {
      return;
    }
    last_rx_time_ = now;
    size_t offset = 0;
    while (offset < datagram.size()) {
      const ArrayView<const uint8_t> rem = datagram.subview(offset);
      bool is_long = false;
      QuicEncryptionLevel level = QuicEncryptionLevel::kOneRtt;
      QuicCid dcid{};
      QuicCid scid{};
      size_t pkt_len = 0;
      if (!QuicCryptoUtils::InspectHeaderIds(rem, &is_long, &level, &dcid,
                                             &scid, &pkt_len)) {
        break;
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
          ack_sets_[lvl_idx].largest_received());
      offset += pkt_len;
      if (!unprot.has_value()) {
        if (!is_long) {
          break;
        }
        continue;
      }

      if (ack_sets_[lvl_idx].Contains(unprot->packet_number)) {
        if (!is_long) {
          break;
        }
        continue;
      }

      if (!is_server_ && is_long && !peer_scid_learned_) {
        peer_dcid_ = unprot->scid;
        peer_scid_learned_ = true;
      } else if (is_server_ && level == QuicEncryptionLevel::kInitial &&
                 !peer_scid_learned_) {
        peer_dcid_ = unprot->scid;
        peer_scid_learned_ = true;
      }

      bool ack_eliciting = false;
      if (ProcessFrames(level, unprot->plaintext, now, &ack_eliciting)) {
        ack_sets_[lvl_idx].RecordReceived(unprot->packet_number, ack_eliciting);
        last_rx_pn_time_[lvl_idx] = now;
      }

      if (!is_long || closed_) {
        break;
      }
    }

    if (!closed_) {
      FlushPackets(now, false);
    }
  }

  void OnPeriodicTimer(Timestamp now) {
    if (closed_) {
      return;
    }

    // 空闲超时检查。
    if (last_rx_time_.IsFinite() &&
        (now - last_rx_time_) >
            TimeDelta::Millis(static_cast<int64_t>(local_tp_.max_idle_timeout_ms))) {
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
        if (pto_count_ >= 3 && cc_) {
          cc_->OnPersistentCongestion(now.us());
        }
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

  struct SentRetransmittable {
    enum class Kind : uint8_t {
      kCrypto,
      kStream,
      kResetStream,
      kHandshakeDone,
    };
    Kind kind = Kind::kStream;
    QuicEncryptionLevel crypto_level = QuicEncryptionLevel::kInitial;
    uint64_t offset = 0;
    std::vector<uint8_t> data;
    StreamChunk stream_chunk;
    PendingReset reset_info;
  };

  struct SentPacketInfo {
    uint64_t pn = 0;
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
    std::vector<uint8_t> unsent_data;
    bool fin_queued = false;
    bool fin_sent = false;
    bool reset = false;
    std::deque<StreamChunk> retransmit_chunks;
  };

  // ---------------- 握手消息构造与解析 ----------------

  std::vector<uint8_t> BuildClientHello() const {
    const auto tp_bytes = local_tp_.Encode();
    std::vector<uint8_t> body;
    body.insert(body.end(), local_random_.begin(), local_random_.end());
    body.insert(body.end(), local_x25519_pub_.begin(), local_x25519_pub_.end());
    QuicVarInt::AppendString(alpn_, &body);
    QuicVarInt::Append(tp_bytes.size(), &body);
    body.insert(body.end(), tp_bytes.begin(), tp_bytes.end());

    std::vector<uint8_t> msg;
    msg.push_back(kCryptoMsgClientHello);
    QuicVarInt::Append(body.size(), &msg);
    msg.insert(msg.end(), body.begin(), body.end());
    return msg;
  }

  std::vector<uint8_t> BuildServerHello() const {
    std::vector<uint8_t> body;
    body.insert(body.end(), local_random_.begin(), local_random_.end());
    body.insert(body.end(), local_x25519_pub_.begin(), local_x25519_pub_.end());

    std::vector<uint8_t> msg;
    msg.push_back(kCryptoMsgServerHello);
    QuicVarInt::Append(body.size(), &msg);
    msg.insert(msg.end(), body.begin(), body.end());
    return msg;
  }

  std::vector<uint8_t> BuildServerEncryptedExtAndFinished(
      ArrayView<const uint8_t> hello_transcript) {
    const auto tp_bytes = local_tp_.Encode();
    std::vector<uint8_t> ee_part;
    QuicVarInt::AppendString(alpn_, &ee_part);
    QuicVarInt::Append(tp_bytes.size(), &ee_part);
    ee_part.insert(ee_part.end(), tp_bytes.begin(), tp_bytes.end());

    std::vector<uint8_t> transcript(hello_transcript.begin(),
                                    hello_transcript.end());
    transcript.insert(transcript.end(), ee_part.begin(), ee_part.end());
    const auto thash = QuicCryptoUtils::Sha256(transcript);

    std::array<uint8_t, 32> fin_key{};
    QuicCryptoUtils::HkdfExpandLabel(
        tx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].secret,
        "finished", ArrayView<const uint8_t>(), fin_key.data(), fin_key.size());
    std::array<uint8_t, 32> verify_data{};
    QuicCryptoUtils::HmacSha256(fin_key, thash, &verify_data);

    std::vector<uint8_t> body = std::move(ee_part);
    body.insert(body.end(), verify_data.begin(), verify_data.end());

    std::vector<uint8_t> msg;
    msg.push_back(kCryptoMsgServerEncryptedExtFinished);
    QuicVarInt::Append(body.size(), &msg);
    msg.insert(msg.end(), body.begin(), body.end());
    return msg;
  }

  bool DeriveHandshakeSecrets(const std::array<uint8_t, 32>& peer_x25519_pub,
                              ArrayView<const uint8_t> hello_transcript) {
    std::array<uint8_t, 32> ecdhe_shared{};
    if (!QuicCryptoUtils::ComputeX25519SharedSecret(
            local_x25519_priv_, peer_x25519_pub, &ecdhe_shared)) {
      return false;
    }
    if (!QuicCryptoUtils::HkdfExtract(initial_secret_, ecdhe_shared,
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

  bool DeriveApplicationSecrets(ArrayView<const uint8_t> full_server_transcript) {
    const std::array<uint8_t, 32> zeros{};
    std::array<uint8_t, 32> master_root{};
    if (!QuicCryptoUtils::HkdfExtract(handshake_root_secret_, zeros,
                                      &master_root)) {
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
    while (buf.size() >= 2) {
      const uint8_t msg_type = buf[0];
      size_t off = 1;
      uint64_t body_len = 0;
      if (!QuicVarInt::Read(buf, &off, &body_len) ||
          off + body_len > buf.size()) {
        break;
      }
      const size_t total_msg_len = off + static_cast<size_t>(body_len);
      const std::vector<uint8_t> raw_msg(
          buf.begin(), buf.begin() + static_cast<ptrdiff_t>(total_msg_len));
      const ArrayView<const uint8_t> body(raw_msg.data() + off,
                                           static_cast<size_t>(body_len));
      buf.erase(buf.begin(),
                buf.begin() + static_cast<ptrdiff_t>(total_msg_len));

      if (is_server_ && level == QuicEncryptionLevel::kInitial &&
          msg_type == kCryptoMsgClientHello && !server_hello_sent_) {
        if (body.size() < 64) {
          continue;
        }
        std::array<uint8_t, 32> peer_pub{};
        std::memcpy(peer_pub.data(), body.data() + 32, 32);
        size_t boff = 64;
        std::string client_alpn;
        uint64_t tp_len = 0;
        if (!QuicVarInt::ReadString(body, &boff, &client_alpn) ||
            !QuicVarInt::Read(body, &boff, &tp_len) ||
            boff + tp_len > body.size()) {
          continue;
        }
        auto parsed_tp = QuicTransportParameters::Decode(
            body.subview(boff, static_cast<size_t>(tp_len)));
        if (!parsed_tp.has_value()) {
          continue;
        }
        peer_tp_ = *parsed_tp;
        client_hello_bytes_ = raw_msg;
        server_hello_bytes_ = BuildServerHello();

        std::vector<uint8_t> hello_transcript = client_hello_bytes_;
        hello_transcript.insert(hello_transcript.end(),
                                server_hello_bytes_.begin(),
                                server_hello_bytes_.end());
        if (!DeriveHandshakeSecrets(peer_pub, hello_transcript)) {
          continue;
        }
        server_ee_fin_bytes_ =
            BuildServerEncryptedExtAndFinished(hello_transcript);

        full_hs_transcript_ = std::move(hello_transcript);
        full_hs_transcript_.insert(full_hs_transcript_.end(),
                                   server_ee_fin_bytes_.begin(),
                                   server_ee_fin_bytes_.end());
        if (!DeriveApplicationSecrets(full_hs_transcript_)) {
          continue;
        }

        server_hello_sent_ = true;
        QueueCryptoData(QuicEncryptionLevel::kInitial, server_hello_bytes_);
        QueueCryptoData(QuicEncryptionLevel::kHandshake, server_ee_fin_bytes_);
      } else if (!is_server_ && level == QuicEncryptionLevel::kInitial &&
                 msg_type == kCryptoMsgServerHello &&
                 !rx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].valid) {
        if (body.size() < 64) {
          continue;
        }
        std::array<uint8_t, 32> peer_pub{};
        std::memcpy(peer_pub.data(), body.data() + 32, 32);
        server_hello_bytes_ = raw_msg;

        std::vector<uint8_t> hello_transcript = client_hello_bytes_;
        hello_transcript.insert(hello_transcript.end(),
                                server_hello_bytes_.begin(),
                                server_hello_bytes_.end());
        DeriveHandshakeSecrets(peer_pub, hello_transcript);
      } else if (!is_server_ && level == QuicEncryptionLevel::kHandshake &&
                 msg_type == kCryptoMsgServerEncryptedExtFinished &&
                 !handshake_established_) {
        size_t boff = 0;
        std::string negotiated_alpn;
        uint64_t tp_len = 0;
        if (!QuicVarInt::ReadString(body, &boff, &negotiated_alpn) ||
            !QuicVarInt::Read(body, &boff, &tp_len) ||
            boff + tp_len + 32 > body.size()) {
          continue;
        }
        const size_t ee_len = boff + static_cast<size_t>(tp_len);
        auto parsed_tp = QuicTransportParameters::Decode(
            body.subview(boff, static_cast<size_t>(tp_len)));
        if (!parsed_tp.has_value()) {
          continue;
        }

        std::vector<uint8_t> transcript = client_hello_bytes_;
        transcript.insert(transcript.end(), server_hello_bytes_.begin(),
                          server_hello_bytes_.end());
        transcript.insert(transcript.end(), body.data(), body.data() + ee_len);
        const auto thash = QuicCryptoUtils::Sha256(transcript);

        std::array<uint8_t, 32> s_fin_key{};
        QuicCryptoUtils::HkdfExpandLabel(
            rx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].secret,
            "finished", ArrayView<const uint8_t>(), s_fin_key.data(),
            s_fin_key.size());
        std::array<uint8_t, 32> expected_mac{};
        QuicCryptoUtils::HmacSha256(s_fin_key, thash, &expected_mac);
        if (CRYPTO_memcmp(expected_mac.data(), body.data() + ee_len, 32) != 0) {
          RTC_LOG(kError) << "QUIC ServerFinished HMAC verification failed";
          closed_ = true;
          events_->OnConnectionClosed(-102);
          return;
        }

        peer_tp_ = *parsed_tp;
        full_hs_transcript_ = client_hello_bytes_;
        full_hs_transcript_.insert(full_hs_transcript_.end(),
                                   server_hello_bytes_.begin(),
                                   server_hello_bytes_.end());
        full_hs_transcript_.insert(full_hs_transcript_.end(), raw_msg.begin(),
                                   raw_msg.end());
        if (!DeriveApplicationSecrets(full_hs_transcript_)) {
          continue;
        }

        // 在 Handshake 加密级别 CRYPTO 空间中构造并发送 ClientFinished 消息。
        const auto full_hash = QuicCryptoUtils::Sha256(full_hs_transcript_);
        std::array<uint8_t, 32> c_fin_key{};
        QuicCryptoUtils::HkdfExpandLabel(
            tx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].secret,
            "finished", ArrayView<const uint8_t>(), c_fin_key.data(),
            c_fin_key.size());
        std::array<uint8_t, 32> client_verify{};
        QuicCryptoUtils::HmacSha256(c_fin_key, full_hash, &client_verify);

        std::vector<uint8_t> cfin_msg;
        cfin_msg.push_back(kCryptoMsgClientFinished);
        QuicVarInt::Append(client_verify.size(), &cfin_msg);
        cfin_msg.insert(cfin_msg.end(), client_verify.begin(),
                        client_verify.end());
        QueueCryptoData(QuicEncryptionLevel::kHandshake, cfin_msg);

        handshake_established_ = true;
        events_->OnHandshakeEstablished();
      } else if (is_server_ && level == QuicEncryptionLevel::kHandshake &&
                 msg_type == kCryptoMsgClientFinished &&
                 !handshake_established_) {
        if (body.size() != 32) {
          continue;
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
          closed_ = true;
          events_->OnConnectionClosed(-103);
          return;
        }

        handshake_established_ = true;
        pending_handshake_done_ = true;
        events_->OnHandshakeEstablished();
      }
    }
  }

  // ---------------- 帧解析与丢包/拥塞恢复 ----------------

  bool ProcessFrames(QuicEncryptionLevel level,
                     ArrayView<const uint8_t> payload,
                     Timestamp now,
                     bool* out_ack_eliciting) {
    *out_ack_eliciting = false;
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

      if (frame_type == kFramePing) {
        *out_ack_eliciting = true;
      } else if (frame_type == kFrameAck || frame_type == kFrameAckEcn) {
        off = type_start;
        uint64_t ack_delay_us = 0;
        std::vector<QuicAckRangeSet::Range> ranges;
        if (!QuicAckRangeSet::DecodeAckFrame(payload, &off, &ack_delay_us,
                                             &ranges)) {
          return false;
        }
        OnAckReceived(level, ack_delay_us, ranges, now);
      } else if (frame_type == kFrameCrypto) {
        *out_ack_eliciting = true;
        uint64_t crypto_off = 0;
        uint64_t crypto_len = 0;
        if (!QuicVarInt::Read(payload, &off, &crypto_off) ||
            !QuicVarInt::Read(payload, &off, &crypto_len) ||
            off + crypto_len > payload.size()) {
          return false;
        }
        crypto_rx_reassembler_[LevelIndex(level)].InsertChunk(
            crypto_off, payload.subview(off, static_cast<size_t>(crypto_len)),
            false);
        off += static_cast<size_t>(crypto_len);
        HandleCryptoBytes(level);
        if (level == QuicEncryptionLevel::kHandshake &&
            rx_keys_[LevelIndex(QuicEncryptionLevel::kHandshake)].valid &&
            !crypto_rx_buf_[LevelIndex(QuicEncryptionLevel::kHandshake)]
                 .empty()) {
          HandleCryptoBytes(QuicEncryptionLevel::kHandshake);
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
              off + stream_len > payload.size()) {
            return false;
          }
        }
        const bool fin = (frame_type & kFrameStreamFinBit) != 0;
        const ArrayView<const uint8_t> sdata =
            payload.subview(off, static_cast<size_t>(stream_len));
        off += static_cast<size_t>(stream_len);

        const bool is_peer_initiated =
            ((stream_id & 0x01u) == (is_server_ ? 0u : 1u));
        if (is_peer_initiated &&
            announced_inbound_streams_.insert(stream_id).second) {
          const bool uni = (stream_id & 0x02u) != 0;
          events_->OnPeerStreamOpened(stream_id, uni);
        }

        auto& rx_buf = inbound_streams_[stream_id];
        rx_buf.InsertChunk(stream_off, sdata, fin);
        std::vector<uint8_t> ordered;
        bool deliver_fin = false;
        if (rx_buf.ExtractContiguous(&ordered, &deliver_fin)) {
          events_->OnPeerStreamData(stream_id, ordered, deliver_fin);
        }
      } else if (frame_type == kFrameResetStream) {
        *out_ack_eliciting = true;
        uint64_t stream_id = 0;
        uint64_t app_err = 0;
        uint64_t final_size = 0;
        if (!QuicVarInt::Read(payload, &off, &stream_id) ||
            !QuicVarInt::Read(payload, &off, &app_err) ||
            !QuicVarInt::Read(payload, &off, &final_size)) {
          return false;
        }
        auto& rx_buf = inbound_streams_[stream_id];
        if (!rx_buf.is_reset()) {
          rx_buf.Reset();
          events_->OnPeerStreamReset(stream_id, app_err);
        }
      } else if (frame_type == kFrameStopSending) {
        *out_ack_eliciting = true;
        uint64_t stream_id = 0;
        uint64_t app_err = 0;
        if (!QuicVarInt::Read(payload, &off, &stream_id) ||
            !QuicVarInt::Read(payload, &off, &app_err)) {
          return false;
        }
        ResetStream(stream_id, app_err);
      } else if (frame_type == kFrameMaxData) {
        *out_ack_eliciting = true;
        uint64_t max_data = 0;
        if (!QuicVarInt::Read(payload, &off, &max_data)) {
          return false;
        }
      } else if (frame_type == kFrameMaxStreamData) {
        *out_ack_eliciting = true;
        uint64_t sid = 0;
        uint64_t max_sdata = 0;
        if (!QuicVarInt::Read(payload, &off, &sid) ||
            !QuicVarInt::Read(payload, &off, &max_sdata)) {
          return false;
        }
      } else if (frame_type == kFrameHandshakeDone) {
        *out_ack_eliciting = true;
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

  void OnAckReceived(QuicEncryptionLevel level,
                     uint64_t ack_delay_us,
                     const std::vector<QuicAckRangeSet::Range>& ranges,
                     Timestamp now) {
    if (ranges.empty()) {
      return;
    }
    const size_t idx = LevelIndex(level);
    const uint64_t largest_acked = ranges.front().largest;
    largest_acked_pn_[idx] = std::max<int64_t>(
        largest_acked_pn_[idx], static_cast<int64_t>(largest_acked));

    auto& sent_map = sent_packets_[idx];
    const auto largest_it = sent_map.find(largest_acked);
    if (largest_it != sent_map.end() && largest_it->second.ack_eliciting) {
      const TimeDelta latest_rtt =
          std::max(TimeDelta::Micros(500), now - largest_it->second.sent_time);
      UpdateRtt(latest_rtt,
                level == QuicEncryptionLevel::kOneRtt
                    ? TimeDelta::Micros(static_cast<int64_t>(ack_delay_us))
                    : TimeDelta::Zero());
    }

    const size_t prior_in_flight = bytes_in_flight_;
    size_t newly_acked_bytes = 0;
    uint32_t newly_acked_pkts = 0;
    std::vector<QuicAckedPacket> acked_vec;
    for (const auto& range : ranges) {
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
          ap.packet_number = it->first;
          ap.bytes = it->second.sent_bytes;
          ap.sent_time_us = it->second.sent_time.us();
          ap.prior_in_flight_bytes = it->second.prior_in_flight_bytes;
          ap.delivered_bytes_at_send = it->second.delivered_bytes_at_send;
          ap.delivered_time_us_at_send = it->second.delivered_time_us_at_send;
          ap.first_sent_time_us_at_send = it->second.first_sent_time_us_at_send;
          ap.is_app_limited = it->second.is_app_limited;
          acked_vec.push_back(ap);
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
              it->first, it->second.sent_bytes, it->second.sent_time.us()});
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
    const TimeDelta base =
        smoothed_rtt_ +
        std::max(rttvar_ * 4, TimeDelta::Millis(1)) +
        TimeDelta::Millis(5);
    const uint32_t shift = std::min<uint32_t>(pto_count_, 6);
    return std::min(TimeDelta::Millis(2000), base * (int64_t{1} << shift));
  }

  void RequeueOldestInFlightForPto() {
    for (QuicEncryptionLevel lvl :
         {QuicEncryptionLevel::kInitial, QuicEncryptionLevel::kHandshake,
          QuicEncryptionLevel::kOneRtt}) {
      auto& sent_map = sent_packets_[LevelIndex(lvl)];
      for (auto it = sent_map.begin(); it != sent_map.end(); ++it) {
        if (it->second.ack_eliciting) {
          if (it->second.in_flight) {
            bytes_in_flight_ =
                (bytes_in_flight_ >= it->second.sent_bytes)
                    ? (bytes_in_flight_ - it->second.sent_bytes)
                    : 0;
          }
          RequeueRetransmittables(std::move(it->second.frames));
          sent_map.erase(it);
          break;
        }
      }
    }
  }

  void RequeueRetransmittables(std::vector<SentRetransmittable>&& frames) {
    for (auto& item : frames) {
      switch (item.kind) {
        case SentRetransmittable::Kind::kCrypto:
          crypto_tx_queue_[LevelIndex(item.crypto_level)].push_front(
              std::move(item));
          break;
        case SentRetransmittable::Kind::kStream: {
          const auto st_it = outbound_streams_.find(item.stream_chunk.stream_id);
          if (st_it != outbound_streams_.end() && !st_it->second.reset) {
            st_it->second.retransmit_chunks.push_front(
                std::move(item.stream_chunk));
          }
          break;
        }
        case SentRetransmittable::Kind::kResetStream:
          pending_resets_.push_front(item.reset_info);
          break;
        case SentRetransmittable::Kind::kHandshakeDone:
          pending_handshake_done_ = true;
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
    prefix.push_back(static_cast<uint8_t>(kQuicCidLength));
    prefix.insert(prefix.end(), peer_dcid_.begin(), peer_dcid_.end());
    prefix.push_back(static_cast<uint8_t>(kQuicCidLength));
    prefix.insert(prefix.end(), local_scid_.begin(), local_scid_.end());
    if (level == QuicEncryptionLevel::kInitial) {
      prefix.push_back(0x00u);  // 令牌长度（Token Length）= 0
    }
    return prefix;
  }

  void EmitSinglePacket(QuicEncryptionLevel level,
                        ArrayView<const uint8_t> frames_payload,
                        bool ack_eliciting,
                        std::vector<SentRetransmittable>&& tracked_frames,
                        Timestamp now) {
    const size_t idx = LevelIndex(level);
    if (!tx_keys_[idx].valid || frames_payload.empty()) {
      return;
    }

    const uint64_t pn = next_tx_pn_[idx]++;
    const auto hdr_prefix = BuildUnmaskedHeaderPrefix(level);
    const size_t min_dgram =
        (!is_server_ && level == QuicEncryptionLevel::kInitial)
            ? kQuicMinClientInitialSize
            : 0;

    const auto wire_pkt = QuicCryptoUtils::ProtectPacket(
        tx_keys_[idx], pn, hdr_prefix, level != QuicEncryptionLevel::kOneRtt,
        frames_payload, min_dgram);
    if (wire_pkt.empty()) {
      return;
    }

    const size_t prior_in_flight = bytes_in_flight_;
    const size_t cur_cwnd =
        cc_ ? cc_->GetCongestionWindowBytes() : (10 * kQuicMaxDatagramSize);
    if (prior_in_flight == 0 && ack_eliciting) {
      conn_first_sent_time_us_ = now.us();
      conn_delivered_time_us_ = now.us();
    }

    SentPacketInfo info;
    info.pn = pn;
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
      cc_->OnPacketSent(now.us(), pn, info.sent_bytes, info.in_flight,
                        prior_in_flight);
    }
    ++total_packets_sent_;
    sent_packets_[idx].emplace(pn, std::move(info));

    events_->SendUdpDatagram(wire_pkt);
  }

  void FlushInitialOrHandshakeSpace(QuicEncryptionLevel level, Timestamp now) {
    const size_t idx = LevelIndex(level);
    if (!tx_keys_[idx].valid) {
      return;
    }

    while (ack_sets_[idx].needs_ack() || !crypto_tx_queue_[idx].empty()) {
      std::vector<uint8_t> payload;
      std::vector<SentRetransmittable> tracked;
      bool ack_eliciting = false;

      if (ack_sets_[idx].needs_ack()) {
        const uint64_t delay_us =
            last_rx_pn_time_[idx].IsFinite()
                ? static_cast<uint64_t>(
                      std::max<int64_t>(0, (now - last_rx_pn_time_[idx]).us()))
                : 0;
        ack_sets_[idx].EncodeAckFrame(delay_us, &payload);
        ack_sets_[idx].ClearAckNeeded();
      }

      while (!crypto_tx_queue_[idx].empty() && payload.size() < 950) {
        auto item = std::move(crypto_tx_queue_[idx].front());
        crypto_tx_queue_[idx].pop_front();
        const size_t max_chunk = 980 - payload.size();
        if (item.data.size() > max_chunk) {
          SentRetransmittable rem;
          rem.kind = SentRetransmittable::Kind::kCrypto;
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

      if (payload.empty()) {
        break;
      }
      EmitSinglePacket(level, payload, ack_eliciting, std::move(tracked), now);
    }
  }

  OutboundStreamState* SelectHighestPriorityReadyStream() {
    OutboundStreamState* best = nullptr;
    for (auto& [sid, st] : outbound_streams_) {
      (void)sid;
      if (st.reset) {
        continue;
      }
      const bool has_work = !st.retransmit_chunks.empty() ||
                            !st.unsent_data.empty() ||
                            (st.fin_queued && !st.fin_sent);
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
      OutboundStreamState* ready_stream =
          can_send_in_flight ? SelectHighestPriorityReadyStream() : nullptr;
      const bool has_ctrl_frames =
          can_send_in_flight &&
          (pending_handshake_done_ || !pending_resets_.empty());

      if (!need_ack && !has_ctrl_frames && ready_stream == nullptr &&
          !pto_probe) {
        break;
      }

      std::vector<uint8_t> payload;
      payload.reserve(kQuicMaxDatagramSize);
      std::vector<SentRetransmittable> tracked;
      bool ack_eliciting = false;
      constexpr size_t kMaxPlaintextBudget =
          kQuicMaxDatagramSize - (1 + kQuicCidLength + 4 + kQuicAeadTagLength);

      if (need_ack) {
        const uint64_t delay_us =
            last_rx_pn_time_[idx].IsFinite()
                ? static_cast<uint64_t>(
                      std::max<int64_t>(0, (now - last_rx_pn_time_[idx]).us()))
                : 0;
        ack_sets_[idx].EncodeAckFrame(delay_us, &payload);
        ack_sets_[idx].ClearAckNeeded();
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

      while (can_send_in_flight &&
             payload.size() + 32 < kMaxPlaintextBudget) {
        OutboundStreamState* st = SelectHighestPriorityReadyStream();
        if (st == nullptr) {
          break;
        }
        const size_t max_data_slice = kMaxPlaintextBudget - payload.size() - 24;
        StreamChunk chunk;
        chunk.stream_id = st->stream_id;

        if (!st->retransmit_chunks.empty()) {
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
          chunk.offset = st->next_send_offset;
          const size_t take = std::min(st->unsent_data.size(), max_data_slice);
          chunk.data.assign(
              st->unsent_data.begin(),
              st->unsent_data.begin() + static_cast<ptrdiff_t>(take));
          st->unsent_data.erase(
              st->unsent_data.begin(),
              st->unsent_data.begin() + static_cast<ptrdiff_t>(take));
          st->next_send_offset += take;
          if (st->unsent_data.empty() && st->fin_queued && !st->fin_sent) {
            chunk.fin = true;
            st->fin_sent = true;
          }
        }

        EncodeStreamFrame(chunk, &payload);
        SentRetransmittable item;
        item.kind = SentRetransmittable::Kind::kStream;
        item.stream_chunk = std::move(chunk);
        tracked.push_back(std::move(item));
        ack_eliciting = true;
      }

      if (payload.empty() && pto_probe) {
        QuicVarInt::Append(kFramePing, &payload);
        ack_eliciting = true;
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
    FlushInitialOrHandshakeSpace(QuicEncryptionLevel::kInitial, now);
    FlushInitialOrHandshakeSpace(QuicEncryptionLevel::kHandshake, now);
    FlushOneRttSpace(now, pto_probe);
  }

  Clock* const clock_;
  const bool is_server_;
  const QuicCid local_scid_;
  QuicCid peer_dcid_;
  const QuicCid initial_dcid_;
  bool peer_scid_learned_ = false;
  const std::string alpn_;
  QuicSessionEvents* const events_;

  QuicTransportParameters local_tp_;
  QuicTransportParameters peer_tp_;

  std::array<uint8_t, 32> initial_secret_{};
  std::array<uint8_t, 32> handshake_root_secret_{};
  std::array<uint8_t, 32> local_x25519_priv_{};
  std::array<uint8_t, 32> local_x25519_pub_{};
  std::array<uint8_t, 32> local_random_{};

  std::vector<uint8_t> client_hello_bytes_;
  std::vector<uint8_t> server_hello_bytes_;
  std::vector<uint8_t> server_ee_fin_bytes_;
  std::vector<uint8_t> full_hs_transcript_;

  bool server_hello_sent_ = false;
  bool handshake_established_ = false;
  bool pending_handshake_done_ = false;
  bool closed_ = false;

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
  std::deque<PendingReset> pending_resets_;
  std::map<uint64_t, QuicStreamReceiveBuffer> inbound_streams_;
  std::set<uint64_t> announced_inbound_streams_;

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
  uint64_t total_packets_sent_ = 0;
  uint64_t total_packets_lost_ = 0;

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
    auto self = shared_from_this();
    network_queue_->PostTask(
        SafeTask(safety_.flag(), [self, host, port, alpn]() {
          RTC_DCHECK_RUN_ON(&self->net_checker_);
          boost::system::error_code ec;
          boost::asio::ip::udp::resolver resolver(
              self->network_queue_->io_context());
          auto endpoints = resolver.resolve(
              boost::asio::ip::udp::v4(), host, std::to_string(port), ec);
          if (ec || endpoints.begin() == endpoints.end()) {
            RTC_LOG(kError) << "QUIC DNS/endpoint resolve failed for " << host
                            << ":" << port << " (" << ec.message() << ")";
            if (auto* obs = self->observer_.load(std::memory_order_acquire)) {
              obs->OnQuicDisconnected(-101);
            }
            return;
          }
          self->remote_endpoint_ = *endpoints.begin();

          self->socket_.open(boost::asio::ip::udp::v4(), ec);
          if (!ec) {
            self->socket_.bind(
                boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0),
                ec);
          }
          if (ec) {
            RTC_LOG(kError) << "QUIC client UDP socket open/bind failed: "
                            << ec.message();
            if (auto* obs = self->observer_.load(std::memory_order_acquire)) {
              obs->OnQuicDisconnected(-104);
            }
            return;
          }

          const QuicCid local_scid = QuicCryptoUtils::GenerateRandomCid();
          const QuicCid init_dcid = QuicCryptoUtils::GenerateRandomCid();
          self->core_ = std::make_unique<QuicSessionCore>(
              self->clock_, /*is_server=*/false, local_scid, init_dcid, alpn,
              self.get(), std::move(self->pending_cc_));

          self->StartReceiveLoop();
          self->core_->StartClientHandshake();
          self->SchedulePeriodicTick();
        }));
    return 0;
  }

  void Close(uint64_t app_error_code) {
    if (network_queue_->IsStopped()) {
      return;
    }
    network_queue_->Invoke([this, app_error_code]() {
      RTC_DCHECK_RUN_ON(&net_checker_);
      safety_.flag()->SetNotAlive();
      if (core_ && !core_->is_closed()) {
        core_->CloseConnection(app_error_code);
      }
      boost::system::error_code ec;
      socket_.close(ec);
      core_.reset();
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
          }
        }));
    return id;
  }

  int WriteStream(uint64_t stream_id, ArrayView<const uint8_t> data, bool fin) {
    std::vector<uint8_t> copy(data.begin(), data.end());
    auto self = shared_from_this();
    network_queue_->PostTask(SafeTask(
        safety_.flag(), [self, stream_id, buf = std::move(copy), fin]() {
          RTC_DCHECK_RUN_ON(&self->net_checker_);
          if (self->core_) {
            self->core_->WriteStream(stream_id, buf, fin);
            self->UpdateCachedSnapshot();
          }
        }));
    return static_cast<int>(data.size());
  }

  void ResetStream(uint64_t stream_id, uint64_t app_error_code) {
    auto self = shared_from_this();
    network_queue_->PostTask(
        SafeTask(safety_.flag(), [self, stream_id, app_error_code]() {
          RTC_DCHECK_RUN_ON(&self->net_checker_);
          if (self->core_) {
            self->core_->ResetStream(stream_id, app_error_code);
          }
        }));
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
    UpdateCachedSnapshot();
    if (auto* obs = observer_.load(std::memory_order_acquire)) {
      obs->OnQuicConnected();
    }
  }

  void OnConnectionClosed(int error_code) override {
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

 private:
  void StartReceiveLoop() {
    if (!socket_.is_open()) {
      return;
    }
    auto self = shared_from_this();
    socket_.async_receive_from(
        boost::asio::buffer(rx_buf_), sender_endpoint_,
        [self](const boost::system::error_code& ec, size_t nbytes) {
          if (ec || !self->safety_.flag()->alive()) {
            return;
          }
          if (nbytes > 0 &&
              !ShouldSimulateDrop(
                  self->rx_drop_prob_.load(std::memory_order_relaxed)) &&
              self->core_) {
            self->core_->ProcessUdpDatagram(
                ArrayView<const uint8_t>(self->rx_buf_.data(), nbytes),
                self->clock_->CurrentTime());
            self->UpdateCachedSnapshot();
          }
          self->StartReceiveLoop();
        });
  }

  void SchedulePeriodicTick() {
    auto self = shared_from_this();
    network_queue_->PostDelayedTask(
        SafeTask(safety_.flag(),
                 [self]() {
                   RTC_DCHECK_RUN_ON(&self->net_checker_);
                   if (self->core_ && !self->core_->is_closed()) {
                     self->core_->OnPeriodicTimer(self->clock_->CurrentTime());
                     self->UpdateCachedSnapshot();
                     self->SchedulePeriodicTick();
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
    std::lock_guard<std::mutex> lock(snap_mutex_);
    cached_snapshot_ = snap;
  }

  Clock* const clock_;
  TaskQueueBoost* const network_queue_;
  SequenceChecker net_checker_;
  boost::asio::ip::udp::socket socket_;
  boost::asio::ip::udp::endpoint remote_endpoint_;
  boost::asio::ip::udp::endpoint sender_endpoint_;
  std::array<uint8_t, 2048> rx_buf_{};

  std::unique_ptr<QuicSessionCore> core_;
  std::unique_ptr<IQuicCongestionController> pending_cc_;
  std::atomic<IMoqQuicEngineObserver*> observer_{nullptr};
  std::atomic<uint64_t> next_bidi_id_{0};
  std::atomic<uint64_t> next_uni_id_{2};
  std::atomic<double> tx_drop_prob_{0.0};
  std::atomic<double> rx_drop_prob_{0.0};

  mutable std::mutex snap_mutex_;
  QuicCongestionSnapshot cached_snapshot_;
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

QuicCongestionSnapshot AsioQuicClientEngine::GetCongestionSnapshot() const {
  return impl_->GetCongestionSnapshot();
}

int AsioQuicClientEngine::SetCongestionController(
    std::unique_ptr<IQuicCongestionController> controller) {
  return impl_->SetCongestionController(std::move(controller));
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
             std::string expected_alpn)
      : clock_(clock),
        network_queue_(network_queue),
        net_checker_(network_queue),
        visitor_(visitor),
        bind_ip_(std::move(bind_ip)),
        expected_alpn_(std::move(expected_alpn)),
        socket_(network_queue->io_context()),
        safety_(PendingTaskSafetyFlag::CreateDetached()) {}

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
                parent->expected_alpn_,
                this,
                std::move(initial_cc)) {
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
      auto self = shared_from_this();
      parent_->network_queue_->PostTask(SafeTask(
          parent_->safety_.flag(), [self, stream_id, app_error_code]() {
            RTC_DCHECK_RUN_ON(&self->parent_->net_checker_);
            if (!self->core_.is_closed()) {
              self->core_.ResetStream(stream_id, app_error_code);
            }
          }));
    }

    void Close(uint64_t app_error_code) override {
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
      if (!core_.is_closed()) {
        core_.CloseConnection(app_error_code);
      }
    }

    void ProcessDatagram(const boost::asio::ip::udp::endpoint& sender_ep,
                         ArrayView<const uint8_t> datagram,
                         Timestamp now) {
      peer_endpoint_ = sender_ep;
      core_.ProcessUdpDatagram(datagram, now);
      UpdateCachedSnapshot();
    }

    void OnTimer(Timestamp now) {
      core_.OnPeriodicTimer(now);
      UpdateCachedSnapshot();
    }

    bool is_closed() const { return core_.is_closed(); }
    const QuicCid& server_scid() const { return server_scid_; }
    const QuicCid& client_initial_dcid() const { return client_initial_dcid_; }

    // QuicSessionEvents 接口重写：
    void SendUdpDatagram(ArrayView<const uint8_t> bytes) override {
      parent_->SendFromSession(peer_endpoint_, bytes);
    }

    void OnHandshakeEstablished() override {
      RTC_LOG(kInfo) << "AsioQuicServer session=" << id_
                     << " QUIC v1 handshake established from "
                     << peer_endpoint_.address().to_string() << ":"
                     << peer_endpoint_.port();
      if (parent_->visitor_ != nullptr) {
        parent_->visitor_->OnServerSessionConnected(shared_from_this());
      }
    }

    void OnConnectionClosed(int error_code) override {
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

   private:
    void UpdateCachedSnapshot() {
      const QuicCongestionSnapshot snap =
          core_.GetCongestionSnapshot(parent_->clock_->CurrentTime());
      std::lock_guard<std::mutex> lock(snap_mutex_);
      cached_snapshot_ = snap;
    }

    const uint64_t id_;
    ServerImpl* const parent_;
    const QuicCid server_scid_;
    const QuicCid client_initial_dcid_;
    boost::asio::ip::udp::endpoint peer_endpoint_;
    QuicSessionCore core_;
    bool disconnect_notified_ = false;
    std::atomic<uint64_t> next_bidi_id_{1};
    std::atomic<uint64_t> next_uni_id_{3};
    mutable std::mutex snap_mutex_;
    QuicCongestionSnapshot cached_snapshot_;
  };

  void StartReceiveLoop() {
    if (!socket_.is_open()) {
      return;
    }
    auto self = shared_from_this();
    socket_.async_receive_from(
        boost::asio::buffer(rx_buf_), sender_endpoint_,
        [self](const boost::system::error_code& ec, size_t nbytes) {
          if (ec || !self->safety_.flag()->alive()) {
            return;
          }
          if (nbytes > 0 &&
              !ShouldSimulateDrop(
                  self->rx_drop_prob_.load(std::memory_order_relaxed))) {
            self->RouteIncomingDatagram(
                self->sender_endpoint_,
                ArrayView<const uint8_t>(self->rx_buf_.data(), nbytes));
          }
          self->StartReceiveLoop();
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
      scid_it->second->ProcessDatagram(sender_ep, datagram, now);
      return;
    }

    auto init_it = sessions_by_initial_dcid_.find(dcid);
    if (init_it != sessions_by_initial_dcid_.end()) {
      init_it->second->ProcessDatagram(sender_ep, datagram, now);
      return;
    }

    // RFC 9000 第 14.1 节：强制要求客户端 Initial 数据包所在的 UDP 数据报至少为 1200 字节，
    // 以防止流量放大攻击。
    if (!is_long || level != QuicEncryptionLevel::kInitial ||
        datagram.size() < kQuicMinClientInitialSize) {
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
  }

  void SchedulePeriodicTick() {
    auto self = shared_from_this();
    network_queue_->PostDelayedTask(
        SafeTask(safety_.flag(),
                 [self]() {
                   RTC_DCHECK_RUN_ON(&self->net_checker_);
                   const Timestamp now = self->clock_->CurrentTime();
                   for (auto it = self->sessions_by_scid_.begin();
                        it != self->sessions_by_scid_.end();) {
                     it->second->OnTimer(now);
                     if (it->second->is_closed()) {
                       self->sessions_by_initial_dcid_.erase(
                           it->second->client_initial_dcid());
                       it = self->sessions_by_scid_.erase(it);
                     } else {
                       ++it;
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
  const std::string expected_alpn_;
  boost::asio::ip::udp::socket socket_;
  boost::asio::ip::udp::endpoint sender_endpoint_;
  std::array<uint8_t, 2048> rx_buf_{};

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
    : impl_(std::make_shared<ServerImpl>(clock,
                                         network_queue,
                                         visitor,
                                         std::move(bind_ip),
                                         std::move(expected_alpn))) {}

AsioQuicServer::~AsioQuicServer() { Stop(); }

bool AsioQuicServer::Start(uint16_t udp_port) {
  return impl_->Start(udp_port, &local_port_);
}

void AsioQuicServer::Stop() { impl_->Stop(); }

void AsioQuicServer::SetSimulatedDropRates(double rx_drop_prob,
                                           double tx_drop_prob) {
  impl_->SetSimulatedDropRates(rx_drop_prob, tx_drop_prob);
}

void AsioQuicServer::SetCongestionControllerFactory(
    std::shared_ptr<IQuicCongestionControllerFactory> factory) {
  impl_->SetCongestionControllerFactory(std::move(factory));
}

}  // namespace rtc