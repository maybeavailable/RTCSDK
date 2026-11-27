#include "pc/dtls_srtp_transport.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "modules/rtp_rtcp/byte_io.h"
#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"

namespace rtc {

void EnsureLibsrtpInitialized() {
  static std::once_flag once;
  std::call_once(once, []() {
    const srtp_err_status_t st = srtp_init();
    RTC_LOG(kInfo) << "libsrtp2 initialized (status=" << static_cast<int>(st)
                   << ")";
  });
}

// ======================= DtlsCertificate DTLS 证书管理 =======================

DtlsCertificate::DtlsCertificate(EVP_PKEY* pkey,
                                 X509* x509,
                                 std::string fingerprint)
    : pkey_(pkey), x509_(x509), fingerprint_(std::move(fingerprint)) {}

DtlsCertificate::~DtlsCertificate() {
  if (x509_ != nullptr) {
    X509_free(x509_);
  }
  if (pkey_ != nullptr) {
    EVP_PKEY_free(pkey_);
  }
}

std::string DtlsCertificate::ComputeX509Sha256Fingerprint(X509* cert) {
  if (cert == nullptr) {
    return "";
  }
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int md_len = 0;
  if (X509_digest(cert, EVP_sha256(), md, &md_len) != 1) {
    return "";
  }
  std::ostringstream oss;
  oss << std::uppercase << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < md_len; ++i) {
    if (i > 0) {
      oss << ':';
    }
    oss << std::setw(2) << static_cast<int>(md[i]);
  }
  return oss.str();
}

std::shared_ptr<DtlsCertificate> DtlsCertificate::GenerateEcdsaP256() {
  EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
  if (pkey == nullptr) {
    RTC_LOG(kError) << "OpenSSL EVP_PKEY_Q_keygen(EC P-256) failed";
    return nullptr;
  }

  X509* x509 = X509_new();
  if (x509 == nullptr) {
    EVP_PKEY_free(pkey);
    return nullptr;
  }
  X509_set_version(x509, 2);

  // RFC 5280 §4.1.2.2：生成随机正 64 位序列号，避免 Firefox 因自签证书相同序列号触发 SEC_ERROR_REUSED_ISSUER_AND_SERIAL。
  uint8_t serial_bytes[8]{};
  if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) {
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return nullptr;
  }
  serial_bytes[0] &= 0x7Fu;
  serial_bytes[0] |= 0x01u;
  BIGNUM* bn_serial = BN_bin2bn(serial_bytes, sizeof(serial_bytes), nullptr);
  if (bn_serial == nullptr ||
      BN_to_ASN1_INTEGER(bn_serial, X509_get_serialNumber(x509)) == nullptr) {
    BN_free(bn_serial);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return nullptr;
  }
  BN_free(bn_serial);

  X509_gmtime_adj(X509_get_notBefore(x509), -3600);
  X509_gmtime_adj(X509_get_notAfter(x509), 365L * 24 * 3600);
  X509_set_pubkey(x509, pkey);

  X509_NAME* name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(
      name, "CN", MBSTRING_ASC,
      reinterpret_cast<const unsigned char*>("rtc-video-sdk"), -1, -1, 0);
  X509_set_issuer_name(x509, name);

  if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
    X509_free(x509);
    EVP_PKEY_free(pkey);
    RTC_LOG(kError) << "OpenSSL X509_sign failed";
    return nullptr;
  }

  std::string fp = ComputeX509Sha256Fingerprint(x509);
  RTC_LOG(kInfo) << "Generated ephemeral ECDSA P-256 DTLS certificate (sha-256="
                 << fp.substr(0, 23) << "...)";
  return std::shared_ptr<DtlsCertificate>(
      new DtlsCertificate(pkey, x509, std::move(fp)));
}

// ======================= SrtpSessionPair SRTP 双工加解密会话 =======================

SrtpSessionPair::SrtpSessionPair() { EnsureLibsrtpInitialized(); }

SrtpSessionPair::~SrtpSessionPair() { Reset(); }

void SrtpSessionPair::Reset() {
  active_.store(false, std::memory_order_release);
  if (send_ctx_ != nullptr) {
    srtp_dealloc(send_ctx_);
    send_ctx_ = nullptr;
  }
  if (recv_ctx_ != nullptr) {
    srtp_dealloc(recv_ctx_);
    recv_ctx_ = nullptr;
  }
}

bool SrtpSessionPair::SetupKeys(
    SrtpCipherProfile profile,
    ArrayView<const uint8_t> send_master_key_and_salt,
    ArrayView<const uint8_t> recv_master_key_and_salt) {
  Reset();

  auto init_one = [profile](srtp_t* out_ctx, srtp_ssrc_type_t ssrc_type,
                            ArrayView<const uint8_t> key_salt) -> bool {
    srtp_policy_t policy{};
    std::memset(&policy, 0, sizeof(policy));
    if (profile == SrtpCipherProfile::kAeadAes128Gcm) {
      if (key_salt.size() != 28) {
        return false;
      }
      srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy.rtp);
      srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy.rtcp);
    } else {
      if (key_salt.size() != 30) {
        return false;
      }
      srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
      srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
    }
    policy.ssrc.type = ssrc_type;
    policy.ssrc.value = 0;
    policy.key = const_cast<uint8_t*>(key_salt.data());
    policy.window_size = 1024;
    policy.allow_repeat_tx = 0;
    policy.next = nullptr;
    return srtp_create(out_ctx, &policy) == srtp_err_status_ok;
  };

  if (!init_one(&send_ctx_, ssrc_any_outbound, send_master_key_and_salt)) {
    Reset();
    return false;
  }
  if (!init_one(&recv_ctx_, ssrc_any_inbound, recv_master_key_and_salt)) {
    Reset();
    return false;
  }
  active_.store(true, std::memory_order_release);
  return true;
}

bool SrtpSessionPair::ProtectRtp(std::vector<uint8_t>* packet_buf) {
  if (!IsActive() || packet_buf == nullptr || packet_buf->size() < 12) {
    return false;
  }
  int len = static_cast<int>(packet_buf->size());
  packet_buf->resize(packet_buf->size() + SRTP_MAX_TRAILER_LEN);
  if (srtp_protect(send_ctx_, packet_buf->data(), &len) != srtp_err_status_ok) {
    return false;
  }
  packet_buf->resize(static_cast<size_t>(len));
  return true;
}

bool SrtpSessionPair::ProtectRtcp(std::vector<uint8_t>* packet_buf) {
  if (!IsActive() || packet_buf == nullptr || packet_buf->size() < 8) {
    return false;
  }
  int len = static_cast<int>(packet_buf->size());
  packet_buf->resize(packet_buf->size() + SRTP_MAX_TRAILER_LEN + 4);
  if (srtp_protect_rtcp(send_ctx_, packet_buf->data(), &len) !=
      srtp_err_status_ok) {
    return false;
  }
  packet_buf->resize(static_cast<size_t>(len));
  return true;
}

bool SrtpSessionPair::UnprotectRtp(std::vector<uint8_t>* packet_buf) {
  if (!IsActive() || packet_buf == nullptr || packet_buf->size() < 12) {
    return false;
  }
  int len = static_cast<int>(packet_buf->size());
  if (srtp_unprotect(recv_ctx_, packet_buf->data(), &len) !=
      srtp_err_status_ok) {
    return false;
  }
  packet_buf->resize(static_cast<size_t>(len));
  return true;
}

bool SrtpSessionPair::UnprotectRtcp(std::vector<uint8_t>* packet_buf) {
  if (!IsActive() || packet_buf == nullptr || packet_buf->size() < 8) {
    return false;
  }
  int len = static_cast<int>(packet_buf->size());
  if (srtp_unprotect_rtcp(recv_ctx_, packet_buf->data(), &len) !=
      srtp_err_status_ok) {
    return false;
  }
  packet_buf->resize(static_cast<size_t>(len));
  return true;
}

// ======================= DtlsSrtpTransport DTLS-SRTP 安全传输层 =======================

namespace {
int AlwaysVerifyPeerCertCallback(int /*preverify_ok*/, X509_STORE_CTX* /*ctx*/) {
  return 1;
}

int DgramBioWrite(BIO* bio, const char* in, int inl) {
  if (in == nullptr || inl <= 0) {
    return 0;
  }
  auto* ice = static_cast<IceTransportChannel*>(BIO_get_data(bio));
  if (ice == nullptr) {
    return -1;
  }
  BIO_clear_retry_flags(bio);
  (void)ice->SendPacket(MakeArrayView(reinterpret_cast<const uint8_t*>(in),
                                      static_cast<size_t>(inl)));
  return inl;
}

long DgramBioCtrl(BIO* /*bio*/, int cmd, long /*num*/, void* /*ptr*/) {
  switch (cmd) {
    case BIO_CTRL_FLUSH:
      return 1;
    case BIO_CTRL_DGRAM_QUERY_MTU:
    case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
      return 1400;
    default:
      return 0;
  }
}

int DgramBioCreate(BIO* bio) {
  BIO_set_init(bio, 1);
  BIO_set_data(bio, nullptr);
  return 1;
}

int DgramBioDestroy(BIO* bio) {
  if (bio == nullptr) {
    return 0;
  }
  BIO_set_init(bio, 0);
  BIO_set_data(bio, nullptr);
  return 1;
}

BIO_METHOD* GetDgramWriteBioMethod() {
  static BIO_METHOD* method = []() {
    BIO_METHOD* m = BIO_meth_new(BIO_TYPE_DGRAM | BIO_TYPE_SOURCE_SINK,
                                 "rtc_dtls_dgram_wbio");
    BIO_meth_set_write(m, &DgramBioWrite);
    BIO_meth_set_ctrl(m, &DgramBioCtrl);
    BIO_meth_set_create(m, &DgramBioCreate);
    BIO_meth_set_destroy(m, &DgramBioDestroy);
    return m;
  }();
  return method;
}
}  // namespace

DtlsSrtpTransport::DtlsSrtpTransport(Clock* clock,
                                     TaskQueueBoost* network_queue,
                                     IceTransportChannel* ice_channel,
                                     std::shared_ptr<DtlsCertificate> local_cert,
                                     DtlsSrtpObserver* observer)
    : clock_(clock),
      network_queue_(network_queue),
      net_checker_(network_queue),
      ice_channel_(ice_channel),
      local_cert_(std::move(local_cert)),
      observer_(observer),
      dtls_app_rx_buf_(SSL3_RT_MAX_PLAIN_LENGTH, 0),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {
  ssl_ctx_ = SSL_CTX_new(DTLS_method());
  if (ssl_ctx_ != nullptr && local_cert_) {
    SSL_CTX_set_min_proto_version(ssl_ctx_, DTLS1_2_VERSION);
    SSL_CTX_use_certificate(ssl_ctx_, local_cert_->x509());
    SSL_CTX_use_PrivateKey(ssl_ctx_, local_cert_->pkey());
    SSL_CTX_set_verify(ssl_ctx_,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       &AlwaysVerifyPeerCertCallback);
    SSL_CTX_set_tlsext_use_srtp(ssl_ctx_,
                                "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80");
  }
}

DtlsSrtpTransport::~DtlsSrtpTransport() {
  network_queue_->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    safety_.flag()->SetNotAlive();
    ResetDtlsHandshakeState();
    srtp_.Reset();
    if (ssl_ctx_ != nullptr) {
      SSL_CTX_free(ssl_ctx_);
      ssl_ctx_ = nullptr;
    }
  });
}

void DtlsSrtpTransport::ResetDtlsHandshakeState() {
  ++timer_generation_;
  timer_scheduled_ = false;
  pending_dtls_packets_.clear();
  inbound_ssrcs_.clear();
  if (ssl_ != nullptr) {
    SSL_free(ssl_);
    ssl_ = nullptr;
  }
  read_bio_ = nullptr;
  write_bio_ = nullptr;
  handshake_started_ = false;
  handshake_complete_.store(false, std::memory_order_release);
  handshake_started_at_ = Timestamp::MinusInfinity();
}

void DtlsSrtpTransport::SetDtlsRoleAndRemoteFingerprint(
    DtlsRole role,
    std::string expected_sha256_fp) {
  network_queue_->PostTask(SafeTask(
      safety_.flag(),
      [this, role, fp = std::move(expected_sha256_fp)]() mutable {
        RTC_DCHECK_RUN_ON(&net_checker_);
        if (handshake_started_ &&
            (role_ != role || expected_remote_fingerprint_ != fp)) {
          ResetDtlsHandshakeState();
          srtp_.Reset();
        }
        role_ = role;
        expected_remote_fingerprint_ = std::move(fp);
        StartHandshakeIfReady();
      }));
}

void DtlsSrtpTransport::SetRtpHeaderExtensionMap(
    const RtpHeaderExtensionMap& ext_map) {
  network_queue_->PostTask(SafeTask(safety_.flag(), [this, ext_map]() {
    RTC_DCHECK_RUN_ON(&net_checker_);
    rtp_ext_map_ = ext_map;
  }));
}

void DtlsSrtpTransport::StartHandshakeIfReady() {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (handshake_started_ || expected_remote_fingerprint_.empty() ||
      ssl_ctx_ == nullptr || !local_cert_ || ice_channel_ == nullptr) {
    return;
  }
  if (ice_channel_->state() != IceTransportState::kConnected &&
      ice_channel_->state() != IceTransportState::kCompleted) {
    return;
  }

  ssl_ = SSL_new(ssl_ctx_);
  if (ssl_ == nullptr) {
    return;
  }
  SSL_set_options(ssl_, SSL_OP_NO_QUERY_MTU);
  SSL_set_mtu(ssl_, 1280);
  DTLS_set_link_mtu(ssl_, 1280);

  read_bio_ = BIO_new(BIO_s_mem());
  write_bio_ = BIO_new(GetDgramWriteBioMethod());
  if (read_bio_ == nullptr || write_bio_ == nullptr) {
    if (read_bio_ != nullptr) BIO_free(read_bio_);
    if (write_bio_ != nullptr) BIO_free(write_bio_);
    read_bio_ = nullptr;
    write_bio_ = nullptr;
    SSL_free(ssl_);
    ssl_ = nullptr;
    return;
  }
  BIO_set_mem_eof_return(read_bio_, -1);
  BIO_set_data(write_bio_, ice_channel_);

  SSL_set_bio(ssl_, read_bio_, write_bio_);

  if (role_ == DtlsRole::kClient) {
    SSL_set_connect_state(ssl_);
  } else {
    SSL_set_accept_state(ssl_);
  }
  handshake_started_ = true;
  handshake_started_at_ = clock_->CurrentTime();
  RTC_LOG(kInfo) << "Starting DTLS 1.2 handshake (role="
                 << (role_ == DtlsRole::kClient ? "kClient" : "kServer") << ")";
  DriveDtlsHandshake();
  if (!pending_dtls_packets_.empty()) {
    auto queued = std::move(pending_dtls_packets_);
    pending_dtls_packets_.clear();
    const Timestamp now = clock_->CurrentTime();
    for (const auto& pkt : queued) {
      if (ssl_ == nullptr) {
        break;
      }
      ProcessDtlsDatagram(pkt, now);
    }
  }
}

void DtlsSrtpTransport::DriveDtlsHandshake() {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (ssl_ == nullptr || handshake_complete_.load(std::memory_order_relaxed)) {
    return;
  }

  ERR_clear_error();
  const int ret = SSL_do_handshake(ssl_);
  if (ret == 1) {
    X509* peer_cert = SSL_get1_peer_certificate(ssl_);
    if (peer_cert == nullptr) {
      RTC_LOG(kError) << "DTLS handshake missing peer X509 certificate";
      ResetDtlsHandshakeState();
      if (observer_ != nullptr) {
        observer_->OnDtlsSrtpError("Missing DTLS peer certificate");
      }
      return;
    }
    const std::string actual_fp =
        DtlsCertificate::ComputeX509Sha256Fingerprint(peer_cert);
    X509_free(peer_cert);

    auto normalize_fp = [](std::string s) {
      while (!s.empty() &&
             (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' ||
              s.front() == '\n')) {
        s.erase(s.begin());
      }
      while (!s.empty() &&
             (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' ||
              s.back() == '\n')) {
        s.pop_back();
      }
      std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
      });
      return s;
    };
    if (normalize_fp(actual_fp) != normalize_fp(expected_remote_fingerprint_)) {
      RTC_LOG(kError) << "DTLS certificate fingerprint mismatch! actual="
                      << actual_fp
                      << " expected=" << expected_remote_fingerprint_;
      ResetDtlsHandshakeState();
      if (observer_ != nullptr) {
        observer_->OnDtlsSrtpError("DTLS certificate fingerprint mismatch");
      }
      return;
    }

    if (!ExportAndInstallSrtpKeys()) {
      RTC_LOG(kError) << "RFC 5764 DTLS-SRTP key export failed";
      ResetDtlsHandshakeState();
      if (observer_ != nullptr) {
        observer_->OnDtlsSrtpError("RFC 5764 SRTP key export failed");
      }
      return;
    }
    ++timer_generation_;
    timer_scheduled_ = false;
    SSL_set_mtu(ssl_, 1400);
    DTLS_set_link_mtu(ssl_, 1400);
    handshake_complete_.store(true, std::memory_order_release);
    RTC_LOG(kInfo) << "DTLS-SRTP handshake verified and SRTP keys installed";
    if (observer_ != nullptr) {
      observer_->OnDtlsSrtpHandshakeComplete();
    }
    return;
  }

  const int ssl_err = SSL_get_error(ssl_, ret);
  if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
    ScheduleDtlsRetransmitTimer();
  } else {
    RTC_LOG(kError) << "DTLS handshake fatal SSL error=" << ssl_err;
    ResetDtlsHandshakeState();
    if (observer_ != nullptr) {
      observer_->OnDtlsSrtpError("DTLS handshake fatal SSL error");
    }
  }
}

void DtlsSrtpTransport::ProcessDtlsDatagram(ArrayView<const uint8_t> packet,
                                            Timestamp receive_time) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (read_bio_ == nullptr || ssl_ == nullptr || packet.empty()) {
    return;
  }
  (void)BIO_reset(read_bio_);
  BIO_set_mem_eof_return(read_bio_, -1);
  BIO_write(read_bio_, packet.data(), static_cast<int>(packet.size()));

  if (!handshake_complete_.load(std::memory_order_relaxed)) {
    DriveDtlsHandshake();
  }
  if (handshake_complete_.load(std::memory_order_relaxed) && ssl_ != nullptr) {
    // RFC 8261：按完整 DTLS 最大明文记录长度（16384B）读取应用数据记录，并在单数据报处理完毕后重置 read_bio_ 防止跨包粘连污染。
    while (ssl_ != nullptr) {
      ERR_clear_error();
      const int n = SSL_read(ssl_, dtls_app_rx_buf_.data(),
                             static_cast<int>(dtls_app_rx_buf_.size()));
      if (n <= 0) {
        const int ssl_err = SSL_get_error(ssl_, n);
        if (ssl_err == SSL_ERROR_ZERO_RETURN || ssl_err == SSL_ERROR_SSL) {
          RTC_LOG(kWarning) << "DTLS session closed or fatal post-handshake "
                               "error (ssl_err="
                            << ssl_err << ")";
          ResetDtlsHandshakeState();
          srtp_.Reset();
          if (observer_ != nullptr) {
            observer_->OnDtlsSrtpError(
                ssl_err == SSL_ERROR_ZERO_RETURN
                    ? "DTLS peer sent close_notify"
                    : "DTLS post-handshake fatal SSL error");
          }
        }
        break;
      }
      if (observer_ != nullptr) {
        observer_->OnDtlsApplicationData(
            MakeArrayView(dtls_app_rx_buf_.data(), static_cast<size_t>(n)),
            receive_time);
      }
    }
  }

  if (read_bio_ != nullptr) {
    (void)BIO_reset(read_bio_);
    BIO_set_mem_eof_return(read_bio_, -1);
  }
}

void DtlsSrtpTransport::ScheduleDtlsRetransmitTimer() {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (ssl_ == nullptr || handshake_complete_.load(std::memory_order_relaxed)) {
    return;
  }
  constexpr TimeDelta kMaxHandshakeTimeout = TimeDelta::Seconds(15);
  if (handshake_started_at_.IsFinite() &&
      (clock_->CurrentTime() - handshake_started_at_) >= kMaxHandshakeTimeout) {
    RTC_LOG(kError) << "DTLS handshake exceeded 15s overall timeout";
    ResetDtlsHandshakeState();
    if (observer_ != nullptr) {
      observer_->OnDtlsSrtpError("DTLS handshake timed out");
    }
    return;
  }
  if (timer_scheduled_) {
    return;
  }
  timer_scheduled_ = true;
  const uint64_t gen = timer_generation_;
  struct timeval tv {};
  int64_t delay_us = 1'000'000;
  if (DTLSv1_get_timeout(ssl_, &tv) == 1) {
    delay_us = static_cast<int64_t>(tv.tv_sec) * 1'000'000 +
               static_cast<int64_t>(tv.tv_usec);
  }
  network_queue_->PostDelayedTask(
      SafeTask(safety_.flag(),
               [this, gen]() {
                 RTC_DCHECK_RUN_ON(&net_checker_);
                 if (gen != timer_generation_) {
                   return;
                 }
                 timer_scheduled_ = false;
                 if (ssl_ == nullptr ||
                     handshake_complete_.load(std::memory_order_relaxed)) {
                   return;
                 }
                 if (handshake_started_at_.IsFinite() &&
                     (clock_->CurrentTime() - handshake_started_at_) >=
                         TimeDelta::Seconds(15)) {
                   RTC_LOG(kError) << "DTLS handshake overall timeout";
                   ResetDtlsHandshakeState();
                   if (observer_ != nullptr) {
                     observer_->OnDtlsSrtpError("DTLS handshake timed out");
                   }
                   return;
                 }
                 ERR_clear_error();
                 if (DTLSv1_handle_timeout(ssl_) < 0) {
                   RTC_LOG(kError)
                       << "DTLS handshake retransmission limit exceeded";
                   ResetDtlsHandshakeState();
                   if (observer_ != nullptr) {
                     observer_->OnDtlsSrtpError("DTLS handshake timed out");
                   }
                   return;
                 }
                 ScheduleDtlsRetransmitTimer();
               }),
      TimeDelta::Micros(std::max<int64_t>(delay_us, 10'000)));
}

bool DtlsSrtpTransport::ExportAndInstallSrtpKeys() {
  const SRTP_PROTECTION_PROFILE* srtp_prof = SSL_get_selected_srtp_profile(ssl_);
  if (srtp_prof == nullptr) {
    return false;
  }

  SrtpCipherProfile cipher = SrtpCipherProfile::kAes128CmSha1_80;
  size_t key_len = 16;
  size_t salt_len = 14;
  if (srtp_prof->id == SRTP_AEAD_AES_128_GCM) {
    cipher = SrtpCipherProfile::kAeadAes128Gcm;
    key_len = 16;
    salt_len = 12;
  } else if (srtp_prof->id == SRTP_AES128_CM_SHA1_80) {
    cipher = SrtpCipherProfile::kAes128CmSha1_80;
    key_len = 16;
    salt_len = 14;
  } else {
    return false;
  }

  const size_t total_export = 2 * (key_len + salt_len);
  std::vector<uint8_t> material(total_export, 0);
  static constexpr const char kLabel[] = "EXTRACTOR-dtls_srtp";
  if (SSL_export_keying_material(ssl_, material.data(), material.size(), kLabel,
                                 sizeof(kLabel) - 1, nullptr, 0, 0) != 1) {
    OPENSSL_cleanse(material.data(), material.size());
    return false;
  }

  std::vector<uint8_t> client_key_salt(key_len + salt_len);
  std::vector<uint8_t> server_key_salt(key_len + salt_len);
  std::memcpy(client_key_salt.data(), material.data(), key_len);
  std::memcpy(server_key_salt.data(), material.data() + key_len, key_len);
  std::memcpy(client_key_salt.data() + key_len, material.data() + 2 * key_len,
              salt_len);
  std::memcpy(server_key_salt.data() + key_len,
              material.data() + 2 * key_len + salt_len, salt_len);

  inbound_ssrcs_.clear();
  RTC_LOG(kInfo) << "Negotiated DTLS-SRTP profile=" << srtp_prof->name;
  const bool ok =
      (role_ == DtlsRole::kClient)
          ? srtp_.SetupKeys(cipher, client_key_salt, server_key_salt)
          : srtp_.SetupKeys(cipher, server_key_salt, client_key_salt);
  OPENSSL_cleanse(material.data(), material.size());
  OPENSSL_cleanse(client_key_salt.data(), client_key_salt.size());
  OPENSSL_cleanse(server_key_salt.data(), server_key_salt.size());
  return ok;
}

void DtlsSrtpTransport::OnLocalCandidateGathered(
    const IceCandidate& candidate) {
  if (on_candidate_gathered_) {
    on_candidate_gathered_(candidate);
  }
}

void DtlsSrtpTransport::OnIceTransportStateChanged(IceTransportState state) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (state == IceTransportState::kConnected ||
      state == IceTransportState::kCompleted) {
    StartHandshakeIfReady();
  }
  if (observer_ != nullptr) {
    observer_->OnIceTransportState(state);
  }
}

void DtlsSrtpTransport::OnIcePacketReceived(ArrayView<const uint8_t> packet,
                                            Timestamp receive_time) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (packet.empty()) {
    return;
  }

  if (packet[0] >= 20 && packet[0] <= 63) {
    if (!handshake_started_) {
      StartHandshakeIfReady();
    }
    if (!handshake_started_) {
      if (pending_dtls_packets_.size() < 8) {
        pending_dtls_packets_.emplace_back(packet.begin(), packet.end());
      }
      return;
    }
    ProcessDtlsDatagram(packet, receive_time);
    return;
  }

  if ((packet[0] & 0xC0) == 0x80 && srtp_.IsActive()) {
    if (IsRtcpPacketWire(packet)) {
      if (packet.size() < 8) {
        return;
      }
      const uint32_t rtcp_ssrc = ReadBigEndian32(packet.data() + 4);
      if (inbound_ssrcs_.find(rtcp_ssrc) == inbound_ssrcs_.end() &&
          inbound_ssrcs_.size() >= kMaxInboundSsrcs) {
        return;
      }
      std::vector<uint8_t> buf(packet.begin(), packet.end());
      if (srtp_.UnprotectRtcp(&buf)) {
        inbound_ssrcs_.insert(rtcp_ssrc);
        if (observer_ != nullptr) {
          observer_->OnDecryptedRtcpPacket(buf, receive_time);
        }
      }
    } else {
      if (packet.size() < 12) {
        return;
      }
      const uint32_t rtp_ssrc = ReadBigEndian32(packet.data() + 8);
      if (inbound_ssrcs_.find(rtp_ssrc) == inbound_ssrcs_.end() &&
          inbound_ssrcs_.size() >= kMaxInboundSsrcs) {
        return;
      }
      std::vector<uint8_t> buf(packet.begin(), packet.end());
      if (srtp_.UnprotectRtp(&buf)) {
        inbound_ssrcs_.insert(rtp_ssrc);
        RtpPacket pkt;
        if (pkt.Parse(buf, rtp_ext_map_) && observer_ != nullptr) {
          observer_->OnDecryptedRtpPacket(pkt, receive_time);
        }
      }
    }
  }
}

bool DtlsSrtpTransport::SendRtpPacket(const RtpPacket& packet) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (!srtp_.IsActive()) {
    return false;
  }
  std::vector<uint8_t> wire = packet.Serialize();
  if (!srtp_.ProtectRtp(&wire)) {
    return false;
  }
  return ice_channel_->SendPacket(wire) > 0;
}

bool DtlsSrtpTransport::SendRtcpPacket(ArrayView<const uint8_t> compound_rtcp) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (!srtp_.IsActive() || compound_rtcp.empty()) {
    return false;
  }
  std::vector<uint8_t> wire(compound_rtcp.begin(), compound_rtcp.end());
  if (!srtp_.ProtectRtcp(&wire)) {
    return false;
  }
  return ice_channel_->SendPacket(wire) > 0;
}

bool DtlsSrtpTransport::SendDtlsApplicationData(
    ArrayView<const uint8_t> payload) {
  RTC_DCHECK_RUN_ON(&net_checker_);
  if (!handshake_complete_.load(std::memory_order_acquire) || ssl_ == nullptr ||
      payload.empty()) {
    return false;
  }
  ERR_clear_error();
  return SSL_write(ssl_, payload.data(), static_cast<int>(payload.size())) > 0;
}

// ======================= RtpDemuxer RTP 解复用器 =======================

bool RtpDemuxer::AddSink(const RtpDemuxCriteria& criteria,
                         RtpPacketSinkInterface* sink) {
  if (sink == nullptr) {
    return false;
  }
  if (!criteria.mid.empty()) {
    sink_by_mid_[criteria.mid] = sink;
  }
  if (!criteria.rsid.empty()) {
    sink_by_rsid_[criteria.rsid] = sink;
  }
  for (uint32_t ssrc : criteria.ssrcs) {
    sink_by_ssrc_[ssrc] = sink;
  }
  return true;
}

void RtpDemuxer::RemoveSink(const RtpPacketSinkInterface* sink) {
  for (auto it = sink_by_ssrc_.begin(); it != sink_by_ssrc_.end();) {
    if (it->second == sink) {
      it = sink_by_ssrc_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = sink_by_mid_.begin(); it != sink_by_mid_.end();) {
    if (it->second == sink) {
      it = sink_by_mid_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = sink_by_rsid_.begin(); it != sink_by_rsid_.end();) {
    if (it->second == sink) {
      it = sink_by_rsid_.erase(it);
    } else {
      ++it;
    }
  }
  if (default_sink_ == sink) {
    default_sink_ = nullptr;
  }
}

RtpPacketSinkInterface* RtpDemuxer::ResolveSink(const RtpPacket& packet) {
  auto bind_ssrc = [this](uint32_t ssrc, RtpPacketSinkInterface* sink) {
    if (sink_by_ssrc_.find(ssrc) != sink_by_ssrc_.end() ||
        sink_by_ssrc_.size() < 64) {
      sink_by_ssrc_[ssrc] = sink;
    }
  };
  if (packet.rid().has_value()) {
    const auto it = sink_by_rsid_.find(*packet.rid());
    if (it != sink_by_rsid_.end()) {
      bind_ssrc(packet.ssrc(), it->second);
      return it->second;
    }
  }
  if (packet.repaired_rid().has_value()) {
    const auto it = sink_by_rsid_.find(*packet.repaired_rid());
    if (it != sink_by_rsid_.end()) {
      bind_ssrc(packet.ssrc(), it->second);
      return it->second;
    }
  }
  // RFC 8843 §9.2：BUNDLE 解复用优先匹配 RTP 头部 MID 扩展并动态更新 SSRC 绑定表。
  if (packet.mid().has_value()) {
    const auto it = sink_by_mid_.find(*packet.mid());
    if (it != sink_by_mid_.end()) {
      bind_ssrc(packet.ssrc(), it->second);
      return it->second;
    }
  }
  const auto ssrc_it = sink_by_ssrc_.find(packet.ssrc());
  if (ssrc_it != sink_by_ssrc_.end()) {
    return ssrc_it->second;
  }
  return default_sink_;
}

bool RtpDemuxer::OnRtpPacket(const RtpPacket& packet, Timestamp receive_time) {
  RtpPacketSinkInterface* sink = ResolveSink(packet);
  if (sink == nullptr) {
    return false;
  }
  sink->OnRtpPacket(packet, receive_time);
  return true;
}

// ======================= PureVideoSdpDescription 纯视频 SDP 序列化与解析 =======================

std::string PureVideoSdpDescription::Serialize() const {
  std::ostringstream sdp;
  sdp << "v=0\r\n"
      << "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n"
      << "s=-\r\n"
      << "t=0 0\r\n";

  // 按 RFC 3264 规范保持 m= 媒体段与 BUNDLE 顺序一致。
  std::vector<SdpMediaKind> order = m_section_order;
  if (order.empty()) {
    for (size_t i = 0; i < video_m_sections.size(); ++i) {
      order.push_back(SdpMediaKind::kVideo);
    }
    if (data_m_section.has_value()) {
      order.push_back(SdpMediaKind::kApplication);
    }
  }

  std::vector<std::string> bundle_mids;
  size_t b_vid_idx = 0;
  bool b_data_used = false;
  for (SdpMediaKind kind : order) {
    if (kind == SdpMediaKind::kVideo && b_vid_idx < video_m_sections.size()) {
      bundle_mids.push_back(video_m_sections[b_vid_idx++].mid);
    } else if (kind == SdpMediaKind::kApplication &&
               data_m_section.has_value() && !b_data_used) {
      bundle_mids.push_back(data_m_section->mid);
      b_data_used = true;
    }
  }
  while (b_vid_idx < video_m_sections.size()) {
    order.push_back(SdpMediaKind::kVideo);
    bundle_mids.push_back(video_m_sections[b_vid_idx++].mid);
  }
  if (data_m_section.has_value() && !b_data_used) {
    order.push_back(SdpMediaKind::kApplication);
    bundle_mids.push_back(data_m_section->mid);
  }

  if (!bundle_mids.empty()) {
    sdp << "a=group:BUNDLE";
    for (const auto& mid : bundle_mids) {
      sdp << " " << mid;
    }
    sdp << "\r\n";
  }
  sdp << "a=extmap-allow-mixed\r\n";

  std::string wms_streams = "*";
  if (!video_m_sections.empty() && !video_m_sections.front().stream_id.empty()) {
    wms_streams = " " + video_m_sections.front().stream_id;
  } else {
    wms_streams = " *";
  }
  sdp << "a=msid-semantic: WMS" << wms_streams << "\r\n";

  if (ice_params.ice_lite) {
    sdp << "a=ice-lite\r\n";
  }

  size_t vid_idx = 0;
  size_t rej_idx = 0;
  bool data_emitted = false;
  size_t emitted_m_count = 0;
  for (SdpMediaKind kind : order) {
    if (kind == SdpMediaKind::kUnsupported) {
      if (rej_idx >= rejected_m_sections.size()) {
        continue;
      }
      const auto& rm = rejected_m_sections[rej_idx++];
      sdp << "m=" << (rm.kind.empty() ? "audio" : rm.kind) << " 0 "
          << (rm.proto.empty() ? "UDP/TLS/RTP/SAVPF" : rm.proto) << " "
          << (rm.fmt.empty() ? "0" : rm.fmt) << "\r\n"
          << "c=IN IP4 0.0.0.0\r\n";
      if (!rm.mid.empty()) {
        sdp << "a=mid:" << rm.mid << "\r\n";
      }
      continue;
    }
    if (kind == SdpMediaKind::kApplication) {
      if (!data_m_section.has_value() || data_emitted) {
        sdp << "m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\n"
            << "c=IN IP4 0.0.0.0\r\n";
        continue;
      }
      data_emitted = true;
      const auto& dm = *data_m_section;
      sdp << "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
          << "c=IN IP4 0.0.0.0\r\n"
          << "a=ice-ufrag:" << ice_params.ufrag << "\r\n"
          << "a=ice-pwd:" << ice_params.pwd << "\r\n"
          << "a=ice-options:trickle\r\n"
          << "a=fingerprint:sha-256 " << dtls_fingerprint_sha256 << "\r\n"
          << "a=setup:" << dtls_setup << "\r\n"
          << "a=mid:" << dm.mid << "\r\n"
          << "a=sctp-port:" << dm.sctp_port << "\r\n"
          << "a=max-message-size:" << dm.max_message_size << "\r\n";
      if (emitted_m_count == 0) {
        for (const auto& c : candidates) {
          sdp << "a=" << c.ToSdpAttribute() << "\r\n";
        }
      }
      ++emitted_m_count;
      continue;
    }

    if (vid_idx >= video_m_sections.size()) {
      // RFC 3264 §6：Answer 中的 m= 行总数必须严格与 Offer 一致，超出单流能力的附加视频轨输出端口 0 拒绝行。
      sdp << "m=video 0 UDP/TLS/RTP/SAVPF 96\r\n"
          << "c=IN IP4 0.0.0.0\r\n";
      continue;
    }
    const auto& m = video_m_sections[vid_idx++];
    sdp << "m=video 9 UDP/TLS/RTP/SAVPF " << static_cast<int>(m.video_pt);
    if (m.has_rtx) {
      sdp << " " << static_cast<int>(m.rtx_pt);
    }
    if (m.has_flexfec) {
      sdp << " " << static_cast<int>(m.flexfec_pt);
    }
    sdp << "\r\n"
        << "c=IN IP4 0.0.0.0\r\n"
        << "a=rtcp:9 IN IP4 0.0.0.0\r\n"
        << "a=ice-ufrag:" << ice_params.ufrag << "\r\n"
        << "a=ice-pwd:" << ice_params.pwd << "\r\n"
        << "a=ice-options:trickle\r\n"
        << "a=fingerprint:sha-256 " << dtls_fingerprint_sha256 << "\r\n"
        << "a=setup:" << dtls_setup << "\r\n"
        << "a=mid:" << m.mid << "\r\n"
        << "a=rtcp-mux\r\n"
        << "a=rtcp-rsize\r\n";

    if (m.ext_map.transport_sequence_number_id != 0) {
      sdp << "a=extmap:"
          << static_cast<int>(m.ext_map.transport_sequence_number_id)
          << " http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n";
    }
    if (m.ext_map.absolute_send_time_id != 0) {
      sdp << "a=extmap:" << static_cast<int>(m.ext_map.absolute_send_time_id)
          << " http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n";
    }
    if (m.ext_map.mid_id != 0) {
      sdp << "a=extmap:" << static_cast<int>(m.ext_map.mid_id)
          << " urn:ietf:params:rtp-hdrext:sdes:mid\r\n";
    }
    if (m.ext_map.playout_delay_id != 0) {
      sdp << "a=extmap:" << static_cast<int>(m.ext_map.playout_delay_id)
          << " http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n";
    }

    if (m.direction_send && m.direction_recv) {
      sdp << "a=sendrecv\r\n";
    } else if (m.direction_send) {
      sdp << "a=sendonly\r\n";
    } else if (m.direction_recv) {
      sdp << "a=recvonly\r\n";
    } else {
      sdp << "a=inactive\r\n";
    }

    const int vpt = static_cast<int>(m.video_pt);
    if (m.codec == VideoCodec::kH265) {
      sdp << "a=rtpmap:" << vpt << " H265/90000\r\n"
          << "a=fmtp:" << vpt
          << " level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST\r\n";
    } else {
      // 默认使用 Constrained Baseline Profile 3.1（42e01f），若对端 Offer 协商了特定 profile-level-id 则按 RFC 6184 回显匹配值。
      const std::string& plid =
          m.h264_profile_level_id.empty() ? "42e01f" : m.h264_profile_level_id;
      sdp << "a=rtpmap:" << vpt << " H264/90000\r\n"
          << "a=fmtp:" << vpt
          << " level-asymmetry-allowed=1;packetization-mode=1;profile-level-id="
          << plid << "\r\n";
    }
    sdp << "a=rtcp-fb:" << vpt << " goog-remb\r\n"
        << "a=rtcp-fb:" << vpt << " transport-cc\r\n"
        << "a=rtcp-fb:" << vpt << " ccm fir\r\n"
        << "a=rtcp-fb:" << vpt << " nack\r\n"
        << "a=rtcp-fb:" << vpt << " nack pli\r\n";

    if (m.has_rtx) {
      const int rpt = static_cast<int>(m.rtx_pt);
      sdp << "a=rtpmap:" << rpt << " rtx/90000\r\n"
          << "a=fmtp:" << rpt << " apt=" << vpt << "\r\n";
    }
    if (m.has_flexfec) {
      const int fpt = static_cast<int>(m.flexfec_pt);
      const std::string& fec_name =
          m.flexfec_subtype.empty() ? "flexfec" : m.flexfec_subtype;
      const uint32_t rw_us =
          m.flexfec_repair_window_us > 0 ? m.flexfec_repair_window_us : 10'000'000;
      sdp << "a=rtpmap:" << fpt << " " << fec_name << "/90000\r\n"
          << "a=fmtp:" << fpt << " repair-window=" << rw_us << "\r\n";
    }

    const std::string stream_id = m.stream_id.empty() ? "rtc_stream" : m.stream_id;
    const std::string track_id = m.track_id.empty() ? "rtc_video0" : m.track_id;
    const std::string cname = m.cname.empty() ? "rtc" : m.cname;

    if (m.direction_send && !m.track_id.empty()) {
      sdp << "a=msid:" << stream_id << " " << track_id << "\r\n";
    }
    if (m.direction_send && m.primary_ssrc != 0) {
      if (m.has_rtx && m.primary_rtx_ssrc != 0) {
        sdp << "a=ssrc-group:FID " << m.primary_ssrc << " "
            << m.primary_rtx_ssrc << "\r\n";
      }
      if (m.has_flexfec && m.flexfec_ssrc != 0) {
        sdp << "a=ssrc-group:FEC-FR " << m.primary_ssrc << " "
            << m.flexfec_ssrc << "\r\n";
      }
      sdp << "a=ssrc:" << m.primary_ssrc << " cname:" << cname << "\r\n"
          << "a=ssrc:" << m.primary_ssrc << " msid:" << stream_id << " "
          << track_id << "\r\n";
      if (m.has_rtx && m.primary_rtx_ssrc != 0) {
        sdp << "a=ssrc:" << m.primary_rtx_ssrc << " cname:" << cname << "\r\n"
            << "a=ssrc:" << m.primary_rtx_ssrc << " msid:" << stream_id << " "
            << track_id << "\r\n";
      }
      if (m.has_flexfec && m.flexfec_ssrc != 0) {
        sdp << "a=ssrc:" << m.flexfec_ssrc << " cname:" << cname << "\r\n";
      }
    }

    if (emitted_m_count == 0) {
      for (const auto& c : candidates) {
        sdp << "a=" << c.ToSdpAttribute() << "\r\n";
      }
    }
    ++emitted_m_count;
  }
  return sdp.str();
}

std::optional<PureVideoSdpDescription> PureVideoSdpDescription::Parse(
    std::string_view sdp_text,
    VideoCodec preferred_codec) {
  struct MSectionCodecScratch {
    std::string proto = "UDP/TLS/RTP/SAVPF";
    std::string first_fmt = "96";
    std::vector<uint8_t> h264_pts;
    std::optional<uint8_t> preferred_h264_cb_pt;
    std::optional<uint8_t> preferred_h264_pm1_pt;
    std::map<uint8_t, std::string> pt_to_profile_level_id;
    std::vector<uint8_t> h265_pts;
    std::map<uint8_t, uint8_t> apt_to_rtx_pt;
    std::optional<uint8_t> flexfec_pt;
    std::string flexfec_subtype = "flexfec";
    std::map<uint8_t, uint32_t> pt_to_repair_window_us;
    bool has_fid_primary = false;
    bool saw_extmap = false;
    RtpHeaderExtensionMap parsed_ext_map{0, 0, 0, 0, 0, 0, 0};
  };

  auto trim_ws = [](std::string_view sv) -> std::string {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) {
      sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t')) {
      sv.remove_suffix(1);
    }
    return std::string(sv);
  };

  PureVideoSdpDescription out;
  std::vector<MSectionCodecScratch> scratches;
  RtpHeaderExtensionMap session_ext_map{0, 0, 0, 0, 0, 0, 0};
  bool saw_session_extmap = false;
  bool saw_any_active_video_m = false;

  // 保护会话级 / 首个被接受 BUNDLE 段的 ICE 与 DTLS 传输参数不被尾部附加媒体段覆盖，
  // 同时保留被拒 BUNDLE 首段（如浏览器 Audio+Video Offer 中的 m=audio）作为兜底参数来源。
  bool has_primary_ufrag = false;
  bool has_primary_pwd = false;
  bool has_primary_fp = false;
  bool has_primary_setup = false;
  std::string fallback_ufrag;
  std::string fallback_pwd;
  std::string fallback_fp;
  std::string fallback_setup;
  size_t accepted_m_count = 0;

  std::istringstream iss{std::string(sdp_text)};
  std::string line;
  VideoMediaTrackDesc* cur_m = nullptr;
  MSectionCodecScratch* cur_scratch = nullptr;
  RejectedMediaDesc* cur_rejected = nullptr;
  bool cur_rejected_was_active_in_offer = false;
  bool in_data_m = false;

  auto parse_extmap_line = [](std::string_view ext_body,
                              RtpHeaderExtensionMap* target_map) {
    const size_t sp = ext_body.find(' ');
    if (sp == std::string_view::npos) {
      return false;
    }
    std::string_view id_part = ext_body.substr(0, sp);
    const size_t slash = id_part.find('/');
    if (slash != std::string_view::npos) {
      id_part = id_part.substr(0, slash);
    }
    uint16_t ext_id = 0;
    if (!ParseUint16(id_part, &ext_id) || ext_id == 0 || ext_id > 255) {
      return false;
    }
    std::string_view uri = ext_body.substr(sp + 1);
    while (!uri.empty() && uri.front() == ' ') {
      uri.remove_prefix(1);
    }
    const size_t trailing_sp = uri.find(' ');
    if (trailing_sp != std::string_view::npos) {
      uri = uri.substr(0, trailing_sp);
    }

    if (uri.find("transport-wide-cc-extensions-01") != std::string_view::npos) {
      target_map->transport_sequence_number_id = static_cast<uint8_t>(ext_id);
    } else if (uri.find("abs-send-time") != std::string_view::npos) {
      target_map->absolute_send_time_id = static_cast<uint8_t>(ext_id);
    } else if (uri == "urn:ietf:params:rtp-hdrext:sdes:mid") {
      target_map->mid_id = static_cast<uint8_t>(ext_id);
    } else if (uri.find("playout-delay") != std::string_view::npos) {
      target_map->playout_delay_id = static_cast<uint8_t>(ext_id);
    }
    return true;
  };

  auto record_candidate_line = [&](const std::string& cand_line) {
    if (std::find(out.raw_candidate_lines.begin(), out.raw_candidate_lines.end(),
                  cand_line) == out.raw_candidate_lines.end()) {
      out.raw_candidate_lines.push_back(cand_line);
    }
    if (auto c = IceCandidate::FromSdpAttribute(cand_line)) {
      const bool dup = std::any_of(
          out.candidates.begin(), out.candidates.end(),
          [&c](const IceCandidate& existing) {
            return existing.address == c->address && existing.type == c->type;
          });
      if (!dup) {
        out.candidates.push_back(*c);
      }
    }
  };

  while (std::getline(iss, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty()) {
      continue;
    }

    if (line.rfind("m=video ", 0) == 0) {
      in_data_m = false;
      cur_rejected = nullptr;
      cur_rejected_was_active_in_offer = false;
      std::istringstream vms(line.substr(8));
      std::string port_tok;
      std::string proto_tok;
      std::string fmt_tok;
      if ((vms >> port_tok >> proto_tok >> fmt_tok) && port_tok == "0") {
        cur_m = nullptr;
        cur_scratch = nullptr;
        out.m_section_order.push_back(SdpMediaKind::kUnsupported);
        out.rejected_m_sections.push_back(
            RejectedMediaDesc{"video", proto_tok, fmt_tok, ""});
        cur_rejected = &out.rejected_m_sections.back();
        continue;
      }
      saw_any_active_video_m = true;
      ++accepted_m_count;
      out.m_section_order.push_back(SdpMediaKind::kVideo);
      out.video_m_sections.emplace_back();
      scratches.emplace_back();
      cur_m = &out.video_m_sections.back();
      cur_scratch = &scratches.back();
      if (!proto_tok.empty()) {
        cur_scratch->proto = proto_tok;
      }
      if (!fmt_tok.empty()) {
        cur_scratch->first_fmt = fmt_tok;
      }
      // RFC 3264 第 5.1 节：若未显式声明方向属性，默认方向为 sendrecv。
      cur_m->direction_send = true;
      cur_m->direction_recv = true;
      continue;
    }
    if (line.rfind("m=application ", 0) == 0) {
      cur_m = nullptr;
      cur_scratch = nullptr;
      cur_rejected = nullptr;
      cur_rejected_was_active_in_offer = false;
      in_data_m = false;
      // 解析 RFC 8841 `m=application <port> UDP/DTLS/SCTP webrtc-datachannel`
      // 及旧版草案 `m=application <port> DTLS/SCTP <sctp-port>`。
      std::istringstream ms(line.substr(14));
      std::string port_tok;
      std::string proto_tok;
      std::string fmt_tok;
      if ((ms >> port_tok >> proto_tok >> fmt_tok) && port_tok != "0") {
        std::string proto_upper = proto_tok;
        std::transform(proto_upper.begin(), proto_upper.end(),
                       proto_upper.begin(), [](unsigned char c) {
                         return static_cast<char>(std::toupper(c));
                       });
        if (proto_upper.find("SCTP") != std::string::npos &&
            !out.data_m_section.has_value()) {
          ++accepted_m_count;
          DataChannelMediaDesc ddesc;
          uint16_t legacy_port = 0;
          if (ParseUint16(fmt_tok, &legacy_port) && legacy_port > 0) {
            ddesc.sctp_port = legacy_port;
          }
          out.data_m_section = ddesc;
          out.m_section_order.push_back(SdpMediaKind::kApplication);
          in_data_m = true;
          continue;
        }
      }
      out.m_section_order.push_back(SdpMediaKind::kUnsupported);
      out.rejected_m_sections.push_back(
          RejectedMediaDesc{"application",
                            proto_tok.empty() ? "UDP/DTLS/SCTP" : proto_tok,
                            fmt_tok.empty() ? "webrtc-datachannel" : fmt_tok,
                            ""});
      cur_rejected = &out.rejected_m_sections.back();
      cur_rejected_was_active_in_offer = (port_tok != "0");
      continue;
    }
    if (line.rfind("m=", 0) == 0) {
      // 记录非视频/非数据通道的 m= 媒体段（如音频段），在 Answer 中按 RFC 3264 输出端口 0 拒绝行。
      cur_m = nullptr;
      cur_scratch = nullptr;
      in_data_m = false;
      std::istringstream oms(line.substr(2));
      std::string kind_tok;
      std::string port_tok;
      std::string proto_tok;
      std::string fmt_tok;
      oms >> kind_tok >> port_tok >> proto_tok >> fmt_tok;
      out.m_section_order.push_back(SdpMediaKind::kUnsupported);
      out.rejected_m_sections.push_back(RejectedMediaDesc{
          kind_tok.empty() ? "audio" : kind_tok,
          proto_tok.empty() ? "UDP/TLS/RTP/SAVPF" : proto_tok,
          fmt_tok.empty() ? "0" : fmt_tok, ""});
      cur_rejected = &out.rejected_m_sections.back();
      cur_rejected_was_active_in_offer = (port_tok != "0");
      continue;
    }

    if (cur_rejected != nullptr) {
      if (line.rfind("a=mid:", 0) == 0) {
        cur_rejected->mid = trim_ws(std::string_view(line).substr(6));
      } else if (cur_rejected_was_active_in_offer) {
        // RFC 8843 BUNDLE：浏览器常将全部 ICE 候选及共享传输属性置于首个 m=audio 段内！
        if (line.rfind("a=candidate:", 0) == 0) {
          record_candidate_line(line);
        } else if (line.rfind("a=ice-ufrag:", 0) == 0 && fallback_ufrag.empty()) {
          fallback_ufrag = trim_ws(std::string_view(line).substr(12));
        } else if (line.rfind("a=ice-pwd:", 0) == 0 && fallback_pwd.empty()) {
          fallback_pwd = trim_ws(std::string_view(line).substr(10));
        } else if (line.rfind("a=fingerprint:", 0) == 0 && fallback_fp.empty()) {
          const size_t sp = line.find(' ', 14);
          if (sp != std::string::npos) {
            std::string hash_alg = line.substr(14, sp - 14);
            std::transform(hash_alg.begin(), hash_alg.end(), hash_alg.begin(),
                           [](unsigned char c) {
                             return static_cast<char>(std::tolower(c));
                           });
            if (hash_alg == "sha-256") {
              fallback_fp = trim_ws(std::string_view(line).substr(sp + 1));
            }
          }
        } else if (line.rfind("a=setup:", 0) == 0 && fallback_setup.empty()) {
          fallback_setup = trim_ws(std::string_view(line).substr(8));
        }
      }
      continue;
    }

    const bool allow_transport_update = (accepted_m_count <= 1);
    if (line == "a=ice-lite") {
      out.ice_params.ice_lite = true;
    } else if (line.rfind("a=ice-ufrag:", 0) == 0) {
      const std::string val = trim_ws(std::string_view(line).substr(12));
      if (!val.empty() && (!has_primary_ufrag || allow_transport_update)) {
        out.ice_params.ufrag = val;
        has_primary_ufrag = true;
      }
    } else if (line.rfind("a=ice-pwd:", 0) == 0) {
      const std::string val = trim_ws(std::string_view(line).substr(10));
      if (!val.empty() && (!has_primary_pwd || allow_transport_update)) {
        out.ice_params.pwd = val;
        has_primary_pwd = true;
      }
    } else if (line.rfind("a=fingerprint:", 0) == 0) {
      const size_t sp = line.find(' ', 14);
      if (sp != std::string::npos) {
        std::string hash_alg = line.substr(14, sp - 14);
        std::transform(hash_alg.begin(), hash_alg.end(), hash_alg.begin(),
                       [](unsigned char c) {
                         return static_cast<char>(std::tolower(c));
                       });
        if (hash_alg == "sha-256") {
          const std::string fp_val =
              trim_ws(std::string_view(line).substr(sp + 1));
          if (!fp_val.empty() && (!has_primary_fp || allow_transport_update)) {
            out.dtls_fingerprint_sha256 = fp_val;
            has_primary_fp = true;
          }
        }
      }
    } else if (line.rfind("a=setup:", 0) == 0) {
      const std::string val = trim_ws(std::string_view(line).substr(8));
      if (!val.empty() && (!has_primary_setup || allow_transport_update)) {
        out.dtls_setup = val;
        has_primary_setup = true;
      }
    } else if (line.rfind("a=candidate:", 0) == 0) {
      record_candidate_line(line);
    } else if (line.rfind("a=extmap:", 0) == 0 && cur_m == nullptr &&
               !in_data_m) {
      if (parse_extmap_line(std::string_view(line).substr(9),
                            &session_ext_map)) {
        saw_session_extmap = true;
      }
    } else if (in_data_m && out.data_m_section.has_value()) {
      if (line.rfind("a=mid:", 0) == 0) {
        out.data_m_section->mid = trim_ws(std::string_view(line).substr(6));
      } else if (line.rfind("a=sctp-port:", 0) == 0) {
        uint16_t sp = 5000;
        if (ParseUint16(trim_ws(std::string_view(line).substr(12)), &sp) &&
            sp > 0) {
          out.data_m_section->sctp_port = sp;
        }
      } else if (line.rfind("a=sctpmap:", 0) == 0) {
        const std::string_view rest = std::string_view(line).substr(10);
        const size_t space = rest.find(' ');
        const std::string_view port_part =
            (space == std::string_view::npos) ? rest : rest.substr(0, space);
        uint16_t sp = 5000;
        if (ParseUint16(port_part, &sp) && sp > 0) {
          out.data_m_section->sctp_port = sp;
        }
      } else if (line.rfind("a=max-message-size:", 0) == 0) {
        // RFC 8841 §6：max-message-size=0 为合法值，代表不限制最大消息字节数。
        uint32_t mms = 262144;
        if (ParseUint32(trim_ws(std::string_view(line).substr(19)), &mms)) {
          out.data_m_section->max_message_size = mms;
        }
      }
    } else if (cur_m != nullptr && cur_scratch != nullptr) {
      if (line.rfind("a=mid:", 0) == 0) {
        cur_m->mid = trim_ws(std::string_view(line).substr(6));
      } else if (line == "a=sendrecv") {
        cur_m->direction_send = true;
        cur_m->direction_recv = true;
      } else if (line == "a=sendonly") {
        cur_m->direction_send = true;
        cur_m->direction_recv = false;
      } else if (line == "a=recvonly") {
        cur_m->direction_send = false;
        cur_m->direction_recv = true;
      } else if (line == "a=inactive") {
        cur_m->direction_send = false;
        cur_m->direction_recv = false;
      } else if (line.rfind("a=msid:", 0) == 0) {
        std::istringstream ms(line.substr(7));
        ms >> cur_m->stream_id >> cur_m->track_id;
      } else if (line.rfind("a=extmap:", 0) == 0) {
        if (parse_extmap_line(std::string_view(line).substr(9),
                              &cur_scratch->parsed_ext_map)) {
          cur_scratch->saw_extmap = true;
        }
      } else if (line.rfind("a=rtpmap:", 0) == 0) {
        const std::string_view rest = std::string_view(line).substr(9);
        const size_t sp = rest.find(' ');
        uint16_t pt = 0;
        if (sp != std::string_view::npos &&
            ParseUint16(rest.substr(0, sp), &pt) && pt <= 127) {
          std::string codec_part(rest.substr(sp + 1));
          std::transform(codec_part.begin(), codec_part.end(),
                         codec_part.begin(), [](unsigned char c) {
                           return static_cast<char>(std::toupper(c));
                         });
          if (codec_part.rfind("H264/90000", 0) == 0) {
            cur_scratch->h264_pts.push_back(static_cast<uint8_t>(pt));
          } else if (codec_part.rfind("H265/90000", 0) == 0 ||
                     codec_part.rfind("HEVC/90000", 0) == 0) {
            cur_scratch->h265_pts.push_back(static_cast<uint8_t>(pt));
          } else if (codec_part.rfind("FLEXFEC/90000", 0) == 0) {
            cur_scratch->flexfec_pt = static_cast<uint8_t>(pt);
            cur_scratch->flexfec_subtype = "flexfec";
          } else if (codec_part.rfind("FLEXFEC-03/90000", 0) == 0) {
            if (!cur_scratch->flexfec_pt.has_value()) {
              cur_scratch->flexfec_pt = static_cast<uint8_t>(pt);
              cur_scratch->flexfec_subtype = "flexfec-03";
            }
          }
        }
      } else if (line.rfind("a=fmtp:", 0) == 0) {
        const std::string_view rest = std::string_view(line).substr(7);
        const size_t sp = rest.find(' ');
        uint16_t pt = 0;
        if (sp != std::string_view::npos &&
            ParseUint16(rest.substr(0, sp), &pt) && pt <= 127) {
          const std::string_view params = rest.substr(sp + 1);
          const size_t apt_pos = params.find("apt=");
          if (apt_pos != std::string_view::npos) {
            std::string_view apt_val = params.substr(apt_pos + 4);
            const size_t semi = apt_val.find(';');
            if (semi != std::string_view::npos) {
              apt_val = apt_val.substr(0, semi);
            }
            uint16_t assoc_pt = 0;
            if (ParseUint16(trim_ws(apt_val), &assoc_pt) && assoc_pt <= 127) {
              cur_scratch->apt_to_rtx_pt[static_cast<uint8_t>(assoc_pt)] =
                  static_cast<uint8_t>(pt);
            }
          }
          const size_t rw_pos = params.find("repair-window=");
          if (rw_pos != std::string_view::npos) {
            std::string_view rw_val = params.substr(rw_pos + 14);
            const size_t semi = rw_val.find(';');
            if (semi != std::string_view::npos) {
              rw_val = rw_val.substr(0, semi);
            }
            uint32_t rw_us = 0;
            if (ParseUint32(trim_ws(rw_val), &rw_us) && rw_us > 0) {
              cur_scratch->pt_to_repair_window_us[static_cast<uint8_t>(pt)] =
                  rw_us;
            }
          }
          std::string lower_params(params);
          std::transform(lower_params.begin(), lower_params.end(),
                         lower_params.begin(), [](unsigned char c) {
                           return static_cast<char>(std::tolower(c));
                         });
          const size_t plid_pos = lower_params.find("profile-level-id=");
          if (plid_pos != std::string::npos) {
            std::string_view plid_sv =
                std::string_view(lower_params).substr(plid_pos + 17);
            const size_t semi = plid_sv.find_first_of("; \t");
            if (semi != std::string_view::npos) {
              plid_sv = plid_sv.substr(0, semi);
            }
            if (plid_sv.size() == 6 &&
                std::all_of(plid_sv.begin(), plid_sv.end(),
                            [](unsigned char c) { return std::isxdigit(c); })) {
              cur_scratch->pt_to_profile_level_id[static_cast<uint8_t>(pt)] =
                  std::string(plid_sv);
            }
          }
          const bool has_pm1 =
              lower_params.find("packetization-mode=1") != std::string::npos;
          if (has_pm1 &&
              !cur_scratch->preferred_h264_pm1_pt.has_value()) {
            cur_scratch->preferred_h264_pm1_pt = static_cast<uint8_t>(pt);
          }
          if (has_pm1 &&
              (lower_params.find("42e0") != std::string::npos ||
               lower_params.find("4200") != std::string::npos ||
               lower_params.find("4280") != std::string::npos ||
               lower_params.find("42c0") != std::string::npos) &&
              !cur_scratch->preferred_h264_cb_pt.has_value()) {
            cur_scratch->preferred_h264_cb_pt = static_cast<uint8_t>(pt);
          }
        }
      } else if (line.rfind("a=ssrc-group:FID ", 0) == 0) {
        std::istringstream fg(line.substr(17));
        uint32_t s1 = 0;
        uint32_t s2 = 0;
        if (fg >> s1 >> s2) {
          if (!cur_scratch->has_fid_primary || cur_m->primary_ssrc == s1) {
            cur_m->primary_ssrc = s1;
            cur_m->primary_rtx_ssrc = s2;
            cur_scratch->has_fid_primary = true;
          }
        }
      } else if (line.rfind("a=ssrc-group:FEC-FR ", 0) == 0) {
        std::istringstream fg(line.substr(20));
        uint32_t s1 = 0;
        uint32_t s2 = 0;
        if (fg >> s1 >> s2) {
          if (!cur_scratch->has_fid_primary || cur_m->primary_ssrc == 0 ||
              cur_m->primary_ssrc == s1) {
            cur_m->primary_ssrc = s1;
            cur_m->flexfec_ssrc = s2;
          }
        }
      } else if (line.rfind("a=ssrc:", 0) == 0 && cur_m->primary_ssrc == 0) {
        std::istringstream sg(line.substr(7));
        sg >> cur_m->primary_ssrc;
      }
    }
  }

  if (out.ice_params.ufrag.empty() && !fallback_ufrag.empty()) {
    out.ice_params.ufrag = fallback_ufrag;
  }
  if (out.ice_params.pwd.empty() && !fallback_pwd.empty()) {
    out.ice_params.pwd = fallback_pwd;
  }
  if (out.dtls_fingerprint_sha256.empty() && !fallback_fp.empty()) {
    out.dtls_fingerprint_sha256 = fallback_fp;
  }
  if (!has_primary_setup && !fallback_setup.empty()) {
    out.dtls_setup = fallback_setup;
  }

  // 过滤无 H.264/H.265 负载类型的 m=video 段（如纯 VP8/VP9/AV1 视频段），绝不凭空伪造 PT=96 H.264！
  std::vector<VideoMediaTrackDesc> valid_video_sections;
  std::vector<SdpMediaKind> rebuilt_order;
  std::vector<RejectedMediaDesc> rebuilt_rejected;
  size_t orig_vid_idx = 0;
  size_t orig_rej_idx = 0;
  for (SdpMediaKind kind : out.m_section_order) {
    if (kind == SdpMediaKind::kUnsupported) {
      rebuilt_order.push_back(SdpMediaKind::kUnsupported);
      if (orig_rej_idx < out.rejected_m_sections.size()) {
        rebuilt_rejected.push_back(std::move(out.rejected_m_sections[orig_rej_idx++]));
      }
      continue;
    }
    if (kind == SdpMediaKind::kApplication) {
      rebuilt_order.push_back(SdpMediaKind::kApplication);
      continue;
    }
    const size_t vi = orig_vid_idx++;
    auto& m = out.video_m_sections[vi];
    const auto& sc = scratches[vi];
    if (sc.h264_pts.empty() && sc.h265_pts.empty()) {
      rebuilt_order.push_back(SdpMediaKind::kUnsupported);
      rebuilt_rejected.push_back(
          RejectedMediaDesc{"video", sc.proto, sc.first_fmt, m.mid});
      continue;
    }
    if (sc.saw_extmap) {
      m.ext_map = sc.parsed_ext_map;
    } else if (saw_session_extmap) {
      m.ext_map = session_ext_map;
    }

    if (preferred_codec == VideoCodec::kH265 && !sc.h265_pts.empty()) {
      m.codec = VideoCodec::kH265;
      m.video_pt = sc.h265_pts.front();
    } else if (!sc.h264_pts.empty()) {
      m.codec = VideoCodec::kH264;
      if (sc.preferred_h264_cb_pt.has_value() &&
          std::find(sc.h264_pts.begin(), sc.h264_pts.end(),
                    *sc.preferred_h264_cb_pt) != sc.h264_pts.end()) {
        m.video_pt = *sc.preferred_h264_cb_pt;
      } else if (sc.preferred_h264_pm1_pt.has_value() &&
                 std::find(sc.h264_pts.begin(), sc.h264_pts.end(),
                           *sc.preferred_h264_pm1_pt) != sc.h264_pts.end()) {
        m.video_pt = *sc.preferred_h264_pm1_pt;
      } else {
        m.video_pt = sc.h264_pts.front();
      }
      const auto plid_it = sc.pt_to_profile_level_id.find(m.video_pt);
      if (plid_it != sc.pt_to_profile_level_id.end()) {
        m.h264_profile_level_id = plid_it->second;
      }
    } else {
      m.codec = VideoCodec::kH265;
      m.video_pt = sc.h265_pts.front();
    }

    const auto rtx_it = sc.apt_to_rtx_pt.find(m.video_pt);
    if (rtx_it != sc.apt_to_rtx_pt.end()) {
      m.has_rtx = true;
      m.rtx_pt = rtx_it->second;
    } else {
      m.has_rtx = false;
    }

    if (sc.flexfec_pt.has_value()) {
      m.has_flexfec = true;
      m.flexfec_pt = *sc.flexfec_pt;
      m.flexfec_subtype = sc.flexfec_subtype;
      const auto rw_it = sc.pt_to_repair_window_us.find(*sc.flexfec_pt);
      if (rw_it != sc.pt_to_repair_window_us.end()) {
        m.flexfec_repair_window_us = rw_it->second;
      }
    } else {
      m.has_flexfec = false;
    }

    rebuilt_order.push_back(SdpMediaKind::kVideo);
    valid_video_sections.push_back(std::move(m));
  }
  out.video_m_sections = std::move(valid_video_sections);
  out.m_section_order = std::move(rebuilt_order);
  out.rejected_m_sections = std::move(rebuilt_rejected);

  if (saw_any_active_video_m && out.video_m_sections.empty()) {
    return std::nullopt;
  }
  if (out.ice_params.ufrag.empty() && out.video_m_sections.empty() &&
      !out.data_m_section.has_value()) {
    return std::nullopt;
  }
  return out;
}

}  // namespace rtc
