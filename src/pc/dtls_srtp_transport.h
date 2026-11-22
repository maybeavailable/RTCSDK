#ifndef SRC_PC_DTLS_SRTP_TRANSPORT_H_
#define SRC_PC_DTLS_SRTP_TRANSPORT_H_

// 1:1 对标 libwebrtc/p2p/base/dtls_transport.h、pc/srtp_session.h、
// pc/srtp_transport.h、call/rtp_demuxer.h 与 pc/webrtc_sdp.h 实现。

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <srtp.h>

#include "api/array_view.h"
#include "api/units.h"
#include "api/video_types.h"
#include "modules/rtp_rtcp/rtp_packet.h"
#include "p2p/stun_turn_ice.h"

namespace rtc {

void EnsureLibsrtpInitialized();

class DtlsCertificate {
 public:
  static std::shared_ptr<DtlsCertificate> GenerateEcdsaP256();
  ~DtlsCertificate();

  DtlsCertificate(const DtlsCertificate&) = delete;
  DtlsCertificate& operator=(const DtlsCertificate&) = delete;

  EVP_PKEY* pkey() const { return pkey_; }
  X509* x509() const { return x509_; }
  const std::string& sha256_fingerprint() const { return fingerprint_; }

  static std::string ComputeX509Sha256Fingerprint(X509* cert);

 private:
  DtlsCertificate(EVP_PKEY* pkey, X509* x509, std::string fingerprint);

  EVP_PKEY* pkey_ = nullptr;
  X509* x509_ = nullptr;
  std::string fingerprint_;
};

enum class SrtpCipherProfile {
  kAes128CmSha1_80 = 1,
  kAeadAes128Gcm = 2,
};

class SrtpSessionPair {
 public:
  SrtpSessionPair();
  ~SrtpSessionPair();

  SrtpSessionPair(const SrtpSessionPair&) = delete;
  SrtpSessionPair& operator=(const SrtpSessionPair&) = delete;

  bool SetupKeys(SrtpCipherProfile profile,
                 ArrayView<const uint8_t> send_master_key_and_salt,
                 ArrayView<const uint8_t> recv_master_key_and_salt);

  bool IsActive() const { return active_; }

  bool ProtectRtp(std::vector<uint8_t>* packet_buf);
  bool ProtectRtcp(std::vector<uint8_t>* packet_buf);
  bool UnprotectRtp(std::vector<uint8_t>* packet_buf);
  bool UnprotectRtcp(std::vector<uint8_t>* packet_buf);

 private:
  void Reset();

  srtp_t send_ctx_ = nullptr;
  srtp_t recv_ctx_ = nullptr;
  bool active_ = false;
};

enum class DtlsRole {
  kClient = 0,
  kServer = 1,
};

class DtlsSrtpObserver {
 public:
  virtual ~DtlsSrtpObserver() = default;

  virtual void OnDtlsSrtpHandshakeComplete() = 0;
  virtual void OnDtlsSrtpError(std::string_view reason) = 0;
  virtual void OnDecryptedRtpPacket(const RtpPacket& packet,
                                    Timestamp receive_time) = 0;
  virtual void OnDecryptedRtcpPacket(ArrayView<const uint8_t> compound_rtcp,
                                     Timestamp receive_time) = 0;
};

class DtlsSrtpTransport final : public IceTransportObserver {
 public:
  DtlsSrtpTransport(Clock* clock,
                    TaskQueueBoost* network_queue,
                    IceTransportChannel* ice_channel,
                    std::shared_ptr<DtlsCertificate> local_cert,
                    DtlsSrtpObserver* observer);
  ~DtlsSrtpTransport() override;

  DtlsSrtpTransport(const DtlsSrtpTransport&) = delete;
  DtlsSrtpTransport& operator=(const DtlsSrtpTransport&) = delete;

  void SetDtlsRoleAndRemoteFingerprint(DtlsRole role,
                                       std::string expected_sha256_fp);
  void SetRtpHeaderExtensionMap(const RtpHeaderExtensionMap& ext_map);
  void StartHandshakeIfReady();

  bool IsSrtpReady() const { return srtp_.IsActive(); }

  bool SendRtpPacket(const RtpPacket& packet);
  bool SendRtcpPacket(ArrayView<const uint8_t> compound_rtcp);

  void OnLocalCandidateGathered(const IceCandidate& candidate) override;
  void OnIceTransportStateChanged(IceTransportState state) override;
  void OnIcePacketReceived(ArrayView<const uint8_t> packet,
                           Timestamp receive_time) override;

  void set_on_candidate_gathered(
      std::function<void(const IceCandidate&)> callback) {
    on_candidate_gathered_ = std::move(callback);
  }

 private:
  void DriveDtlsHandshake();
  void ScheduleDtlsRetransmitTimer();
  bool ExportAndInstallSrtpKeys();

  Clock* const clock_;
  TaskQueueBoost* const network_queue_;
  SequenceChecker net_checker_;
  IceTransportChannel* const ice_channel_;
  std::shared_ptr<DtlsCertificate> local_cert_;
  DtlsSrtpObserver* const observer_;

  std::function<void(const IceCandidate&)> on_candidate_gathered_;
  DtlsRole role_ = DtlsRole::kClient;
  std::string expected_remote_fingerprint_;
  bool handshake_started_ = false;
  bool handshake_complete_ = false;

  SSL_CTX* ssl_ctx_ = nullptr;
  SSL* ssl_ = nullptr;
  BIO* read_bio_ = nullptr;
  BIO* write_bio_ = nullptr;
  std::vector<std::vector<uint8_t>> pending_dtls_packets_;

  SrtpSessionPair srtp_;
  RtpHeaderExtensionMap rtp_ext_map_ = RtpHeaderExtensionMap::BrowserDefault();
  ScopedTaskSafety safety_;
};

class RtpPacketSinkInterface {
 public:
  virtual ~RtpPacketSinkInterface() = default;
  virtual void OnRtpPacket(const RtpPacket& packet, Timestamp receive_time) = 0;
};

struct RtpDemuxCriteria {
  std::string mid;
  std::string rsid;
  std::vector<uint32_t> ssrcs;
};

class RtpDemuxer {
 public:
  RtpDemuxer() = default;

  RtpDemuxer(const RtpDemuxer&) = delete;
  RtpDemuxer& operator=(const RtpDemuxer&) = delete;

  bool AddSink(const RtpDemuxCriteria& criteria, RtpPacketSinkInterface* sink);
  void SetDefaultSink(RtpPacketSinkInterface* sink) { default_sink_ = sink; }
  void RemoveSink(const RtpPacketSinkInterface* sink);
  bool OnRtpPacket(const RtpPacket& packet, Timestamp receive_time);

 private:
  RtpPacketSinkInterface* ResolveSink(const RtpPacket& packet);

  std::map<uint32_t, RtpPacketSinkInterface*> sink_by_ssrc_;
  std::map<std::string, RtpPacketSinkInterface*> sink_by_mid_;
  std::map<std::string, RtpPacketSinkInterface*> sink_by_rsid_;
  RtpPacketSinkInterface* default_sink_ = nullptr;
};

struct VideoMediaTrackDesc {
  std::string mid = "0";
  std::string track_id;
  std::string stream_id;
  std::string cname = "rtc";
  VideoCodec codec = VideoCodec::kH264;
  bool direction_send = true;
  bool direction_recv = true;

  uint8_t video_pt = 96;
  uint8_t rtx_pt = 97;
  uint8_t flexfec_pt = 118;
  bool has_rtx = true;
  bool has_flexfec = true;

  uint32_t primary_ssrc = 0;
  uint32_t primary_rtx_ssrc = 0;
  uint32_t flexfec_ssrc = 0;

  RtpHeaderExtensionMap ext_map = RtpHeaderExtensionMap::BrowserDefault();
};

struct PureVideoSdpDescription {
  std::string session_type = "offer";
  IceParameters ice_params;
  std::string dtls_fingerprint_sha256;
  std::string dtls_setup = "actpass";
  std::vector<IceCandidate> candidates;
  std::vector<VideoMediaTrackDesc> video_m_sections;

  std::string Serialize() const;
  static std::optional<PureVideoSdpDescription> Parse(
      std::string_view sdp_text,
      VideoCodec preferred_codec = VideoCodec::kH264);
};

}  // namespace rtc

#endif  // SRC_PC_DTLS_SRTP_TRANSPORT_H_
