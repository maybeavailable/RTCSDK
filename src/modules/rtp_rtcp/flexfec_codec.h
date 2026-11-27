#ifndef SRC_MODULES_RTP_RTCP_FLEXFEC_CODEC_H_
#define SRC_MODULES_RTP_RTCP_FLEXFEC_CODEC_H_

// 严格遵循 IETF RFC 8627（RTP Payload Format for Flexible Forward Error Correction）实现：
//   - RTP 头部携带保护源流 CSRC 列表（CC >= 1），Marker 位强制置 0，初始序列号随机化
//   - 完整实现 R=0, F=0 柔性位掩码（MSB 优先，k-bit 级联支持 15 / 46 / 110 位掩码）
//   - 完整实现 R=0, F=1 固定 L 列 × D 行矩阵（1-D 行、1-D 交织列及 2-D 行列联合纠错，过滤 L=0,D=0）
//   - 完整实现 R=1, F=0 单包重传封装与解封装，严格忽略 R=1, F=1 保留变体
//   - Repair Payload 严格从源 RTP 固定 12 字节头之后开始异或，Length Recovery 为去头后字节数（L_i - 12）
//   - 接收端采用 SeqNumUnwrapper 单调展开键值管理缓存，彻底消除 65535->0 序列号回绕误删与残余泄漏

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "api/units.h"
#include "modules/rtp_rtcp/rtp_packet.h"
#include "rtc_base/seq_num_unwrapper.h"

namespace rtc {

struct FecProtectionParams {
  uint8_t fec_rate = 0;  // 0..255（以 255 为基数的冗余比例）
  int max_fec_frames = 1;
  bool use_burst_interleaving = false;
  // 为 true 时采用 RFC 8627 第 4.2.2.2 节 F=1 固定行列矩阵头部；默认采用 F=0 柔性位掩码。
  bool use_fixed_matrix_f1 = false;
};

class FecControllerDefault {
 public:
  void UpdateNetworkMetrics(DataRate estimated_bitrate,
                            TimeDelta rtt,
                            double loss_rate_ratio);

  FecProtectionParams keyframe_params() const { return keyframe_params_; }
  FecProtectionParams delta_params() const { return delta_params_; }

 private:
  FecProtectionParams keyframe_params_{};
  FecProtectionParams delta_params_{};
};

class FlexfecSender {
 public:
  FlexfecSender(uint8_t flexfec_payload_type,
                uint32_t flexfec_ssrc,
                uint32_t protected_media_ssrc,
                std::string mid = "",
                uint32_t repair_window_us = 10'000'000);

  FlexfecSender(const FlexfecSender&) = delete;
  FlexfecSender& operator=(const FlexfecSender&) = delete;

  void SetProtectionParameters(const FecProtectionParams& params);
  void set_repair_window_us(uint32_t repair_window_us) {
    repair_window_us_ = repair_window_us > 0 ? repair_window_us : 10'000'000;
  }
  void set_use_flexfec_03(bool enable) { use_flexfec_03_ = enable; }
  bool use_flexfec_03() const { return use_flexfec_03_; }

  void AddRtpPacketAndGenerateFec(const RtpPacket& media_packet);

  // 按 RFC 8627 第 4.2.2.1 节（R=0, F=0）柔性位掩码构造修复包（自动选择 15/46/110 位掩码）。
  std::optional<RtpPacket> BuildFlexibleMaskParityPacket(
      const std::vector<const RtpPacket*>& group);

  // 按 RFC 8627 第 4.2.2.2 节（R=0, F=1）固定 L 列 × D 行矩阵构造修复包。
  std::optional<RtpPacket> BuildFixedMatrixParityPacket(
      const std::vector<const RtpPacket*>& group,
      uint16_t sn_base,
      uint8_t columns_l,
      uint8_t rows_d);

  // 按 RFC 8627 第 4.2.2.3 节（R=1, F=0）构造单源包重传封装包。
  std::optional<RtpPacket> BuildRetransmissionPacket(
      const RtpPacket& media_packet);

  std::vector<RtpPacket> GetFecPackets();

  uint32_t ssrc() const { return flexfec_ssrc_; }
  uint8_t payload_type() const { return flexfec_pt_; }

 private:
  void EvictExpiredPendingMedia(const RtpPacket& newest_packet);

  const uint8_t flexfec_pt_;
  const uint32_t flexfec_ssrc_;
  const uint32_t protected_media_ssrc_;
  const std::string mid_;
  uint32_t repair_window_us_ = 10'000'000;
  uint16_t seq_num_ = 0;
  std::optional<uint16_t> last_added_seq_;
  bool use_flexfec_03_ = false;
  int fec_budget_accum_ = 0;

  FecProtectionParams params_{};
  std::vector<RtpPacket> pending_media_;
  std::vector<RtpPacket> ready_fec_packets_;
};

class FlexfecReceiver {
 public:
  FlexfecReceiver(uint32_t flexfec_ssrc,
                  uint32_t protected_media_ssrc,
                  uint32_t repair_window_us = 10'000'000);

  FlexfecReceiver(const FlexfecReceiver&) = delete;
  FlexfecReceiver& operator=(const FlexfecReceiver&) = delete;

  void set_extension_map(const RtpHeaderExtensionMap& ext_map) {
    ext_map_ = ext_map;
  }
  void set_repair_window_us(uint32_t repair_window_us) {
    repair_window_us_ = repair_window_us > 0 ? repair_window_us : 10'000'000;
  }

  std::vector<RtpPacket> OnRtpPacket(const RtpPacket& packet);

  size_t CachedMediaCountForTest() const { return received_media_wire_.size(); }
  size_t PendingFecCountForTest() const { return pending_fecs_.size(); }

 private:
  struct ParityRecord {
    int64_t unwrapped_base_seq = 0;
    uint32_t outer_rtp_ts = 0;
    uint8_t hdr0_recovery = 0;
    uint8_t hdr1_recovery = 0;
    uint16_t length_recovery = 0;
    uint32_t ts_recovery = 0;
    std::vector<uint16_t> protected_seqs;
    std::vector<uint8_t> repair_payload;
  };

  enum class RecoverStatus {
    kRecovered = 0,
    kAlreadyComplete = 1,
    kNeedMorePackets = 2,
  };

  bool ParseRepairPacket(const RtpPacket& packet, ParityRecord* out_record);
  RecoverStatus TryRecover(const ParityRecord& fec, RtpPacket* out_recovered);
  void DrainPendingFecs(std::vector<RtpPacket>* out_recovered_list);
  void PruneBuffers();

  const uint32_t flexfec_ssrc_;
  const uint32_t protected_media_ssrc_;
  uint32_t repair_window_us_ = 10'000'000;
  RtpHeaderExtensionMap ext_map_{};

  SeqNumUnwrapper<uint16_t> seq_unwrapper_;
  bool has_received_media_ = false;
  int64_t newest_unwrapped_seq_ = -1;
  std::map<int64_t, std::vector<uint8_t>> received_media_wire_;
  std::deque<ParityRecord> pending_fecs_;
};

}  // namespace rtc

#endif  // SRC_MODULES_RTP_RTCP_FLEXFEC_CODEC_H_
