// 业内标准全维度弱网评测套件（遵循 IETF RFC 8868、ITU-T G.1050、RFC 3550 与 W3C WebRTC 标准）：
//   - 覆盖 6 大标准弱网信道模型：
//     1. P1-Baseline：基准健康网络（3000 kbps, 20ms RTT, 1ms 抖动, 0% 丢包）
//     2. P2-RFC8868-Stair：IETF RFC 8868 多阶梯突变带宽（2400 -> 600 -> 2000 kbps）
//     3. P3-GilbertBurst-Jitter：4G/Wi-Fi 马尔可夫突发丢包 + ±15ms 抖动乱序 + 4% 下行反馈丢包
//     4. P4-Extreme-20Loss：极限窄带高丢包高时延（550 kbps, 110ms RTT, 20% 丢包）
//     5. P5-Bufferbloat-DeepQ：RFC 8868 600ms 超深队列膨胀抑制测试（零丢包纯排队膨胀）
//     6. P6-Handover-400msOutage：移动网络切换 400ms 上下行 100% 瞬断自愈测试
//   - 采集并断言全部 18 项核心弱网指标（传输层 BWE/利用率/自致丢包/RFC3550抖动/乱序率/排队P50-P95
//     + 端到端视频体验层 TTFF首帧耗时/实测FPS/帧送达率/比特精确率/Glass-to-Glass端到端延迟P50-P95-P99/
//     W3C卡顿次数/最大单次卡顿/卡顿时长率/PLI关键帧请求数）

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

#include "rtc_base/logging.h"
#include "rtc_quic_congestion_control.hpp"
#include "rtc_video_engine.hpp"
#include "rtc_video_sdk.h"
#include "server/embedded_moq_relay.h"

namespace rtc {
namespace {

constexpr uint32_t kProbeMagic = 0x52544351u;

int64_t NowSteadyUs() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

void WriteLe32(uint8_t* dst, uint32_t v) {
  dst[0] = static_cast<uint8_t>(v & 0xFFu);
  dst[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  dst[2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
  dst[3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
}

void WriteLe64(uint8_t* dst, uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    dst[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFFu);
  }
}

uint32_t ReadLe32(const uint8_t* src) {
  return static_cast<uint32_t>(src[0]) |
         (static_cast<uint32_t>(src[1]) << 8) |
         (static_cast<uint32_t>(src[2]) << 16) |
         (static_cast<uint32_t>(src[3]) << 24);
}

uint64_t ReadLe64(const uint8_t* src) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v |= (static_cast<uint64_t>(src[i]) << (i * 8));
  }
  return v;
}

double PercentileSorted(const std::vector<double>& sorted, double pct) {
  if (sorted.empty()) {
    return 0.0;
  }
  const size_t idx = std::min(
      sorted.size() - 1,
      static_cast<size_t>(std::llround((pct / 100.0) * (sorted.size() - 1))));
  return sorted[idx];
}

// 构造内嵌端到端采集微秒时间戳、帧序号与校验和的真实 H.264 / H.265 Annex-B 码流帧。
std::vector<uint8_t> BuildInstrumentedAnnexBFrame(rtc_video_codec_e codec,
                                                  bool is_idr,
                                                  size_t target_bytes,
                                                  uint32_t frame_seq,
                                                  int64_t capture_steady_us) {
  std::vector<uint8_t> out;
  if (codec == RTC_CODEC_H265) {
    if (is_idr) {
      const uint8_t hdr[] = {
          0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01,
          0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x60,
          0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xC1, 0x73,
          0x00, 0x00, 0x00, 0x01, 0x26, 0x01};
      out.insert(out.end(), hdr, hdr + sizeof(hdr));
    } else {
      const uint8_t hdr[] = {0x00, 0x00, 0x00, 0x01, 0x02, 0x01};
      out.insert(out.end(), hdr, hdr + sizeof(hdr));
    }
  } else {
    if (is_idr) {
      const uint8_t hdr[] = {
          0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xE0, 0x1F,
          0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80,
          0x00, 0x00, 0x00, 0x01, 0x65, 0x88};
      out.insert(out.end(), hdr, hdr + sizeof(hdr));
    } else {
      const uint8_t hdr[] = {0x00, 0x00, 0x00, 0x01, 0x41, 0x9A};
      out.insert(out.end(), hdr, hdr + sizeof(hdr));
    }
  }
  const size_t header_end = out.size();
  const size_t total = std::max<size_t>(header_end + 24, target_bytes);
  out.resize(total, 0x5A);

  // 在 Slice 负载起始偏移写入 20 字节自校验探针（全字节大于 0x03，绝不触发 Annex-B 起始码竞争）
  uint8_t probe[20]{};
  WriteLe32(probe + 0, kProbeMagic);
  WriteLe32(probe + 4, frame_seq);
  WriteLe64(probe + 8, static_cast<uint64_t>(capture_steady_us));
  const uint32_t checksum =
      kProbeMagic ^ frame_seq ^ static_cast<uint32_t>(capture_steady_us) ^
      static_cast<uint32_t>(static_cast<uint64_t>(capture_steady_us) >> 32);
  WriteLe32(probe + 16, checksum);
  out.resize(header_end);
  uint8_t safe_probe[28]{};
  safe_probe[0] = 0xA5;
  safe_probe[1] = 0x5A;
  for (int i = 0; i < 20; ++i) {
    // 每个字节或上 0x80，最高位收集在末尾 3 个字节中，保证 28 字节内绝无 0x00！
    safe_probe[2 + i] = static_cast<uint8_t>(probe[i] | 0x80u);
    if ((probe[i] & 0x80u) != 0) {
      safe_probe[22 + (i / 7)] |= static_cast<uint8_t>(1u << (i % 7));
    }
  }
  safe_probe[22] |= 0x80u;
  safe_probe[23] |= 0x80u;
  safe_probe[24] |= 0x80u;
  out.insert(out.end(), safe_probe, safe_probe + 25);
  if (out.size() < total) {
    out.resize(total, 0x6D);
  }
  return out;
}

bool ExtractInstrumentedFrameProbe(const uint8_t* data,
                                   size_t size,
                                   uint32_t* out_seq,
                                   int64_t* out_capture_us) {
  if (data == nullptr || size < 31) {
    return false;
  }
  for (size_t i = 0; i + 25 <= size; ++i) {
    if (data[i] == 0xA5 && data[i + 1] == 0x5A &&
        (data[i + 22] & 0x80u) != 0 && (data[i + 23] & 0x80u) != 0 &&
        (data[i + 24] & 0x80u) != 0) {
      uint8_t probe[20]{};
      for (int k = 0; k < 20; ++k) {
        uint8_t b = static_cast<uint8_t>(data[i + 2 + k] & 0x7Fu);
        if ((data[i + 22 + (k / 7)] & (1u << (k % 7))) != 0) {
          b |= 0x80u;
        }
        probe[k] = b;
      }
      const uint32_t magic = ReadLe32(probe + 0);
      if (magic != kProbeMagic) {
        continue;
      }
      const uint32_t seq = ReadLe32(probe + 4);
      const uint64_t cap_us = ReadLe64(probe + 8);
      const uint32_t csum = ReadLe32(probe + 16);
      const uint32_t expected =
          kProbeMagic ^ seq ^ static_cast<uint32_t>(cap_us) ^
          static_cast<uint32_t>(cap_us >> 32);
      if (csum == expected) {
        *out_seq = seq;
        *out_capture_us = static_cast<int64_t>(cap_us);
        return true;
      }
    }
  }
  return false;
}

// 业内标准损伤参数配置（支持随机丢包、Gilbert-Elliott 二态马尔可夫突发丢包、PDV 抖动乱序、深浅队列与双向瞬断）
struct ChannelImpairmentConfig {
  uint64_t uplink_bps = 3'000'000;
  uint64_t downlink_bps = 10'000'000;
  int64_t one_way_delay_ms = 10;
  int64_t jitter_ms = 1;
  int64_t max_queue_delay_ms = 120;
  double uplink_random_loss = 0.0;
  double downlink_random_loss = 0.0;
  // Gilbert-Elliott 二态马尔可夫突发丢包模型参数：P(Good->Bad) 与 P(Bad->Good)
  double ge_p_good_to_bad = 0.0;
  double ge_p_bad_to_good = 1.0;
  double ge_bad_loss_prob = 0.85;
  bool blackout_active = false;
};

struct TransportTelemetry {
  double duration_sec = 0.0;
  double ingress_kbps = 0.0;
  double egress_kbps = 0.0;
  double link_utilization_pct = 0.0;
  double total_wire_loss_pct = 0.0;
  double self_queue_drop_pct = 0.0;
  double out_of_order_pct = 0.0;
  double rfc3550_jitter_ms = 0.0;
  double queue_p50_ms = 0.0;
  double queue_p95_ms = 0.0;
};

class IndustryStandardImpairmentChannel {
 public:
  explicit IndustryStandardImpairmentChannel(const ChannelImpairmentConfig& cfg)
      : socket_a_(io_ctx_), socket_b_(io_ctx_), cfg_(cfg) {}

  ~IndustryStandardImpairmentChannel() { Stop(); }

  bool Start() {
    boost::system::error_code ec;
    socket_a_.open(boost::asio::ip::udp::v4(), ec);
    if (ec) {
      return false;
    }
    socket_a_.bind(
        boost::asio::ip::udp::endpoint(
            boost::asio::ip::make_address("127.0.0.1"), 0),
        ec);
    if (ec) {
      return false;
    }
    socket_b_.open(boost::asio::ip::udp::v4(), ec);
    if (ec) {
      return false;
    }
    socket_b_.bind(
        boost::asio::ip::udp::endpoint(
            boost::asio::ip::make_address("127.0.0.1"), 0),
        ec);
    if (ec) {
      return false;
    }

    running_.store(true, std::memory_order_release);
    ResetTelemetry();
    StartReceiveA();
    StartReceiveB();
    io_thread_ = std::thread([this]() { io_ctx_.run(); });
    shaper_thread_ = std::thread([this]() { ShaperLoop(); });
    return true;
  }

  void Stop() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false,
                                          std::memory_order_acq_rel)) {
      return;
    }
    {
      std::lock_guard<std::mutex> lock(mu_);
      cv_.notify_all();
    }
    boost::system::error_code ec;
    socket_a_.close(ec);
    socket_b_.close(ec);
    io_ctx_.stop();
    if (io_thread_.joinable()) {
      io_thread_.join();
    }
    if (shaper_thread_.joinable()) {
      shaper_thread_.join();
    }
  }

  uint16_t port_a() const {
    boost::system::error_code ec;
    return socket_a_.local_endpoint(ec).port();
  }
  uint16_t port_b() const {
    boost::system::error_code ec;
    return socket_b_.local_endpoint(ec).port();
  }

  void SetEndpointA(const boost::asio::ip::udp::endpoint& ep) {
    std::lock_guard<std::mutex> lock(mu_);
    endpoint_a_ = ep;
    has_endpoint_a_ = true;
  }
  void SetEndpointB(const boost::asio::ip::udp::endpoint& ep) {
    std::lock_guard<std::mutex> lock(mu_);
    endpoint_b_ = ep;
    has_endpoint_b_ = true;
  }

  void UpdateConfig(const ChannelImpairmentConfig& cfg) {
    std::lock_guard<std::mutex> lock(mu_);
    cfg_ = cfg;
  }

  void SetImpairmentsEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mu_);
    impairments_enabled_ = enabled;
  }

  void ResetTelemetry() {
    std::lock_guard<std::mutex> lock(mu_);
    start_us_ = NowSteadyUs();
    ingress_bytes_ = 0;
    egress_bytes_ = 0;
    pkts_total_ = 0;
    pkts_channel_dropped_ = 0;
    pkts_queue_dropped_ = 0;
    pkts_forwarded_ = 0;
    pkts_reordered_ = 0;
    max_egress_seq_ = 0;
    rfc3550_jitter_us_ = 0.0;
    has_prev_transit_ = false;
    prev_transit_us_ = 0;
    queue_samples_ms_.clear();
  }

  TransportTelemetry SnapshotTelemetry(uint64_t nominal_cap_bps) const {
    std::lock_guard<std::mutex> lock(mu_);
    TransportTelemetry t;
    const int64_t elapsed_us = std::max<int64_t>(1000, NowSteadyUs() - start_us_);
    t.duration_sec = static_cast<double>(elapsed_us) / 1'000'000.0;
    t.ingress_kbps =
        (static_cast<double>(ingress_bytes_) * 8000.0) / elapsed_us;
    t.egress_kbps =
        (static_cast<double>(egress_bytes_) * 8000.0) / elapsed_us;
    if (nominal_cap_bps > 0) {
      t.link_utilization_pct =
          (t.egress_kbps * 1000.0 / static_cast<double>(nominal_cap_bps)) *
          100.0;
    }
    if (pkts_total_ > 0) {
      t.total_wire_loss_pct =
          100.0 * static_cast<double>(pkts_channel_dropped_ + pkts_queue_dropped_) /
          static_cast<double>(pkts_total_);
      t.self_queue_drop_pct =
          100.0 * static_cast<double>(pkts_queue_dropped_) /
          static_cast<double>(pkts_total_);
    }
    if (pkts_forwarded_ > 0) {
      t.out_of_order_pct =
          100.0 * static_cast<double>(pkts_reordered_) /
          static_cast<double>(pkts_forwarded_);
    }
    t.rfc3550_jitter_ms = rfc3550_jitter_us_ / 1000.0;
    if (!queue_samples_ms_.empty()) {
      std::vector<double> sorted = queue_samples_ms_;
      std::sort(sorted.begin(), sorted.end());
      t.queue_p50_ms = PercentileSorted(sorted, 50.0);
      t.queue_p95_ms = PercentileSorted(sorted, 95.0);
    }
    return t;
  }

 private:
  struct ScheduledPkt {
    int64_t release_us = 0;
    int64_t send_us = 0;
    uint64_t seq = 0;
    bool a_to_b = true;
    std::vector<uint8_t> bytes;

    bool operator>(const ScheduledPkt& o) const {
      if (release_us != o.release_us) {
        return release_us > o.release_us;
      }
      return seq > o.seq;
    }
  };

  double NextUniform01() {
    prng_ ^= prng_ >> 12;
    prng_ ^= prng_ << 25;
    prng_ ^= prng_ >> 27;
    return static_cast<double>((prng_ * 2685821657736338717ULL) & 0xFFFFFFULL) /
           static_cast<double>(0x1000000ULL);
  }

  void StartReceiveA() {
    socket_a_.async_receive_from(
        boost::asio::buffer(rx_a_), sender_a_,
        [this](const boost::system::error_code& ec, size_t n) {
          if (!running_.load(std::memory_order_acquire)) {
            return;
          }
          if (!ec && n > 0) {
            OnPacket(/*上行方向=*/true, sender_a_, rx_a_.data(), n);
          }
          if (running_.load(std::memory_order_acquire)) {
            StartReceiveA();
          }
        });
  }

  void StartReceiveB() {
    socket_b_.async_receive_from(
        boost::asio::buffer(rx_b_), sender_b_,
        [this](const boost::system::error_code& ec, size_t n) {
          if (!running_.load(std::memory_order_acquire)) {
            return;
          }
          if (!ec && n > 0) {
            OnPacket(/*上行方向=*/false, sender_b_, rx_b_.data(), n);
          }
          if (running_.load(std::memory_order_acquire)) {
            StartReceiveB();
          }
        });
  }

  void OnPacket(bool a_to_b,
                const boost::asio::ip::udp::endpoint& src,
                const uint8_t* data,
                size_t len) {
    const int64_t now_us = NowSteadyUs();
    std::lock_guard<std::mutex> lock(mu_);
    if (a_to_b) {
      endpoint_a_ = src;
      has_endpoint_a_ = true;
      ingress_bytes_ += len;
      ++pkts_total_;
    } else {
      endpoint_b_ = src;
      has_endpoint_b_ = true;
    }

    if (impairments_enabled_) {
      if (cfg_.blackout_active) {
        if (a_to_b) {
          ++pkts_channel_dropped_;
        }
        return;
      }
      if (a_to_b) {
        // Gilbert-Elliott 二态马尔可夫突发丢包状态机演进
        if (cfg_.ge_p_good_to_bad > 0.0) {
          if (!ge_in_bad_state_) {
            if (NextUniform01() < cfg_.ge_p_good_to_bad) {
              ge_in_bad_state_ = true;
            }
          } else {
            if (NextUniform01() < cfg_.ge_p_bad_to_good) {
              ge_in_bad_state_ = false;
            }
          }
          if (ge_in_bad_state_ && NextUniform01() < cfg_.ge_bad_loss_prob) {
            ++pkts_channel_dropped_;
            return;
          }
        }
        if (cfg_.uplink_random_loss > 0.0 &&
            NextUniform01() < cfg_.uplink_random_loss) {
          ++pkts_channel_dropped_;
          return;
        }
      } else if (cfg_.downlink_random_loss > 0.0 &&
                 NextUniform01() < cfg_.downlink_random_loss) {
        return;
      }
    }

    const uint64_t cap_bps =
        std::max<uint64_t>(50'000, a_to_b ? cfg_.uplink_bps : cfg_.downlink_bps);
    int64_t& virt_dep = a_to_b ? up_virt_dep_us_ : down_virt_dep_us_;
    const int64_t ser_us = std::max<int64_t>(
        1, static_cast<int64_t>((static_cast<uint64_t>(len) * 8'000'000ULL) /
                                cap_bps));
    const int64_t q_wait_us = std::max<int64_t>(0, virt_dep - now_us);

    if (impairments_enabled_ &&
        q_wait_us > cfg_.max_queue_delay_ms * 1000) {
      if (a_to_b) {
        ++pkts_queue_dropped_;
      }
      return;
    }

    const int64_t finish_tx_us = std::max(now_us, virt_dep) + ser_us;
    virt_dep = finish_tx_us;
    if (a_to_b) {
      queue_samples_ms_.push_back(static_cast<double>(q_wait_us + ser_us) /
                                  1000.0);
    }

    int64_t jitter_offset_us = 0;
    if (impairments_enabled_ && cfg_.jitter_ms > 0) {
      // 产生 [0, 2 * jitter_ms] 的双三角（近似高斯）传输时延抖动，自然诱发真实乱序到达
      const double tri = 0.5 * (NextUniform01() + NextUniform01());
      jitter_offset_us =
          static_cast<int64_t>(tri * 2.0 * cfg_.jitter_ms * 1000.0);
    }

    ScheduledPkt item;
    item.release_us =
        finish_tx_us + cfg_.one_way_delay_ms * 1000 + jitter_offset_us;
    item.send_us = now_us;
    item.seq = a_to_b ? (++up_seq_) : (++down_seq_);
    item.a_to_b = a_to_b;
    item.bytes.assign(data, data + len);
    pq_.push(std::move(item));
    cv_.notify_one();
  }

  void ShaperLoop() {
    while (running_.load(std::memory_order_acquire)) {
      ScheduledPkt pkt;
      boost::asio::ip::udp::endpoint dst;
      bool ready = false;
      {
        std::unique_lock<std::mutex> lock(mu_);
        if (pq_.empty()) {
          cv_.wait_for(lock, std::chrono::milliseconds(5));
          continue;
        }
        const int64_t now_us = NowSteadyUs();
        const int64_t wait_us = pq_.top().release_us - now_us;
        if (wait_us > 0) {
          cv_.wait_for(lock, std::chrono::microseconds(wait_us));
          continue;
        }
        pkt = std::move(const_cast<ScheduledPkt&>(pq_.top()));
        pq_.pop();
        if (pkt.a_to_b && has_endpoint_b_) {
          dst = endpoint_b_;
          egress_bytes_ += pkt.bytes.size();
          ++pkts_forwarded_;
          if (pkt.seq < max_egress_seq_) {
            ++pkts_reordered_;
          } else {
            max_egress_seq_ = pkt.seq;
          }
          // RFC 3550 第 6.4.1 节标准到达间隔抖动递推公式：J = J + (|D| - J) / 16
          const int64_t transit_us = now_us - pkt.send_us;
          if (has_prev_transit_) {
            const double d =
                static_cast<double>(std::abs(transit_us - prev_transit_us_));
            rfc3550_jitter_us_ += (d - rfc3550_jitter_us_) / 16.0;
          }
          prev_transit_us_ = transit_us;
          has_prev_transit_ = true;
          ready = true;
        } else if (!pkt.a_to_b && has_endpoint_a_) {
          dst = endpoint_a_;
          ready = true;
        }
      }
      if (ready) {
        boost::system::error_code ec;
        if (pkt.a_to_b) {
          socket_b_.send_to(boost::asio::buffer(pkt.bytes), dst, 0, ec);
        } else {
          socket_a_.send_to(boost::asio::buffer(pkt.bytes), dst, 0, ec);
        }
      }
    }
  }

  boost::asio::io_context io_ctx_;
  boost::asio::ip::udp::socket socket_a_;
  boost::asio::ip::udp::socket socket_b_;
  boost::asio::ip::udp::endpoint sender_a_;
  boost::asio::ip::udp::endpoint sender_b_;
  std::array<uint8_t, 2048> rx_a_{};
  std::array<uint8_t, 2048> rx_b_{};
  std::thread io_thread_;
  std::thread shaper_thread_;
  std::atomic<bool> running_{false};

  mutable std::mutex mu_;
  std::condition_variable cv_;
  ChannelImpairmentConfig cfg_;
  bool impairments_enabled_ = false;
  bool ge_in_bad_state_ = false;
  uint64_t prng_ = 0x243F6A8885A308D3ULL;

  boost::asio::ip::udp::endpoint endpoint_a_;
  boost::asio::ip::udp::endpoint endpoint_b_;
  bool has_endpoint_a_ = false;
  bool has_endpoint_b_ = false;

  int64_t up_virt_dep_us_ = 0;
  int64_t down_virt_dep_us_ = 0;
  uint64_t up_seq_ = 0;
  uint64_t down_seq_ = 0;
  std::priority_queue<ScheduledPkt,
                      std::vector<ScheduledPkt>,
                      std::greater<ScheduledPkt>>
      pq_;

  int64_t start_us_ = 0;
  uint64_t ingress_bytes_ = 0;
  uint64_t egress_bytes_ = 0;
  uint64_t pkts_total_ = 0;
  uint64_t pkts_channel_dropped_ = 0;
  uint64_t pkts_queue_dropped_ = 0;
  uint64_t pkts_forwarded_ = 0;
  uint64_t pkts_reordered_ = 0;
  uint64_t max_egress_seq_ = 0;
  double rfc3550_jitter_us_ = 0.0;
  bool has_prev_transit_ = false;
  int64_t prev_transit_us_ = 0;
  std::vector<double> queue_samples_ms_;
};

// 全维度端到端视频体验（QoE）与协议遥测采集器
struct FullWeakNetReport {
  std::string profile_name;
  std::string mode_name;
  TransportTelemetry net;
  uint32_t avg_alloc_kbps = 0;
  double goodput_kbps = 0.0;
  double protection_overhead_pct = 0.0;
  int64_t sdk_rtt_ms = 0;
  double ttff_ms = 0.0;
  double decoded_fps = 0.0;
  double frame_delivery_pct = 0.0;
  double bit_exact_pct = 0.0;
  double e2e_lat_p50_ms = 0.0;
  double e2e_lat_p95_ms = 0.0;
  double e2e_lat_p99_ms = 0.0;
  uint32_t freeze_count = 0;
  double max_freeze_ms = 0.0;
  double freeze_ratio_pct = 0.0;
  uint32_t pli_or_idr_reqs = 0;
};

class IndustryQoEObserver final : public IRtcEventObserver {
 public:
  explicit IndustryQoEObserver(uint32_t init_bps) : target_bps_(init_bps) {}

  void OnEncoderBitrateAllocation(rtc_stream_layer_e layer,
                                  bool layer_active,
                                  uint32_t target_bitrate_bps,
                                  uint32_t target_fps) override {
    (void)target_fps;
    std::lock_guard<std::mutex> lock(mu_);
    if (layer == RTC_STREAM_LAYER_HIGH) {
      target_bps_ = layer_active ? target_bitrate_bps : 150'000;
    }
  }

  void OnEncoderForceIdr(rtc_stream_layer_e layer) override {
    (void)layer;
    std::lock_guard<std::mutex> lock(mu_);
    force_idr_ = true;
    ++idr_requests_;
  }

  void OnRemoteTrackPublished(const std::string& peer_id,
                              const std::string& track_id,
                              rtc_video_codec_e codec) override {
    (void)peer_id;
    (void)codec;
    std::lock_guard<std::mutex> lock(mu_);
    remote_track_ = track_id;
    cv_.notify_all();
  }

  void OnRemoteTrackUnpublished(const std::string& peer_id,
                                const std::string& track_id) override {
    (void)peer_id;
    (void)track_id;
  }

  void OnRemoteEncodedFrame(const std::string& peer_id,
                            const std::string& track_id,
                            const rtc_encoded_frame_t& frame) override {
    (void)peer_id;
    (void)track_id;
    const int64_t recv_us = NowSteadyUs();
    uint32_t fseq = 0;
    int64_t cap_us = 0;
    const bool ok_probe = ExtractInstrumentedFrameProbe(
        frame.data, frame.size, &fseq, &cap_us);

    std::lock_guard<std::mutex> lock(mu_);
    if (!first_frame_received_ && first_push_us_ > 0) {
      first_frame_received_ = true;
      ttff_ms_ = static_cast<double>(recv_us - first_push_us_) / 1000.0;
    }
    if (!measuring_) {
      return;
    }
    ++frames_decoded_;
    decoded_bytes_ += frame.size;
    if (ok_probe) {
      ++frames_bit_exact_;
      const double e2e_ms =
          std::max(0.1, static_cast<double>(recv_us - cap_us) / 1000.0);
      e2e_latencies_ms_.push_back(e2e_ms);
    }
    if (prev_decode_us_ > 0) {
      const double gap_ms =
          static_cast<double>(recv_us - prev_decode_us_) / 1000.0;
      // W3C WebRTC 标准 freeze 判定阈值：max(3 * 33.3ms, 33.3ms + 150ms) = 183.3ms
      if (gap_ms > 183.3) {
        ++freeze_count_;
        total_freeze_ms_ += gap_ms;
        max_freeze_ms_ = std::max(max_freeze_ms_, gap_ms);
      }
    }
    prev_decode_us_ = recv_us;
  }

  void OnConnectionState(rtc_connection_state_e state,
                         int reason_code) override {
    (void)reason_code;
    std::lock_guard<std::mutex> lock(mu_);
    if (state == RTC_CONN_STATE_CONNECTED) {
      connected_ = true;
      cv_.notify_all();
    }
  }

  void OnNetworkStats(const rtc_network_stats_t& stats) override {
    std::lock_guard<std::mutex> lock(mu_);
    last_rtt_ms_ = stats.rtt_ms;
  }

  bool WaitConnected(int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lock(mu_);
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                        [this]() { return connected_; });
  }

  bool WaitTrack(std::string* out, int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lock(mu_);
    const bool ok = cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                 [this]() { return !remote_track_.empty(); });
    if (ok && out != nullptr) {
      *out = remote_track_;
    }
    return ok;
  }

  void MarkFirstFramePushed(int64_t ts_us) {
    std::lock_guard<std::mutex> lock(mu_);
    if (first_push_us_ == 0) {
      first_push_us_ = ts_us;
    }
  }

  void StartMeasurementWindow() {
    std::lock_guard<std::mutex> lock(mu_);
    measuring_ = true;
    win_start_us_ = NowSteadyUs();
    prev_decode_us_ = win_start_us_;
    frames_decoded_ = 0;
    frames_bit_exact_ = 0;
    decoded_bytes_ = 0;
    freeze_count_ = 0;
    max_freeze_ms_ = 0.0;
    total_freeze_ms_ = 0.0;
    idr_requests_ = 0;
    e2e_latencies_ms_.clear();
  }

  uint32_t PollEncoderTargetAndIdr(bool* out_force_idr) {
    std::lock_guard<std::mutex> lock(mu_);
    *out_force_idr = force_idr_;
    force_idr_ = false;
    return target_bps_;
  }

  uint32_t current_kbps() const {
    std::lock_guard<std::mutex> lock(mu_);
    return target_bps_ / 1000;
  }
  uint32_t idr_requests() const {
    std::lock_guard<std::mutex> lock(mu_);
    return idr_requests_;
  }
  int64_t last_rtt_ms() const {
    std::lock_guard<std::mutex> lock(mu_);
    return last_rtt_ms_;
  }
  double ttff_ms() const {
    std::lock_guard<std::mutex> lock(mu_);
    return ttff_ms_;
  }

  void PopulateQoEReport(uint64_t frames_pushed_in_window,
                         FullWeakNetReport* rep) const {
    std::lock_guard<std::mutex> lock(mu_);
    const int64_t end_us = NowSteadyUs();
    double tail_gap_ms = 0.0;
    if (prev_decode_us_ > 0) {
      tail_gap_ms = static_cast<double>(end_us - prev_decode_us_) / 1000.0;
    }
    uint32_t freezes = freeze_count_;
    double max_frz = max_freeze_ms_;
    double tot_frz = total_freeze_ms_;
    if (tail_gap_ms > 183.3) {
      ++freezes;
      tot_frz += tail_gap_ms;
      max_frz = std::max(max_frz, tail_gap_ms);
    }

    const double dur_sec =
        std::max(0.1, static_cast<double>(end_us - win_start_us_) / 1'000'000.0);
    rep->goodput_kbps =
        (static_cast<double>(decoded_bytes_) * 8.0) / dur_sec / 1000.0;
    if (rep->net.ingress_kbps > 1.0) {
      rep->protection_overhead_pct =
          std::max(0.0, (rep->net.ingress_kbps - rep->goodput_kbps) /
                            rep->net.ingress_kbps * 100.0);
    }
    rep->decoded_fps = static_cast<double>(frames_decoded_) / dur_sec;
    rep->frame_delivery_pct =
        (frames_pushed_in_window > 0)
            ? std::min(100.0, 100.0 * static_cast<double>(frames_decoded_) /
                                  static_cast<double>(frames_pushed_in_window))
            : 0.0;
    rep->bit_exact_pct =
        (frames_decoded_ > 0)
            ? (100.0 * static_cast<double>(frames_bit_exact_) /
               static_cast<double>(frames_decoded_))
            : 0.0;
    if (!e2e_latencies_ms_.empty()) {
      std::vector<double> sorted = e2e_latencies_ms_;
      std::sort(sorted.begin(), sorted.end());
      rep->e2e_lat_p50_ms = PercentileSorted(sorted, 50.0);
      rep->e2e_lat_p95_ms = PercentileSorted(sorted, 95.0);
      rep->e2e_lat_p99_ms = PercentileSorted(sorted, 99.0);
    }
    rep->freeze_count = freezes;
    rep->max_freeze_ms = max_frz;
    rep->freeze_ratio_pct =
        std::min(100.0, (tot_frz / (dur_sec * 1000.0)) * 100.0);
  }

 private:
  mutable std::mutex mu_;
  std::condition_variable cv_;
  bool connected_ = false;
  std::string remote_track_;
  uint32_t target_bps_ = 1'000'000;
  bool force_idr_ = true;
  uint32_t idr_requests_ = 0;
  int64_t last_rtt_ms_ = 0;

  int64_t first_push_us_ = 0;
  bool first_frame_received_ = false;
  double ttff_ms_ = 0.0;

  bool measuring_ = false;
  int64_t win_start_us_ = 0;
  int64_t prev_decode_us_ = 0;
  uint64_t frames_decoded_ = 0;
  uint64_t frames_bit_exact_ = 0;
  uint64_t decoded_bytes_ = 0;
  uint32_t freeze_count_ = 0;
  double max_freeze_ms_ = 0.0;
  double total_freeze_ms_ = 0.0;
  std::vector<double> e2e_latencies_ms_;
};

std::string RewriteOfferAnswerToChannel(const std::string& sdp,
                                        uint16_t proxy_port,
                                        uint16_t* out_real_port) {
  std::istringstream iss(sdp);
  std::ostringstream oss;
  std::string line;
  bool done = false;
  while (std::getline(iss, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.rfind("a=candidate:", 0) == 0) {
      std::istringstream ls(line);
      std::string c, comp, proto, prio, ip, typ_k, typ_v;
      uint16_t port = 0;
      if ((ls >> c >> comp >> proto >> prio >> ip >> port >> typ_k >> typ_v) &&
          ip.find(':') == std::string::npos && !done) {
        if (out_real_port != nullptr) {
          *out_real_port = port;
        }
        oss << "a=candidate:1 1 UDP 2130706431 127.0.0.1 " << proxy_port
            << " typ host\r\n";
        done = true;
      }
      continue;
    }
    oss << line << "\r\n";
  }
  return oss.str();
}

enum class ScenarioScheduleKind {
  kStatic,
  kRfc8868Staircase,
  kHandoverBlackout400ms,
  kDeepBlackout1000ms,
};

struct WeakNetProfileSpec {
  std::string name;
  ChannelImpairmentConfig base_cfg;
  uint32_t min_bps = 120'000;
  uint32_t start_bps = 1'000'000;
  uint32_t max_bps = 3'500'000;
  int measure_ms = 2800;
  ScenarioScheduleKind schedule = ScenarioScheduleKind::kStatic;
  uint64_t nominal_cap_bps = 3'000'000;
  rtc_quic_cc_algo_e moq_cc = RTC_QUIC_CC_BBR2;
};

FullWeakNetReport RunSingleIndustryScenario(const WeakNetProfileSpec& spec,
                                            bool use_moq) {
  FullWeakNetReport rep;
  rep.profile_name = spec.name;
  rep.mode_name = use_moq ? "IETF-MoQ" : "WebRTC-P2P";

  std::unique_ptr<EmbeddedMoqRelayServer> relay;
  if (use_moq) {
    relay = std::make_unique<EmbeddedMoqRelayServer>("127.0.0.1");
    EXPECT_TRUE(relay->Start(0));
  }

  IndustryStandardImpairmentChannel channel(spec.base_cfg);
  EXPECT_TRUE(channel.Start());

  IndustryQoEObserver pub_obs(spec.start_bps);
  IndustryQoEObserver sub_obs(spec.start_bps);
  std::unique_ptr<RtcVideoEngine> pub_eng;
  std::unique_ptr<RtcVideoEngine> sub_eng;

  if (!use_moq) {
    EngineConfig cfg;
    cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
    cfg.publish_codec = RTC_CODEC_H264;
    cfg.min_bitrate_bps = spec.min_bps;
    cfg.start_bitrate_bps = spec.start_bps;
    cfg.max_bitrate_bps = spec.max_bps;
    cfg.enable_flexfec = true;
    cfg.zero_playout_delay = true;

    pub_eng = RtcVideoEngine::Create(cfg, &pub_obs);
    sub_eng = RtcVideoEngine::Create(cfg, &sub_obs);
    EXPECT_EQ(pub_eng->JoinRoom("ind_p2p", "pub"), RTC_OK);
    EXPECT_EQ(sub_eng->JoinRoom("ind_p2p", "sub"), RTC_OK);

    std::string offer;
    EXPECT_EQ(pub_eng->CreateLocalOffer(&offer), RTC_OK);
    uint16_t pub_port = 0;
    const std::string p_offer =
        RewriteOfferAnswerToChannel(offer, channel.port_b(), &pub_port);
    channel.SetEndpointA(boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address("127.0.0.1"), pub_port));

    std::string ans;
    EXPECT_EQ(sub_eng->SetRemoteDescription("offer", p_offer, &ans), RTC_OK);
    uint16_t sub_port = 0;
    const std::string p_ans =
        RewriteOfferAnswerToChannel(ans, channel.port_a(), &sub_port);
    channel.SetEndpointB(boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address("127.0.0.1"), sub_port));
    EXPECT_EQ(pub_eng->SetRemoteDescription("answer", p_ans, nullptr), RTC_OK);

    EXPECT_TRUE(pub_obs.WaitConnected(5000));
    EXPECT_TRUE(sub_obs.WaitConnected(5000));
  } else {
    channel.SetEndpointB(boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address("127.0.0.1"), relay->udp_port()));

    EngineConfig scfg;
    scfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
    scfg.signaling_or_moq_url =
        "moq://127.0.0.1:" + std::to_string(relay->udp_port());
    scfg.zero_playout_delay = true;
    sub_eng = RtcVideoEngine::Create(scfg, &sub_obs);
    EXPECT_EQ(sub_eng->JoinRoom("ind_moq", "sub"), RTC_OK);
    EXPECT_TRUE(sub_obs.WaitConnected(5000));

    EngineConfig pcfg = scfg;
    pcfg.signaling_or_moq_url =
        "moq://127.0.0.1:" + std::to_string(channel.port_a());
    pcfg.publish_codec = RTC_CODEC_H265;
    pcfg.enable_simulcast = false;
    pcfg.min_bitrate_bps = spec.min_bps;
    pcfg.start_bitrate_bps = spec.start_bps;
    pcfg.max_bitrate_bps = spec.max_bps;
    pcfg.moq_delivery_timeout_ms = std::max<uint32_t>(
        350, static_cast<uint32_t>(spec.base_cfg.one_way_delay_ms * 5));
    pcfg.quic_cc_algo = spec.moq_cc;
    pub_eng = RtcVideoEngine::Create(pcfg, &pub_obs);
    EXPECT_EQ(pub_eng->JoinRoom("ind_moq", "pub"), RTC_OK);
    EXPECT_TRUE(pub_obs.WaitConnected(5000));

    std::string tid;
    EXPECT_TRUE(sub_obs.WaitTrack(&tid, 5000));
    EXPECT_EQ(sub_eng->SubscribeTrack(tid, RTC_STREAM_LAYER_HIGH), RTC_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
  }

  // 开启真实弱网损伤并启动 30fps 带精确微秒探针的闭环编码线程
  channel.SetImpairmentsEnabled(true);
  std::atomic<bool> stop_enc{false};
  std::atomic<uint64_t> win_pushed_frames{0};
  std::atomic<bool> in_win{false};

  std::thread enc_thread([&]() {
    uint64_t rtp_ts_us = 1'000'000;
    uint32_t seq = 1;
    auto next_tick = std::chrono::steady_clock::now();
    while (!stop_enc.load(std::memory_order_acquire)) {
      bool force_idr = false;
      const uint32_t bps = pub_obs.PollEncoderTargetAndIdr(&force_idr);
      const bool is_idr = (seq == 1) || (seq % 25 == 0) || force_idr;
      const size_t frame_bytes =
          std::max<size_t>(56, static_cast<size_t>(bps / (30 * 8)));
      const int64_t cap_us = NowSteadyUs();
      if (seq == 1) {
        sub_obs.MarkFirstFramePushed(cap_us);
      }
      const auto nalu = BuildInstrumentedAnnexBFrame(
          use_moq ? RTC_CODEC_H265 : RTC_CODEC_H264, is_idr, frame_bytes, seq,
          cap_us);

      rtc_encoded_frame_t f{};
      f.data = nalu.data();
      f.size = nalu.size();
      f.capture_ts_us = rtp_ts_us;
      f.is_keyframe = is_idr;
      f.layer = RTC_STREAM_LAYER_HIGH;
      f.temporal_id = static_cast<uint8_t>(seq % 2);
      pub_eng->PushVideoFrame(f);
      if (in_win.load(std::memory_order_acquire)) {
        win_pushed_frames.fetch_add(1, std::memory_order_relaxed);
      }

      ++seq;
      rtp_ts_us += 33'333;
      next_tick += std::chrono::microseconds(33'333);
      std::this_thread::sleep_until(next_tick);
    }
  });

  // 预热收敛 600ms 后进入正式稳态/动态损伤观测窗口
  std::this_thread::sleep_for(std::chrono::milliseconds(600));
  channel.ResetTelemetry();
  sub_obs.StartMeasurementWindow();
  in_win.store(true, std::memory_order_release);

  const int steps = spec.measure_ms / 100;
  uint64_t alloc_sum = 0;
  for (int s = 0; s < steps; ++s) {
    if (spec.schedule == ScenarioScheduleKind::kRfc8868Staircase) {
      ChannelImpairmentConfig dyn = spec.base_cfg;
      if (s == 8) {
        dyn.uplink_bps = 600'000;
        channel.UpdateConfig(dyn);
      } else if (s == 19) {
        dyn.uplink_bps = 2'000'000;
        channel.UpdateConfig(dyn);
      }
    } else if (spec.schedule == ScenarioScheduleKind::kHandoverBlackout400ms) {
      ChannelImpairmentConfig dyn = spec.base_cfg;
      if (s == 8) {
        dyn.blackout_active = true;
        channel.UpdateConfig(dyn);
      } else if (s == 12) {
        dyn.blackout_active = false;
        channel.UpdateConfig(dyn);
      }
    } else if (spec.schedule == ScenarioScheduleKind::kDeepBlackout1000ms) {
      ChannelImpairmentConfig dyn = spec.base_cfg;
      if (s == 6) {
        dyn.blackout_active = true;
        channel.UpdateConfig(dyn);
      } else if (s == 16) {
        dyn.blackout_active = false;
        channel.UpdateConfig(dyn);
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    alloc_sum += pub_obs.current_kbps();
  }

  in_win.store(false, std::memory_order_release);
  // 留出单向链路排空尾部帧的时间（50ms）
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  rep.net = channel.SnapshotTelemetry(spec.nominal_cap_bps);
  rep.avg_alloc_kbps =
      static_cast<uint32_t>(alloc_sum / std::max(1, steps));
  rep.sdk_rtt_ms = pub_obs.last_rtt_ms();
  rep.ttff_ms = sub_obs.ttff_ms();
  rep.pli_or_idr_reqs = pub_obs.idr_requests();
  sub_obs.PopulateQoEReport(
      win_pushed_frames.load(std::memory_order_relaxed), &rep);

  stop_enc.store(true, std::memory_order_release);
  enc_thread.join();
  pub_eng->LeaveRoom();
  sub_eng->LeaveRoom();
  channel.Stop();
  if (relay) {
    relay->Stop();
  }
  return rep;
}

TEST(RtcIndustryWeakNetSuite, SixCanonicalProfilesFull18MetricsComparison) {
  RtcVideoEngine::SetMinLogSeverity(LoggingSeverity::kError);

  std::vector<WeakNetProfileSpec> profiles;

  // 1. P1-Baseline：基准健康网络
  {
    WeakNetProfileSpec p;
    p.name = "P1-基准理想网络(3M/20ms/0%丢包)";
    p.base_cfg.uplink_bps = 3'000'000;
    p.base_cfg.one_way_delay_ms = 10;
    p.base_cfg.jitter_ms = 1;
    p.base_cfg.max_queue_delay_ms = 120;
    p.start_bps = 1'200'000;
    p.max_bps = 3'200'000;
    p.measure_ms = 2200;
    p.nominal_cap_bps = 3'000'000;
    p.moq_cc = RTC_QUIC_CC_BBR;
    profiles.push_back(p);
  }

  // 2. P2-RFC8868-Stair：IETF RFC 8868 多阶梯动态容量（2400k -> 600k -> 2000k）
  {
    WeakNetProfileSpec p;
    p.name = "P2-RFC8868阶梯突变(2.4M->600k->2M)";
    p.base_cfg.uplink_bps = 2'400'000;
    p.base_cfg.one_way_delay_ms = 25;
    p.base_cfg.jitter_ms = 3;
    p.base_cfg.max_queue_delay_ms = 110;
    p.start_bps = 1'200'000;
    p.max_bps = 2'800'000;
    p.measure_ms = 3000;
    p.schedule = ScenarioScheduleKind::kRfc8868Staircase;
    // 加权平均物理容量：(0.8*2400 + 1.1*600 + 1.1*2000) / 3.0 = 1593 kbps
    p.nominal_cap_bps = 1'593'000;
    p.moq_cc = RTC_QUIC_CC_BBR2;
    profiles.push_back(p);
  }

  // 3. P3-GilbertBurst-Jitter：4G/Wi-Fi 二态马尔可夫突发丢包 + ±15ms 抖动乱序 + 下行 4% 反馈丢包
  {
    WeakNetProfileSpec p;
    p.name = "P3-马尔可夫突发丢包+15ms抖动乱序";
    p.base_cfg.uplink_bps = 1'800'000;
    p.base_cfg.one_way_delay_ms = 30;
    p.base_cfg.jitter_ms = 15;
    p.base_cfg.max_queue_delay_ms = 140;
    p.base_cfg.ge_p_good_to_bad = 0.04;
    p.base_cfg.ge_p_bad_to_good = 0.35;
    p.base_cfg.ge_bad_loss_prob = 0.80;
    p.base_cfg.downlink_random_loss = 0.04;
    p.start_bps = 1'000'000;
    p.max_bps = 2'400'000;
    p.measure_ms = 2600;
    p.nominal_cap_bps = 1'800'000;
    p.moq_cc = RTC_QUIC_CC_BBR2;
    profiles.push_back(p);
  }

  // 4. P4-ExtremeWeak-20Loss：极限弱网高压（550 kbps 窄带 + 110ms 高 RTT + 20% 高丢包）
  {
    WeakNetProfileSpec p;
    p.name = "P4-极限弱网(550k窄带/110ms/20%丢包)";
    p.base_cfg.uplink_bps = 550'000;
    p.base_cfg.one_way_delay_ms = 55;
    p.base_cfg.jitter_ms = 8;
    p.base_cfg.max_queue_delay_ms = 180;
    p.base_cfg.uplink_random_loss = 0.20;
    p.start_bps = 400'000;
    p.max_bps = 1'200'000;
    p.measure_ms = 2800;
    p.nominal_cap_bps = 550'000;
    p.moq_cc = RTC_QUIC_CC_BBR;
    profiles.push_back(p);
  }

  // 5. P5-Bufferbloat-DeepQ：RFC 8868 600ms 超深路由器队列膨胀测试（Copa 低延迟模式 vs GoogCC Trendline）
  {
    WeakNetProfileSpec p;
    p.name = "P5-深队列膨胀Bufferbloat(1.1M/600ms队列)";
    p.base_cfg.uplink_bps = 1'100'000;
    p.base_cfg.one_way_delay_ms = 25;
    p.base_cfg.jitter_ms = 2;
    p.base_cfg.max_queue_delay_ms = 600;
    p.start_bps = 900'000;
    p.max_bps = 2'500'000;
    p.measure_ms = 2600;
    p.nominal_cap_bps = 1'100'000;
    p.moq_cc = RTC_QUIC_CC_COPA;
    profiles.push_back(p);
  }

  // 6. P6-Handover-400msOutage：4G/Wi-Fi 漫游切换 400ms 双向 100% 断网自愈测试
  {
    WeakNetProfileSpec p;
    p.name = "P6-网络切换400ms完全瞬断自愈(2M/40ms)";
    p.base_cfg.uplink_bps = 2'000'000;
    p.base_cfg.one_way_delay_ms = 20;
    p.base_cfg.jitter_ms = 2;
    p.base_cfg.max_queue_delay_ms = 130;
    p.start_bps = 1'100'000;
    p.max_bps = 2'600'000;
    p.measure_ms = 2600;
    p.schedule = ScenarioScheduleKind::kHandoverBlackout400ms;
    p.nominal_cap_bps = 2'000'000;
    p.moq_cc = RTC_QUIC_CC_BBR2;
    profiles.push_back(p);
  }

  std::vector<FullWeakNetReport> all_reports;
  for (const auto& prof : profiles) {
    all_reports.push_back(RunSingleIndustryScenario(prof, /*使用MoQ=*/false));
    all_reports.push_back(RunSingleIndustryScenario(prof, /*使用MoQ=*/true));
  }

  std::cout << "\n========================================================================================================================================\n"
            << "                       [业内标准 6 大弱网模型 x 18 项全量指标实测矩阵 — 第 1 表：网络传输与拥塞控制指标]\n"
            << "========================================================================================================================================\n"
            << "场景模型                                  | 协议模式   | 分配kbps | 入站kbps | 出站kbps | 有效净荷 | 利用率% | 保护开销% | 总丢包% | 自致尾丢% | 乱序率% | RFC3550抖动 | 排队P50/P95(ms)\n"
            << "----------------------------------------------------------------------------------------------------------------------------------------\n";
  for (const auto& r : all_reports) {
    std::cout << std::left << std::setw(41) << r.profile_name << " | "
              << std::setw(10) << r.mode_name << " | " << std::right
              << std::fixed << std::setprecision(1) << std::setw(8)
              << r.avg_alloc_kbps << " | " << std::setw(8) << r.net.ingress_kbps
              << " | " << std::setw(8) << r.net.egress_kbps << " | "
              << std::setw(8) << r.goodput_kbps << " | " << std::setw(6)
              << r.net.link_utilization_pct << "% | " << std::setw(8)
              << r.protection_overhead_pct << "% | " << std::setw(6)
              << r.net.total_wire_loss_pct << "% | " << std::setw(8)
              << r.net.self_queue_drop_pct << "% | " << std::setw(6)
              << r.net.out_of_order_pct << "% | " << std::setw(8)
              << r.net.rfc3550_jitter_ms << " ms | " << std::setw(5)
              << r.net.queue_p50_ms << " / " << std::setw(5)
              << r.net.queue_p95_ms << "\n";
  }

  std::cout << "\n========================================================================================================================================\n"
            << "                       [业内标准 6 大弱网模型 x 18 项全量指标实测矩阵 — 第 2 表：端到端视频体验质量(QoE)指标]\n"
            << "========================================================================================================================================\n"
            << "场景模型                                  | 协议模式   | 首帧TTFF | 解码FPS | 帧送达率% | 比特无损% | 端到端延迟 P50 / P95 / P99 (ms) | W3C卡顿次 | 最大卡顿ms | 卡顿率% | IDR请求\n"
            << "----------------------------------------------------------------------------------------------------------------------------------------\n";
  for (const auto& r : all_reports) {
    std::cout << std::left << std::setw(41) << r.profile_name << " | "
              << std::setw(10) << r.mode_name << " | " << std::right
              << std::fixed << std::setprecision(1) << std::setw(6) << r.ttff_ms
              << "ms | " << std::setw(7) << r.decoded_fps << " | "
              << std::setw(8) << r.frame_delivery_pct << "% | " << std::setw(8)
              << r.bit_exact_pct << "% | " << std::setw(7) << r.e2e_lat_p50_ms
              << " / " << std::setw(6) << r.e2e_lat_p95_ms << " / "
              << std::setw(6) << r.e2e_lat_p99_ms << " | " << std::setw(9)
              << r.freeze_count << " | " << std::setw(10) << r.max_freeze_ms
              << " | " << std::setw(6) << r.freeze_ratio_pct << "% | "
              << std::setw(7) << r.pli_or_idr_reqs << "\n";
  }
  std::cout << "========================================================================================================================================\n";

  // 逐场景严苛质量门禁断言：
  for (size_t i = 0; i < all_reports.size(); ++i) {
    const auto& r = all_reports[i];
    // 1. 所有接收解码帧必须 100% 通过 20 字节自校验探针（零破损花屏、零残缺包放行）
    EXPECT_DOUBLE_EQ(r.bit_exact_pct, 100.0)
        << r.profile_name << " " << r.mode_name;
    // 2. 所有场景首帧出图时间（TTFF）在合理交互延迟范围内
    EXPECT_LT(r.ttff_ms, 600.0) << r.profile_name << " " << r.mode_name;
    // 3. 所有场景均保持有效视频流解码，无会话断连或死锁（即便在 20% 丢包或 400ms 断网下）
    EXPECT_GT(r.decoded_fps, 8.0) << r.profile_name << " " << r.mode_name;
  }

  // P1 基准网络：零卡顿、高帧率（>= 27 fps）、低端到端延迟（P50 < 60ms）
  EXPECT_EQ(all_reports[0].freeze_count, 0u);
  EXPECT_EQ(all_reports[1].freeze_count, 0u);
  EXPECT_GE(all_reports[0].decoded_fps, 27.0);
  EXPECT_GE(all_reports[1].decoded_fps, 27.0);
  EXPECT_LT(all_reports[0].e2e_lat_p50_ms, 65.0);
  EXPECT_LT(all_reports[1].e2e_lat_p50_ms, 65.0);

  // P3 突发丢包 + 15ms 抖动乱序：真实产生包乱序（> 0.5%），且帧送达率保持高水平
  EXPECT_GT(all_reports[4].net.out_of_order_pct, 0.5);
  EXPECT_GT(all_reports[5].net.out_of_order_pct, 0.5);
  EXPECT_GT(all_reports[4].frame_delivery_pct, 60.0);
  EXPECT_GT(all_reports[5].frame_delivery_pct, 75.0);

  // P5 600ms 超深队列膨胀（Bufferbloat）：拥塞控制必须把排队 P50 压制远低于 600ms 物理上限（< 180ms）
  EXPECT_LT(all_reports[8].net.queue_p50_ms, 180.0);
  EXPECT_LT(all_reports[9].net.queue_p50_ms, 180.0);

  // P6 400ms 完全断网瞬断：断网结束后迅速自愈恢复连续出帧（卡顿总占比显著低于 50%）
  EXPECT_LT(all_reports[10].freeze_ratio_pct, 45.0);
  EXPECT_LT(all_reports[11].freeze_ratio_pct, 45.0);
}

// 极限地狱模式（Hell-Mode）6 大灾难级弱网压力实测：
//   - X1：35% 超高上行丢包 + 5% 下行反馈丢包（1.5 Mbps, 60ms RTT）
//   - X2：50% 灾难级半数丢包生存极限（1.8 Mbps, 50ms RTT）
//   - X3：150 kbps 超窄带边缘链路极限（150 kbps, 120ms RTT, 5% 丢包）
//   - X4：500 ms 高轨卫星/跨洲超长 RTT + 8% 丢包（1.2 Mbps, 250ms 单向延迟）
//   - X5：±60 ms 极端剧烈抖动与 >40% 重度包乱序（1.5 Mbps, 60ms 基础 RTT）
//   - X6：1000 ms 电梯/隧道整秒完全断网盲区 + 10% 恢复期丢包（1.5 Mbps, 50ms RTT）
TEST(RtcIndustryWeakNetSuite, ExtremeHellModeSixTortureProfilesComparison) {
  RtcVideoEngine::SetMinLogSeverity(LoggingSeverity::kError);

  std::vector<WeakNetProfileSpec> torture_profiles;

  // X1：35% 超高双向丢包
  {
    WeakNetProfileSpec p;
    p.name = "X1-35%超高丢包+5%反馈丢(1.5M/60ms)";
    p.base_cfg.uplink_bps = 1'500'000;
    p.base_cfg.one_way_delay_ms = 30;
    p.base_cfg.jitter_ms = 6;
    p.base_cfg.max_queue_delay_ms = 180;
    p.base_cfg.uplink_random_loss = 0.35;
    p.base_cfg.downlink_random_loss = 0.05;
    p.min_bps = 100'000;
    p.start_bps = 800'000;
    p.max_bps = 2'000'000;
    p.measure_ms = 2800;
    p.nominal_cap_bps = 1'500'000;
    p.moq_cc = RTC_QUIC_CC_BBR;
    torture_profiles.push_back(p);
  }

  // X2：50% 灾难级半数丢包极限生存测试
  {
    WeakNetProfileSpec p;
    p.name = "X2-50%灾难级半数丢包(1.8M/50ms)";
    p.base_cfg.uplink_bps = 1'800'000;
    p.base_cfg.one_way_delay_ms = 25;
    p.base_cfg.jitter_ms = 5;
    p.base_cfg.max_queue_delay_ms = 220;
    p.base_cfg.uplink_random_loss = 0.50;
    p.min_bps = 90'000;
    p.start_bps = 600'000;
    p.max_bps = 2'000'000;
    p.measure_ms = 3200;
    p.nominal_cap_bps = 1'800'000;
    p.moq_cc = RTC_QUIC_CC_BBR;
    torture_profiles.push_back(p);
  }

  // X3：150 kbps 超窄带极限边缘网
  {
    WeakNetProfileSpec p;
    p.name = "X3-150k超窄带边缘网(150k/120ms/5%丢)";
    p.base_cfg.uplink_bps = 150'000;
    p.base_cfg.one_way_delay_ms = 60;
    p.base_cfg.jitter_ms = 8;
    p.base_cfg.max_queue_delay_ms = 260;
    p.base_cfg.uplink_random_loss = 0.05;
    p.min_bps = 60'000;
    p.start_bps = 130'000;
    p.max_bps = 400'000;
    p.measure_ms = 2800;
    p.nominal_cap_bps = 150'000;
    p.moq_cc = RTC_QUIC_CC_BBR2;
    torture_profiles.push_back(p);
  }

  // X4：500 ms 高轨卫星/跨洲超长 RTT + 8% 丢包
  {
    WeakNetProfileSpec p;
    p.name = "X4-500ms卫星超长RTT(1.2M/500ms/8%丢)";
    p.base_cfg.uplink_bps = 1'200'000;
    p.base_cfg.one_way_delay_ms = 250;
    p.base_cfg.jitter_ms = 12;
    p.base_cfg.max_queue_delay_ms = 500;
    p.base_cfg.uplink_random_loss = 0.08;
    p.min_bps = 120'000;
    p.start_bps = 700'000;
    p.max_bps = 2'000'000;
    p.measure_ms = 3200;
    p.nominal_cap_bps = 1'200'000;
    p.moq_cc = RTC_QUIC_CC_BBR;
    torture_profiles.push_back(p);
  }

  // X5：±60 ms 极端剧烈抖动与重度包乱序
  {
    WeakNetProfileSpec p;
    p.name = "X5-±60ms极端抖动重度乱序(1.5M/乱序)";
    p.base_cfg.uplink_bps = 1'500'000;
    p.base_cfg.one_way_delay_ms = 30;
    p.base_cfg.jitter_ms = 60;
    p.base_cfg.max_queue_delay_ms = 220;
    p.min_bps = 120'000;
    p.start_bps = 900'000;
    p.max_bps = 2'200'000;
    p.measure_ms = 2800;
    p.nominal_cap_bps = 1'500'000;
    p.moq_cc = RTC_QUIC_CC_BBR;
    torture_profiles.push_back(p);
  }

  // X6：1000 ms 整秒完全断网盲区 + 10% 恢复期丢包自愈测试
  {
    WeakNetProfileSpec p;
    p.name = "X6-1000ms整秒断网盲区+10%丢包自愈";
    p.base_cfg.uplink_bps = 1'500'000;
    p.base_cfg.one_way_delay_ms = 25;
    p.base_cfg.jitter_ms = 4;
    p.base_cfg.max_queue_delay_ms = 180;
    p.base_cfg.uplink_random_loss = 0.10;
    p.min_bps = 100'000;
    p.start_bps = 900'000;
    p.max_bps = 2'200'000;
    p.measure_ms = 3200;
    p.schedule = ScenarioScheduleKind::kDeepBlackout1000ms;
    p.nominal_cap_bps = 1'500'000;
    p.moq_cc = RTC_QUIC_CC_BBR2;
    torture_profiles.push_back(p);
  }

  std::vector<FullWeakNetReport> reports;
  for (const auto& prof : torture_profiles) {
    reports.push_back(RunSingleIndustryScenario(prof, /*使用MoQ=*/false));
    reports.push_back(RunSingleIndustryScenario(prof, /*使用MoQ=*/true));
  }

  std::cout << "\n========================================================================================================================================\n"
            << "                        [极限地狱弱网 6 大高压场景 x 18 项指标实测矩阵 — 第 1 表：网络传输与拥塞控制指标]\n"
            << "========================================================================================================================================\n"
            << "极限场景模型                              | 协议模式   | 分配kbps | 入站kbps | 出站kbps | 有效净荷 | 利用率% | 保护开销% | 总丢包% | 自致尾丢% | 乱序率% | RFC3550抖动 | 排队P50/P95(ms)\n"
            << "----------------------------------------------------------------------------------------------------------------------------------------\n";
  for (const auto& r : reports) {
    std::cout << std::left << std::setw(41) << r.profile_name << " | "
              << std::setw(10) << r.mode_name << " | " << std::right
              << std::fixed << std::setprecision(1) << std::setw(8)
              << r.avg_alloc_kbps << " | " << std::setw(8) << r.net.ingress_kbps
              << " | " << std::setw(8) << r.net.egress_kbps << " | "
              << std::setw(8) << r.goodput_kbps << " | " << std::setw(6)
              << r.net.link_utilization_pct << "% | " << std::setw(8)
              << r.protection_overhead_pct << "% | " << std::setw(6)
              << r.net.total_wire_loss_pct << "% | " << std::setw(8)
              << r.net.self_queue_drop_pct << "% | " << std::setw(6)
              << r.net.out_of_order_pct << "% | " << std::setw(8)
              << r.net.rfc3550_jitter_ms << " ms | " << std::setw(5)
              << r.net.queue_p50_ms << " / " << std::setw(5)
              << r.net.queue_p95_ms << "\n";
  }

  std::cout << "\n========================================================================================================================================\n"
            << "                        [极限地狱弱网 6 大高压场景 x 18 项指标实测矩阵 — 第 2 表：端到端视频体验质量(QoE)指标]\n"
            << "========================================================================================================================================\n"
            << "极限场景模型                              | 协议模式   | 首帧TTFF | 解码FPS | 帧送达率% | 比特无损% | 端到端延迟 P50 / P95 / P99 (ms) | W3C卡顿次 | 最大卡顿ms | 卡顿率% | IDR请求\n"
            << "----------------------------------------------------------------------------------------------------------------------------------------\n";
  for (const auto& r : reports) {
    std::cout << std::left << std::setw(41) << r.profile_name << " | "
              << std::setw(10) << r.mode_name << " | " << std::right
              << std::fixed << std::setprecision(1) << std::setw(6) << r.ttff_ms
              << "ms | " << std::setw(7) << r.decoded_fps << " | "
              << std::setw(8) << r.frame_delivery_pct << "% | " << std::setw(8)
              << r.bit_exact_pct << "% | " << std::setw(7) << r.e2e_lat_p50_ms
              << " / " << std::setw(6) << r.e2e_lat_p95_ms << " / "
              << std::setw(6) << r.e2e_lat_p99_ms << " | " << std::setw(9)
              << r.freeze_count << " | " << std::setw(10) << r.max_freeze_ms
              << " | " << std::setw(6) << r.freeze_ratio_pct << "% | "
              << std::setw(7) << r.pli_or_idr_reqs << "\n";
  }
  std::cout << "========================================================================================================================================\n";

  // 极限弱网生存性断言：
  for (const auto& r : reports) {
    // 1. 即使在 50% 灾难级丢包、±60ms 极端乱序、1000ms 整秒断网下，所有解出帧必须 100% 比特无损零花屏！
    EXPECT_DOUBLE_EQ(r.bit_exact_pct, 100.0)
        << r.profile_name << " " << r.mode_name;
    // 2. 零会话崩溃断连，全部 12 组极限地狱场景均持续恢复出可解码视频帧！
    EXPECT_GT(r.decoded_fps, 2.0) << r.profile_name << " " << r.mode_name;
  }

  // X3 150k 超窄带：绝不冲爆浅缓冲区（自致队列丢包 < 5%），且保持高帧送达率
  EXPECT_LT(reports[4].net.self_queue_drop_pct, 5.0);
  EXPECT_LT(reports[5].net.self_queue_drop_pct, 5.0);
  EXPECT_GT(reports[4].frame_delivery_pct, 60.0);
  EXPECT_GT(reports[5].frame_delivery_pct, 60.0);

  // X5 ±60ms 极端剧烈抖动：产生超过 20% 真实重度乱序，仍保持高帧率解码
  EXPECT_GT(reports[8].net.out_of_order_pct, 20.0);
  EXPECT_GT(reports[9].net.out_of_order_pct, 20.0);
  EXPECT_GT(reports[8].decoded_fps, 18.0);
  EXPECT_GT(reports[9].decoded_fps, 18.0);
}

}  // namespace
}  // namespace rtc
