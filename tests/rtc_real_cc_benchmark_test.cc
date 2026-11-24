// 真实操作系统 UDP 套接字端到端拥塞控制基准测试套件：
//   - 基于双端口 Boost.Asio 真实 UDP 瓶颈路由器（精确串行化限速、传播时延、有限缓冲区尾部丢包）
//   - 验证 WebRTC P2P（Full-ICE + DTLS-SRTP + SRTCP TWCC + GoogCC + Pacer + RTX + FlexFEC）
//     在带宽爬升、拥塞骤降与容量恢复三阶段下的真实码率收敛、排队时延控制与视频连续解码
//   - 验证 IETF MoQ（QUIC v1 + Simulcast 双层自适应 + BBRv1/BBRv2/CUBIC/Copa/NewReno 五种可插拔
//     拥塞控制及运行期热切换）在真实受限 UDP 管道上的码率跟踪、高低清层自动启停与 Relay 无缝降级恢复

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
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

#include "modules/congestion_controller/goog_cc/goog_cc_controller.h"
#include "modules/rtp_rtcp/rtcp_packets.h"
#include "rtc_base/logging.h"
#include "rtc_quic_congestion_control.hpp"
#include "rtc_video_engine.hpp"
#include "server/embedded_moq_relay.h"

namespace rtc {
namespace {

int64_t SteadyNowUs() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

// 真实双端口 UDP 瓶颈链路仿真代理：
//   - 端口 A 面向发送端（Peer A / MoQ Publisher），端口 B 面向接收端（Peer B / MoQ Relay）
//   - 彻底隔离两端真实端口，杜绝 ICE prflx 候选绕过限速管道
//   - 精确模拟物理链路串行化速率（capacity_bps）、单向传播时延（one_way_delay_ms）
//     以及有限路由器队列尾部丢包（max_queue_delay_ms）
class RealUdpBottleneckProxy {
 public:
  struct PhaseTelemetry {
    double duration_sec = 0.0;
    double uplink_ingress_kbps = 0.0;
    double uplink_egress_kbps = 0.0;
    double queue_delay_p50_ms = 0.0;
    double queue_delay_p95_ms = 0.0;
    uint64_t packets_forwarded = 0;
    uint64_t packets_dropped = 0;
    double drop_ratio = 0.0;
  };

  RealUdpBottleneckProxy(uint64_t uplink_bps,
                         uint64_t downlink_bps,
                         int64_t one_way_delay_ms,
                         int64_t max_queue_delay_ms)
      : socket_a_(io_ctx_),
        socket_b_(io_ctx_),
        uplink_bps_(uplink_bps),
        downlink_bps_(downlink_bps),
        one_way_delay_us_(one_way_delay_ms * 1000),
        max_queue_delay_us_(max_queue_delay_ms * 1000) {}

  ~RealUdpBottleneckProxy() { Stop(); }

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
    phase_start_us_ = SteadyNowUs();
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

  void SetUplinkCapacityBps(uint64_t bps) {
    std::lock_guard<std::mutex> lock(mu_);
    uplink_bps_ = std::max<uint64_t>(50'000, bps);
  }

  void SetDownlinkCapacityBps(uint64_t bps) {
    std::lock_guard<std::mutex> lock(mu_);
    downlink_bps_ = std::max<uint64_t>(50'000, bps);
  }

  void SetUplinkRandomLossProb(double prob) {
    std::lock_guard<std::mutex> lock(mu_);
    uplink_random_loss_prob_ = std::clamp(prob, 0.0, 0.90);
  }

  void ResetPhaseTelemetry() {
    std::lock_guard<std::mutex> lock(mu_);
    phase_start_us_ = SteadyNowUs();
    uplink_ingress_bytes_ = 0;
    uplink_egress_bytes_ = 0;
    uplink_forwarded_pkts_ = 0;
    uplink_dropped_pkts_ = 0;
    queue_delays_ms_.clear();
  }

  PhaseTelemetry SnapshotPhaseTelemetry() const {
    std::lock_guard<std::mutex> lock(mu_);
    PhaseTelemetry out;
    const int64_t elapsed_us = std::max<int64_t>(1000, SteadyNowUs() - phase_start_us_);
    out.duration_sec = static_cast<double>(elapsed_us) / 1'000'000.0;
    out.uplink_ingress_kbps =
        (static_cast<double>(uplink_ingress_bytes_) * 8000.0) /
        static_cast<double>(elapsed_us);
    out.uplink_egress_kbps =
        (static_cast<double>(uplink_egress_bytes_) * 8000.0) /
        static_cast<double>(elapsed_us);
    out.packets_forwarded = uplink_forwarded_pkts_;
    out.packets_dropped = uplink_dropped_pkts_;
    const uint64_t total_pkts = uplink_forwarded_pkts_ + uplink_dropped_pkts_;
    out.drop_ratio = (total_pkts > 0)
                         ? (static_cast<double>(uplink_dropped_pkts_) /
                            static_cast<double>(total_pkts))
                         : 0.0;
    if (!queue_delays_ms_.empty()) {
      std::vector<double> sorted = queue_delays_ms_;
      std::sort(sorted.begin(), sorted.end());
      out.queue_delay_p50_ms = sorted[sorted.size() / 2];
      out.queue_delay_p95_ms =
          sorted[std::min(sorted.size() - 1, (sorted.size() * 95) / 100)];
    }
    return out;
  }

 private:
  struct ScheduledDatagram {
    int64_t release_us = 0;
    uint64_t seq = 0;
    bool a_to_b = true;
    std::vector<uint8_t> data;

    bool operator>(const ScheduledDatagram& other) const {
      if (release_us != other.release_us) {
        return release_us > other.release_us;
      }
      return seq > other.seq;
    }
  };

  void StartReceiveA() {
    socket_a_.async_receive_from(
        boost::asio::buffer(rx_buf_a_), sender_a_,
        [this](const boost::system::error_code& ec, size_t nbytes) {
          if (!running_.load(std::memory_order_acquire)) {
            return;
          }
          if (!ec && nbytes > 0) {
            EnqueuePacket(/*上行方向=*/true, sender_a_, rx_buf_a_.data(),
                          nbytes);
          }
          if (running_.load(std::memory_order_acquire)) {
            StartReceiveA();
          }
        });
  }

  void StartReceiveB() {
    socket_b_.async_receive_from(
        boost::asio::buffer(rx_buf_b_), sender_b_,
        [this](const boost::system::error_code& ec, size_t nbytes) {
          if (!running_.load(std::memory_order_acquire)) {
            return;
          }
          if (!ec && nbytes > 0) {
            EnqueuePacket(/*上行方向=*/false, sender_b_, rx_buf_b_.data(),
                          nbytes);
          }
          if (running_.load(std::memory_order_acquire)) {
            StartReceiveB();
          }
        });
  }

  void EnqueuePacket(bool a_to_b,
                     const boost::asio::ip::udp::endpoint& src_ep,
                     const uint8_t* bytes,
                     size_t len) {
    const int64_t now_us = SteadyNowUs();
    std::lock_guard<std::mutex> lock(mu_);
    if (a_to_b) {
      endpoint_a_ = src_ep;
      has_endpoint_a_ = true;
      uplink_ingress_bytes_ += len;
    } else {
      endpoint_b_ = src_ep;
      has_endpoint_b_ = true;
    }

    // 模拟无线信道随机丢包（仅在数据承载阶段对非握手小控制包生效或按固定伪随机序列丢弃，避免握手偶发重传超时干扰时序）
    if (a_to_b && uplink_random_loss_prob_ > 0.0 && len > 90) {
      prng_state_ ^= prng_state_ >> 12;
      prng_state_ ^= prng_state_ << 25;
      prng_state_ ^= prng_state_ >> 27;
      const double u =
          static_cast<double>((prng_state_ * 2685821657736338717ULL) &
                              0xFFFFFFULL) /
          static_cast<double>(0x1000000ULL);
      if (u < uplink_random_loss_prob_) {
        ++uplink_dropped_pkts_;
        return;
      }
    }

    const uint64_t cap_bps = a_to_b ? uplink_bps_ : downlink_bps_;
    int64_t& virt_dep_us =
        a_to_b ? uplink_virt_departure_us_ : downlink_virt_departure_us_;

    const int64_t ser_us = std::max<int64_t>(
        1, static_cast<int64_t>((static_cast<uint64_t>(len) * 8'000'000ULL) /
                                cap_bps));
    const int64_t queue_wait_us = std::max<int64_t>(0, virt_dep_us - now_us);

    if (queue_wait_us > max_queue_delay_us_) {
      if (a_to_b) {
        ++uplink_dropped_pkts_;
      }
      return;
    }

    const int64_t finish_tx_us = std::max(now_us, virt_dep_us) + ser_us;
    virt_dep_us = finish_tx_us;
    if (a_to_b) {
      ++uplink_forwarded_pkts_;
      queue_delays_ms_.push_back(static_cast<double>(queue_wait_us + ser_us) /
                                 1000.0);
    }

    ScheduledDatagram item;
    item.release_us = finish_tx_us + one_way_delay_us_;
    item.seq = ++next_seq_;
    item.a_to_b = a_to_b;
    item.data.assign(bytes, bytes + len);
    pq_.push(std::move(item));
    cv_.notify_one();
  }

  void ShaperLoop() {
    while (running_.load(std::memory_order_acquire)) {
      ScheduledDatagram pkt;
      boost::asio::ip::udp::endpoint dst;
      bool can_send = false;

      {
        std::unique_lock<std::mutex> lock(mu_);
        if (pq_.empty()) {
          cv_.wait_for(lock, std::chrono::milliseconds(10));
          continue;
        }
        const int64_t now_us = SteadyNowUs();
        const int64_t wait_us = pq_.top().release_us - now_us;
        if (wait_us > 0) {
          cv_.wait_for(lock, std::chrono::microseconds(wait_us));
          continue;
        }
        pkt = std::move(const_cast<ScheduledDatagram&>(pq_.top()));
        pq_.pop();
        if (pkt.a_to_b && has_endpoint_b_) {
          dst = endpoint_b_;
          uplink_egress_bytes_ += pkt.data.size();
          can_send = true;
        } else if (!pkt.a_to_b && has_endpoint_a_) {
          dst = endpoint_a_;
          can_send = true;
        }
      }

      if (can_send) {
        boost::system::error_code ec;
        if (pkt.a_to_b) {
          socket_b_.send_to(boost::asio::buffer(pkt.data), dst, 0, ec);
        } else {
          socket_a_.send_to(boost::asio::buffer(pkt.data), dst, 0, ec);
        }
      }
    }
  }

  boost::asio::io_context io_ctx_;
  boost::asio::ip::udp::socket socket_a_;
  boost::asio::ip::udp::socket socket_b_;
  boost::asio::ip::udp::endpoint sender_a_;
  boost::asio::ip::udp::endpoint sender_b_;
  std::array<uint8_t, 2048> rx_buf_a_{};
  std::array<uint8_t, 2048> rx_buf_b_{};
  std::thread io_thread_;
  std::thread shaper_thread_;
  std::atomic<bool> running_{false};

  mutable std::mutex mu_;
  std::condition_variable cv_;
  boost::asio::ip::udp::endpoint endpoint_a_;
  boost::asio::ip::udp::endpoint endpoint_b_;
  bool has_endpoint_a_ = false;
  bool has_endpoint_b_ = false;

  uint64_t uplink_bps_ = 2'000'000;
  uint64_t downlink_bps_ = 10'000'000;
  double uplink_random_loss_prob_ = 0.0;
  uint64_t prng_state_ = 0x9E3779B97F4A7C15ULL;
  int64_t one_way_delay_us_ = 20'000;
  int64_t max_queue_delay_us_ = 120'000;
  int64_t uplink_virt_departure_us_ = 0;
  int64_t downlink_virt_departure_us_ = 0;
  uint64_t next_seq_ = 0;
  std::priority_queue<ScheduledDatagram,
                      std::vector<ScheduledDatagram>,
                      std::greater<ScheduledDatagram>>
      pq_;

  int64_t phase_start_us_ = 0;
  uint64_t uplink_ingress_bytes_ = 0;
  uint64_t uplink_egress_bytes_ = 0;
  uint64_t uplink_forwarded_pkts_ = 0;
  uint64_t uplink_dropped_pkts_ = 0;
  std::vector<double> queue_delays_ms_;
};

// 解析 SDP 中的首个 IPv4 host 候选端口，并将全部候选重写为指向代理监听地址 127.0.0.1:proxy_port。
std::string RewriteSdpCandidatesToProxy(const std::string& sdp,
                                        uint16_t proxy_port,
                                        uint16_t* out_original_port) {
  std::istringstream iss(sdp);
  std::ostringstream oss;
  std::string line;
  bool rewrote_one = false;

  while (std::getline(iss, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.rfind("a=candidate:", 0) == 0) {
      // 格式：a=candidate:<foundation> <comp> UDP <prio> <ip> <port> typ <type>
      std::istringstream ls(line);
      std::string tok_cand, comp, proto, prio, ip, typ_kw, typ_val;
      uint16_t port = 0;
      if ((ls >> tok_cand >> comp >> proto >> prio >> ip >> port >> typ_kw >>
           typ_val) &&
          ip.find(':') == std::string::npos) {
        if (!rewrote_one) {
          if (out_original_port != nullptr) {
            *out_original_port = port;
          }
          oss << "a=candidate:1 1 UDP 2130706431 127.0.0.1 " << proxy_port
              << " typ host\r\n";
          rewrote_one = true;
        }
      }
      continue;
    }
    oss << line << "\r\n";
  }
  return oss.str();
}

std::vector<uint8_t> BuildClosedLoopAnnexBFrame(rtc_video_codec_e codec,
                                                bool is_idr,
                                                size_t target_bytes) {
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
  const size_t clamped_total = std::max<size_t>(out.size() + 16, target_bytes);
  out.resize(clamped_total, 0x6B);
  return out;
}

// 闭环编码与遥测观察者：实时响应 SDK 下发的 OnEncoderBitrateAllocation 码率分配与关键帧请求。
class ClosedLoopCcObserver final : public IRtcEventObserver {
 public:
  explicit ClosedLoopCcObserver(uint32_t init_high_bps = 800'000,
                                uint32_t init_low_bps = 300'000) {
    layer_active_[0] = true;
    layer_active_[1] = true;
    layer_bps_[0] = init_low_bps;
    layer_bps_[1] = init_high_bps;
  }

  void OnEncoderBitrateAllocation(rtc_stream_layer_e layer,
                                  bool layer_active,
                                  uint32_t target_bitrate_bps,
                                  uint32_t target_fps) override {
    std::lock_guard<std::mutex> lock(mu_);
    const size_t idx = (layer == RTC_STREAM_LAYER_LOW) ? 0 : 1;
    layer_active_[idx] = layer_active;
    layer_bps_[idx] = layer_active ? target_bitrate_bps : 0;
    if (target_fps > 0) {
      target_fps_ = target_fps;
    }
    ++bwe_updates_;
  }

  void OnEncoderForceIdr(rtc_stream_layer_e layer) override {
    std::lock_guard<std::mutex> lock(mu_);
    const size_t idx = (layer == RTC_STREAM_LAYER_LOW) ? 0 : 1;
    force_idr_[idx] = true;
  }

  void OnRemoteTrackPublished(const std::string& peer_id,
                              const std::string& track_id,
                              rtc_video_codec_e codec) override {
    (void)peer_id;
    (void)codec;
    std::lock_guard<std::mutex> lock(mu_);
    remote_track_id_ = track_id;
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
    std::lock_guard<std::mutex> lock(mu_);
    ++decoded_frames_;
    if (frame.layer == RTC_STREAM_LAYER_LOW) {
      ++decoded_low_frames_;
    } else {
      ++decoded_high_frames_;
    }
    last_decoded_layer_ = frame.layer;
    cv_.notify_all();
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
    last_stats_ = stats;
    has_stats_ = true;
  }

  bool WaitConnected(int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lock(mu_);
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                        [this]() { return connected_; });
  }

  bool WaitRemoteTrack(std::string* out_track, int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lock(mu_);
    const bool ok = cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                 [this]() { return !remote_track_id_.empty(); });
    if (ok && out_track != nullptr) {
      *out_track = remote_track_id_;
    }
    return ok;
  }

  void GetEncoderState(bool simulcast,
                       bool* out_low_active,
                       uint32_t* out_low_bps,
                       bool* out_high_active,
                       uint32_t* out_high_bps,
                       bool* out_low_idr,
                       bool* out_high_idr) {
    std::lock_guard<std::mutex> lock(mu_);
    *out_low_active = simulcast ? layer_active_[0] : false;
    *out_low_bps = simulcast ? layer_bps_[0] : 0;
    *out_high_active = layer_active_[1];
    *out_high_bps = layer_bps_[1];
    *out_low_idr = force_idr_[0];
    *out_high_idr = force_idr_[1];
    force_idr_[0] = false;
    force_idr_[1] = false;
  }

  uint32_t TotalAllocatedKbps(bool simulcast) const {
    std::lock_guard<std::mutex> lock(mu_);
    const uint64_t total_bps =
        (simulcast && layer_active_[0] ? layer_bps_[0] : 0) +
        (layer_active_[1] ? layer_bps_[1] : 0);
    return static_cast<uint32_t>(total_bps / 1000);
  }

  bool IsHighLayerActive() const {
    std::lock_guard<std::mutex> lock(mu_);
    return layer_active_[1];
  }

  uint64_t decoded_frames() const {
    std::lock_guard<std::mutex> lock(mu_);
    return decoded_frames_;
  }
  uint64_t decoded_low_frames() const {
    std::lock_guard<std::mutex> lock(mu_);
    return decoded_low_frames_;
  }
  uint64_t decoded_high_frames() const {
    std::lock_guard<std::mutex> lock(mu_);
    return decoded_high_frames_;
  }
  rtc_network_stats_t last_stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return last_stats_;
  }

 private:
  mutable std::mutex mu_;
  std::condition_variable cv_;
  bool connected_ = false;
  std::string remote_track_id_;
  bool layer_active_[2]{true, true};
  uint32_t layer_bps_[2]{300'000, 800'000};
  bool force_idr_[2]{true, true};
  uint32_t target_fps_ = 30;
  uint64_t bwe_updates_ = 0;
  uint64_t decoded_frames_ = 0;
  uint64_t decoded_low_frames_ = 0;
  uint64_t decoded_high_frames_ = 0;
  rtc_stream_layer_e last_decoded_layer_ = RTC_STREAM_LAYER_HIGH;
  rtc_network_stats_t last_stats_{};
  bool has_stats_ = false;
};

// 1. 验证长周期嵌入式主机运行（跨 6.21 天 24 位 TWCC 基准时间回绕边界与 15 天超长运行时间）
//    下 RtcpTransportFeedback 序列化/解析与 TransportFeedbackAdapter 单调时间展开的精确性。
TEST(RtcRealCongestionControlTest, Twcc24BitWraparoundMultiWeekUptimeSafety) {
  TransportFeedbackAdapter adapter;
  GoogCcConfig cfg;
  cfg.start_bitrate = DataRate::KilobitsPerSec(1200);
  GoogCcNetworkController goog_cc(cfg);

  // 0x7FFFFF * 64,000 us = 536,870,848,000 us（约 6.21378 天，恰处 24 位有符号基准时间跳变前夕）
  int64_t rx_clock_us = int64_t{0x7FFFFF} * 64'000 - 20'000;
  int64_t tx_clock_us = 10'000'000;
  uint16_t twcc_seq = 65530;  // 同时覆盖 16 位 TWCC 序列号跨 65535 -> 0 回绕边界

  for (int batch = 0; batch < 6; ++batch) {
    RtcpTransportFeedback fb;
    fb.sender_ssrc = 0x1111;
    fb.media_ssrc = 0x2222;
    fb.feedback_seq = static_cast<uint8_t>(batch);

    for (int i = 0; i < 10; ++i) {
      const uint16_t seq = twcc_seq++;
      PacedPacketInfo pinfo;
      adapter.AddPacket(seq, DataSize::Bytes(1100), pinfo,
                        Timestamp::Micros(tx_clock_us));
      auto sent = adapter.ProcessSentPacket(seq, Timestamp::Micros(tx_clock_us));
      ASSERT_TRUE(sent.has_value());
      (void)goog_cc.OnSentPacket(*sent);

      // 发送间隔与接收间隔严格相等（均为 5ms），对应零排队斜率（kBwNormal）
      if (i == 0) {
        fb.SetBase(seq, Timestamp::Micros(rx_clock_us));
      }
      ASSERT_TRUE(fb.AddReceivedPacket(seq, Timestamp::Micros(rx_clock_us)));
      tx_clock_us += 5000;
      rx_clock_us += 5000;
    }

    const auto wire = fb.Build();
    ASSERT_GT(wire.size(), 20u);
    const ParsedCompoundRtcp parsed = ParseCompoundRtcp(wire);
    ASSERT_EQ(parsed.transport_feedbacks.size(), 1u);

    const auto report = adapter.ProcessTransportFeedback(
        parsed.transport_feedbacks[0], Timestamp::Micros(tx_clock_us + 20'000));
    ASSERT_TRUE(report.has_value());
    ASSERT_EQ(report->packet_feedbacks.size(), 10u);

    for (size_t i = 1; i < report->packet_feedbacks.size(); ++i) {
      const TimeDelta rx_delta = report->packet_feedbacks[i].receive_time -
                                 report->packet_feedbacks[i - 1].receive_time;
      EXPECT_EQ(rx_delta.us(), 5000);
    }

    (void)goog_cc.OnTransportPacketsFeedback(*report);
    EXPECT_EQ(goog_cc.DetectorState(), BandwidthUsage::kBwNormal);
  }
}

// 2. 真实 UDP 瓶颈路由器下的 WebRTC P2P（GoogCC + Pacer + TWCC + RTX + FlexFEC）
//    三阶段动态拥塞控制实测：2400 kbps 爬升 -> 650 kbps 拥塞骤降 -> 2200 kbps 带宽恢复。
TEST(RtcRealCongestionControlTest, WebRtcP2pGoogCcDynamicBottleneckAdaptation) {
  RtcVideoEngine::SetMinLogSeverity(LoggingSeverity::kWarning);

  // 初始上行瓶颈容量 2400 kbps，下行 10 Mbps，单向传播时延 20ms（基础 RTT=40ms），路由队列上限 120ms
  RealUdpBottleneckProxy proxy(/*上行容量=*/2'400'000,
                               /*下行容量=*/10'000'000,
                               /*单向时延毫秒=*/20,
                               /*最大队列毫秒=*/120);
  ASSERT_TRUE(proxy.Start());

  EngineConfig pub_cfg;
  pub_cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  pub_cfg.publish_codec = RTC_CODEC_H264;
  pub_cfg.min_bitrate_bps = 150'000;
  pub_cfg.start_bitrate_bps = 800'000;
  pub_cfg.max_bitrate_bps = 3'500'000;
  pub_cfg.enable_flexfec = true;
  pub_cfg.zero_playout_delay = true;

  EngineConfig sub_cfg = pub_cfg;

  ClosedLoopCcObserver pub_obs(/*初始高清码率=*/800'000);
  ClosedLoopCcObserver sub_obs(/*初始高清码率=*/800'000);
  auto pub_eng = RtcVideoEngine::Create(pub_cfg, &pub_obs);
  auto sub_eng = RtcVideoEngine::Create(sub_cfg, &sub_obs);

  ASSERT_EQ(pub_eng->JoinRoom("real_cc_p2p", "pub_cam"), RTC_OK);
  ASSERT_EQ(sub_eng->JoinRoom("real_cc_p2p", "sub_viewer"), RTC_OK);

  std::string raw_offer;
  ASSERT_EQ(pub_eng->CreateLocalOffer(&raw_offer), RTC_OK);
  uint16_t pub_real_port = 0;
  const std::string proxied_offer =
      RewriteSdpCandidatesToProxy(raw_offer, proxy.port_b(), &pub_real_port);
  ASSERT_GT(pub_real_port, 0u);
  proxy.SetEndpointA(boost::asio::ip::udp::endpoint(
      boost::asio::ip::make_address("127.0.0.1"), pub_real_port));

  std::string raw_answer;
  ASSERT_EQ(sub_eng->SetRemoteDescription("offer", proxied_offer, &raw_answer),
            RTC_OK);
  uint16_t sub_real_port = 0;
  const std::string proxied_answer =
      RewriteSdpCandidatesToProxy(raw_answer, proxy.port_a(), &sub_real_port);
  ASSERT_GT(sub_real_port, 0u);
  proxy.SetEndpointB(boost::asio::ip::udp::endpoint(
      boost::asio::ip::make_address("127.0.0.1"), sub_real_port));

  ASSERT_EQ(pub_eng->SetRemoteDescription("answer", proxied_answer, nullptr),
            RTC_OK);

  ASSERT_TRUE(pub_obs.WaitConnected(5000));
  ASSERT_TRUE(sub_obs.WaitConnected(5000));

  // 启动 30fps 真实闭环视频编码线程，严格按照 SDK 回调的目标码率生成 Annex-B 帧字节数。
  std::atomic<bool> stop_enc{false};
  std::thread enc_thread([&]() {
    uint64_t ts_us = 1'000'000;
    uint32_t frame_idx = 0;
    auto next_tick = std::chrono::steady_clock::now();
    while (!stop_enc.load(std::memory_order_acquire)) {
      bool low_act = false, high_act = true, low_idr = false, high_idr = false;
      uint32_t low_bps = 0, high_bps = 800'000;
      pub_obs.GetEncoderState(/*启用联播=*/false, &low_act, &low_bps,
                              &high_act, &high_bps, &low_idr, &high_idr);

      const bool is_idr = (frame_idx % 30 == 0) || high_idr;
      const size_t frame_bytes =
          std::max<size_t>(120, static_cast<size_t>(high_bps / (30 * 8)));
      const auto nalu =
          BuildClosedLoopAnnexBFrame(RTC_CODEC_H264, is_idr, frame_bytes);

      rtc_encoded_frame_t f{};
      f.data = nalu.data();
      f.size = nalu.size();
      f.capture_ts_us = ts_us;
      f.is_keyframe = is_idr;
      f.layer = RTC_STREAM_LAYER_HIGH;
      f.temporal_id = static_cast<uint8_t>(frame_idx % 2);
      pub_eng->PushVideoFrame(f);

      ++frame_idx;
      ts_us += 33'333;
      next_tick += std::chrono::microseconds(33'333);
      std::this_thread::sleep_until(next_tick);
    }
  });

  std::cout << "\n--- [WebRTC P2P (GoogCC) 0.5s 粒度实时追踪轨迹] ---\n";
  double sim_sec = 0.0;
  auto log_p2p_slice = [&](const char* tag, uint32_t cap_kbps) {
    sim_sec += 0.5;
    std::cout << std::fixed << std::setprecision(1) << "  t=" << std::setw(4)
              << sim_sec << "s [" << tag << " 限速=" << std::setw(4) << cap_kbps
              << "k] -> SDK编码分配=" << std::setw(4)
              << pub_obs.TotalAllocatedKbps(false)
              << " kbps | 累计解码帧=" << sub_obs.decoded_frames() << "\n";
  };

  // 阶段 1：2400 kbps 高带宽爬升与稳态（预热 1.0s 后统计 2.5s 稳态窗口）
  for (int k = 0; k < 2; ++k) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    log_p2p_slice("爬升预热", 2400);
  }
  proxy.ResetPhaseTelemetry();
  const uint64_t dec_before_p1 = sub_obs.decoded_frames();
  uint32_t p1_peak_alloc_kbps = 0;
  for (int i = 0; i < 25; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    p1_peak_alloc_kbps =
        std::max(p1_peak_alloc_kbps, pub_obs.TotalAllocatedKbps(false));
    if ((i + 1) % 5 == 0) {
      log_p2p_slice("阶段1稳态", 2400);
    }
  }
  const uint32_t p1_end_alloc_kbps = pub_obs.TotalAllocatedKbps(false);
  const auto p1_tel = proxy.SnapshotPhaseTelemetry();
  const uint64_t p1_decoded = sub_obs.decoded_frames() - dec_before_p1;

  // 阶段 2：物理瓶颈骤降至 650 kbps（收敛过渡 1.2s 后统计 2.3s 稳态窗口）
  proxy.SetUplinkCapacityBps(650'000);
  for (int k = 0; k < 2; ++k) {
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    sim_sec += 0.1;
    log_p2p_slice("骤降过渡", 650);
  }
  proxy.ResetPhaseTelemetry();
  const uint64_t dec_before_p2 = sub_obs.decoded_frames();
  uint32_t p2_min_alloc_kbps = 10'000;
  uint64_t p2_sum_alloc_kbps = 0;
  for (int i = 0; i < 23; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const uint32_t cur = pub_obs.TotalAllocatedKbps(false);
    p2_min_alloc_kbps = std::min(p2_min_alloc_kbps, cur);
    p2_sum_alloc_kbps += cur;
    if ((i + 1) % 5 == 0) {
      log_p2p_slice("阶段2限速", 650);
    }
  }
  const uint32_t p2_avg_alloc_kbps = static_cast<uint32_t>(p2_sum_alloc_kbps / 23);
  const auto p2_tel = proxy.SnapshotPhaseTelemetry();
  const uint64_t p2_decoded = sub_obs.decoded_frames() - dec_before_p2;

  // 阶段 3：物理瓶颈恢复至 2200 kbps（探测爬升 1.2s 后统计 2.8s 恢复窗口）
  proxy.SetUplinkCapacityBps(2'200'000);
  for (int k = 0; k < 2; ++k) {
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    sim_sec += 0.1;
    log_p2p_slice("恢复探测", 2200);
  }
  proxy.ResetPhaseTelemetry();
  const uint64_t dec_before_p3 = sub_obs.decoded_frames();
  uint32_t p3_peak_alloc_kbps = 0;
  for (int i = 0; i < 28; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    p3_peak_alloc_kbps =
        std::max(p3_peak_alloc_kbps, pub_obs.TotalAllocatedKbps(false));
    if ((i + 1) % 5 == 0) {
      log_p2p_slice("阶段3恢复", 2200);
    }
  }
  const auto p3_tel = proxy.SnapshotPhaseTelemetry();
  const uint64_t p3_decoded = sub_obs.decoded_frames() - dec_before_p3;

  stop_enc.store(true, std::memory_order_release);
  enc_thread.join();

  std::cout << "\n==================== [WebRTC P2P (GoogCC) 真实瓶颈拥塞控制实测报告] ====================\n"
            << std::fixed << std::setprecision(1)
            << "  阶段 1 (2400 kbps 爬升稳态): 编码分配峰值=" << p1_peak_alloc_kbps
            << " kbps (末值=" << p1_end_alloc_kbps << " kbps)"
            << " | 真实网卡入站=" << p1_tel.uplink_ingress_kbps << " kbps"
            << " | 瓶颈出站=" << p1_tel.uplink_egress_kbps << " kbps"
            << " | 排队P50/P95=" << p1_tel.queue_delay_p50_ms << "/"
            << p1_tel.queue_delay_p95_ms << " ms"
            << " | 丢包率=" << (p1_tel.drop_ratio * 100.0) << "%"
            << " | 解码帧=" << p1_decoded << "\n"
            << "  阶段 2 (650 kbps 拥塞骤降):  编码分配均值=" << p2_avg_alloc_kbps
            << " kbps (最低=" << p2_min_alloc_kbps << " kbps)"
            << " | 真实网卡入站=" << p2_tel.uplink_ingress_kbps << " kbps"
            << " | 瓶颈出站=" << p2_tel.uplink_egress_kbps << " kbps"
            << " | 排队P50/P95=" << p2_tel.queue_delay_p50_ms << "/"
            << p2_tel.queue_delay_p95_ms << " ms"
            << " | 丢包率=" << (p2_tel.drop_ratio * 100.0) << "%"
            << " | 解码帧=" << p2_decoded << "\n"
            << "  阶段 3 (2200 kbps 容量恢复): 编码分配峰值=" << p3_peak_alloc_kbps
            << " kbps"
            << " | 真实网卡入站=" << p3_tel.uplink_ingress_kbps << " kbps"
            << " | 瓶颈出站=" << p3_tel.uplink_egress_kbps << " kbps"
            << " | 排队P50/P95=" << p3_tel.queue_delay_p50_ms << "/"
            << p3_tel.queue_delay_p95_ms << " ms"
            << " | 丢包率=" << (p3_tel.drop_ratio * 100.0) << "%"
            << " | 解码帧=" << p3_decoded << "\n"
            << "=======================================================================================\n";

  // 断言 1：阶段 1 从初始 800 kbps 成功探测并爬升（含 RTP/SRTP/FlexFEC 开销守恒折算后媒体码率显著高于起始值）
  EXPECT_GE(p1_peak_alloc_kbps, 1300u);
  EXPECT_LE(p1_end_alloc_kbps, 2400u);
  EXPECT_GE(p1_tel.uplink_egress_kbps, 1400.0);
  EXPECT_GT(p1_decoded, 40u);

  // 断言 2：阶段 2 链路骤降至 650 kbps 后，GoogCC 准确识别排队/丢包并大幅下调编码器目标码率，防止网络崩溃
  EXPECT_LE(p2_avg_alloc_kbps, 680u);
  EXPECT_LT(p2_avg_alloc_kbps, (p1_peak_alloc_kbps * 55) / 100);
  EXPECT_LE(p2_tel.uplink_ingress_kbps, 850.0);
  EXPECT_GT(p2_decoded, 20u);

  // 断言 3：阶段 3 链路恢复至 2200 kbps 后，探测与 AIMD 使编码器目标码率显著回升
  EXPECT_GE(p3_peak_alloc_kbps, 1100u);
  EXPECT_GT(p3_peak_alloc_kbps, p2_avg_alloc_kbps + 450u);
  EXPECT_GT(p3_decoded, 45u);

  pub_eng->LeaveRoom();
  sub_eng->LeaveRoom();
  proxy.Stop();
}

// 3. 真实 UDP 瓶颈路由器下的 IETF MoQ（QUIC v1 + Simulcast + 全部 5 种可插拔拥塞控制模块及热切换）实测。
TEST(RtcRealCongestionControlTest,
     MoqSimulcastAndAllFiveQuicCongestionControllersRealBottleneck) {
  RtcVideoEngine::SetMinLogSeverity(LoggingSeverity::kWarning);

  // ---------------- 第一部分：Simulcast 高低清层自动启停 + 拥塞骤降降级 + 恢复回切 + 热切换 ----------------
  EmbeddedMoqRelayServer relay("127.0.0.1");
  ASSERT_TRUE(relay.Start(0));

  RealUdpBottleneckProxy proxy(/*上行容量=*/2'800'000,
                               /*下行容量=*/10'000'000,
                               /*单向时延毫秒=*/15,
                               /*最大队列毫秒=*/120);
  ASSERT_TRUE(proxy.Start());
  proxy.SetEndpointB(boost::asio::ip::udp::endpoint(
      boost::asio::ip::make_address("127.0.0.1"), relay.udp_port()));

  EngineConfig sub_cfg;
  sub_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
  sub_cfg.signaling_or_moq_url =
      "moq://127.0.0.1:" + std::to_string(relay.udp_port());
  sub_cfg.zero_playout_delay = true;

  ClosedLoopCcObserver sub_obs;
  auto sub_eng = RtcVideoEngine::Create(sub_cfg, &sub_obs);
  ASSERT_EQ(sub_eng->JoinRoom("real_cc_moq", "sub_nvr"), RTC_OK);
  ASSERT_TRUE(sub_obs.WaitConnected(5000));

  EngineConfig pub_cfg;
  pub_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
  pub_cfg.signaling_or_moq_url =
      "moq://127.0.0.1:" + std::to_string(proxy.port_a());
  pub_cfg.publish_codec = RTC_CODEC_H265;
  pub_cfg.enable_simulcast = true;
  pub_cfg.min_bitrate_bps = 150'000;
  pub_cfg.start_bitrate_bps = 1'500'000;
  pub_cfg.max_bitrate_bps = 4'500'000;
  pub_cfg.moq_delivery_timeout_ms = 300;
  pub_cfg.quic_cc_algo = RTC_QUIC_CC_BBR;
  pub_cfg.zero_playout_delay = true;

  ClosedLoopCcObserver pub_obs(/*初始高清码率=*/1'100'000,
                               /*初始低清码率=*/400'000);
  auto pub_eng = RtcVideoEngine::Create(pub_cfg, &pub_obs);
  ASSERT_EQ(pub_eng->JoinRoom("real_cc_moq", "pub_uav"), RTC_OK);
  ASSERT_TRUE(pub_obs.WaitConnected(5000));

  std::string discovered_track;
  ASSERT_TRUE(sub_obs.WaitRemoteTrack(&discovered_track, 5000));
  ASSERT_EQ(sub_eng->SubscribeTrack(discovered_track, RTC_STREAM_LAYER_HIGH),
            RTC_OK);
  std::this_thread::sleep_for(std::chrono::milliseconds(60));

  std::atomic<bool> stop_moq_enc{false};
  std::thread moq_enc_thread([&]() {
    uint64_t ts_us = 2'000'000;
    uint32_t frame_idx = 0;
    auto next_tick = std::chrono::steady_clock::now();
    while (!stop_moq_enc.load(std::memory_order_acquire)) {
      bool low_act = true, high_act = true, low_idr = false, high_idr = false;
      uint32_t low_bps = 400'000, high_bps = 1'100'000;
      pub_obs.GetEncoderState(/*启用联播=*/true, &low_act, &low_bps, &high_act,
                              &high_bps, &low_idr, &high_idr);

      // 每 15 帧（500ms）生成对齐 GOP 关键帧，使高低层按需平滑切换
      const bool gop_idr = (frame_idx % 15 == 0);
      if (low_act && low_bps > 0) {
        const bool is_idr = gop_idr || low_idr;
        const size_t sz =
            std::max<size_t>(100, static_cast<size_t>(low_bps / (30 * 8)));
        const auto bytes =
            BuildClosedLoopAnnexBFrame(RTC_CODEC_H265, is_idr, sz);
        rtc_encoded_frame_t lf{};
        lf.data = bytes.data();
        lf.size = bytes.size();
        lf.capture_ts_us = ts_us;
        lf.is_keyframe = is_idr;
        lf.layer = RTC_STREAM_LAYER_LOW;
        lf.temporal_id = 0;
        pub_eng->PushVideoFrame(lf);
      }

      if (high_act && high_bps > 0) {
        const bool is_idr = gop_idr || high_idr;
        const size_t sz =
            std::max<size_t>(140, static_cast<size_t>(high_bps / (30 * 8)));
        const auto bytes =
            BuildClosedLoopAnnexBFrame(RTC_CODEC_H265, is_idr, sz);
        rtc_encoded_frame_t hf{};
        hf.data = bytes.data();
        hf.size = bytes.size();
        hf.capture_ts_us = ts_us;
        hf.is_keyframe = is_idr;
        hf.layer = RTC_STREAM_LAYER_HIGH;
        hf.temporal_id = 0;
        pub_eng->PushVideoFrame(hf);
      }

      ++frame_idx;
      ts_us += 33'333;
      next_tick += std::chrono::microseconds(33'333);
      std::this_thread::sleep_until(next_tick);
    }
  });

  std::cout << "\n--- [IETF MoQ (QUIC v1 + Simulcast) 0.6s 粒度实时追踪轨迹] ---\n";
  double moq_sec = 0.0;
  auto log_moq_slice = [&](const char* tag, uint32_t cap_kbps, double dt) {
    moq_sec += dt;
    std::cout << std::fixed << std::setprecision(1) << "  t=" << std::setw(4)
              << moq_sec << "s [" << tag << " 限速=" << std::setw(4) << cap_kbps
              << "k] -> SDK总分配=" << std::setw(4)
              << pub_obs.TotalAllocatedKbps(true) << " kbps | 高清层激活="
              << (pub_obs.IsHighLayerActive() ? "是" : "否")
              << " | 累计高清/低清解码=" << sub_obs.decoded_high_frames() << "/"
              << sub_obs.decoded_low_frames() << "\n";
  };

  // MoQ 阶段 1：2800 kbps 双层高清稳态（预热 0.6s + 观测 1.8s）
  std::this_thread::sleep_for(std::chrono::milliseconds(600));
  log_moq_slice("双层预热", 2800, 0.6);
  proxy.ResetPhaseTelemetry();
  const uint64_t moq_high_before_p1 = sub_obs.decoded_high_frames();
  uint64_t m1_sum_alloc = 0;
  bool m1_high_active_seen = false;
  for (int i = 0; i < 18; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    m1_sum_alloc += pub_obs.TotalAllocatedKbps(true);
    if (pub_obs.IsHighLayerActive()) {
      m1_high_active_seen = true;
    }
    if ((i + 1) % 6 == 0) {
      log_moq_slice("阶段1双层", 2800, 0.6);
    }
  }
  const uint32_t m1_avg_alloc_kbps = static_cast<uint32_t>(m1_sum_alloc / 18);
  const auto m1_tel = proxy.SnapshotPhaseTelemetry();
  const uint64_t m1_high_decoded =
      sub_obs.decoded_high_frames() - moq_high_before_p1;

  // MoQ 阶段 2：瓶颈骤降至 580 kbps（过渡 0.8s + 观测 1.8s），验证自动暂停高清层且 Relay 无缝降级转发低清层
  proxy.SetUplinkCapacityBps(580'000);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  log_moq_slice("骤降挂起", 580, 0.8);
  proxy.ResetPhaseTelemetry();
  const uint64_t moq_low_before_p2 = sub_obs.decoded_low_frames();
  uint64_t m2_sum_alloc = 0;
  int m2_high_suspended_samples = 0;
  for (int i = 0; i < 18; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    m2_sum_alloc += pub_obs.TotalAllocatedKbps(true);
    if (!pub_obs.IsHighLayerActive()) {
      ++m2_high_suspended_samples;
    }
    if ((i + 1) % 6 == 0) {
      log_moq_slice("阶段2降级", 580, 0.6);
    }
  }
  const uint32_t m2_avg_alloc_kbps = static_cast<uint32_t>(m2_sum_alloc / 18);
  const auto m2_tel = proxy.SnapshotPhaseTelemetry();
  const uint64_t m2_low_decoded =
      sub_obs.decoded_low_frames() - moq_low_before_p2;

  // MoQ 阶段 3：恢复至 2800 kbps 并在线热切换拥塞控制模块（BBRv1 -> BBRv2 -> CUBIC）
  proxy.SetUplinkCapacityBps(2'800'000);
  ASSERT_EQ(pub_eng->SetQuicCongestionControl(RTC_QUIC_CC_BBR2), RTC_OK);
  std::this_thread::sleep_for(std::chrono::milliseconds(900));
  log_moq_slice("切至BBR2", 2800, 0.9);
  ASSERT_EQ(pub_eng->SetQuicCongestionControl(RTC_QUIC_CC_CUBIC), RTC_OK);
  proxy.ResetPhaseTelemetry();
  const uint64_t moq_high_before_p3 = sub_obs.decoded_high_frames();
  uint32_t m3_peak_alloc_kbps = 0;
  bool m3_high_restored = false;
  for (int i = 0; i < 20; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    m3_peak_alloc_kbps =
        std::max(m3_peak_alloc_kbps, pub_obs.TotalAllocatedKbps(true));
    if (pub_obs.IsHighLayerActive()) {
      m3_high_restored = true;
    }
    if ((i + 1) % 5 == 0) {
      log_moq_slice("切CUBIC稳", 2800, 0.5);
    }
  }
  const auto m3_tel = proxy.SnapshotPhaseTelemetry();
  const uint64_t m3_high_decoded =
      sub_obs.decoded_high_frames() - moq_high_before_p3;

  stop_moq_enc.store(true, std::memory_order_release);
  moq_enc_thread.join();

  std::cout << "\n================ [IETF MoQ (QUIC v1 + Simulcast) 真实瓶颈拥塞控制实测报告] ================\n"
            << std::fixed << std::setprecision(1)
            << "  阶段 1 (2800 kbps BBRv1 双层): 编码分配均值=" << m1_avg_alloc_kbps
            << " kbps | 网卡入站=" << m1_tel.uplink_ingress_kbps << " kbps"
            << " | 瓶颈出站=" << m1_tel.uplink_egress_kbps << " kbps"
            << " | 排队P50/P95=" << m1_tel.queue_delay_p50_ms << "/"
            << m1_tel.queue_delay_p95_ms << " ms"
            << " | 高清解码帧=" << m1_high_decoded << "\n"
            << "  阶段 2 (580 kbps 拥塞骤降):    编码分配均值=" << m2_avg_alloc_kbps
            << " kbps | 网卡入站=" << m2_tel.uplink_ingress_kbps << " kbps"
            << " | 瓶颈出站=" << m2_tel.uplink_egress_kbps << " kbps"
            << " | 高清层暂停占比=" << m2_high_suspended_samples << "/18"
            << " | 自动降级低清解码帧=" << m2_low_decoded << "\n"
            << "  阶段 3 (2800 kbps 恢复+热切):  编码分配峰值=" << m3_peak_alloc_kbps
            << " kbps | 网卡入站=" << m3_tel.uplink_ingress_kbps << " kbps"
            << " | 瓶颈出站=" << m3_tel.uplink_egress_kbps << " kbps"
            << " | 高清恢复解码帧=" << m3_high_decoded << "\n"
            << "==========================================================================================\n";

  EXPECT_TRUE(m1_high_active_seen);
  EXPECT_GE(m1_avg_alloc_kbps, 1600u);
  EXPECT_GT(m1_high_decoded, 20u);

  EXPECT_GE(m2_high_suspended_samples, 12);
  EXPECT_LE(m2_avg_alloc_kbps, 620u);
  EXPECT_GT(m2_low_decoded, 15u);

  EXPECT_TRUE(m3_high_restored);
  EXPECT_GE(m3_peak_alloc_kbps, 1400u);
  EXPECT_GT(m3_high_decoded, 15u);

  sub_eng->LeaveRoom();
  pub_eng->LeaveRoom();
  proxy.Stop();

  // ---------------- 第二部分：逐一验证全部 5 种内置 QUIC 拥塞控制模块在真实受限管道上的收敛与退避 ----------------
  const rtc_quic_cc_algo_e kAlgos[] = {
      RTC_QUIC_CC_BBR,     RTC_QUIC_CC_BBR2,    RTC_QUIC_CC_CUBIC,
      RTC_QUIC_CC_COPA,    RTC_QUIC_CC_NEWRENO,
  };

  std::cout << "\n---------------- [全部 5 种可插拔 QUIC 拥塞控制真实 UDP 瓶颈对比 (1600 -> 600 kbps)] ----------------\n";
  for (rtc_quic_cc_algo_e algo : kAlgos) {
    RealUdpBottleneckProxy algo_proxy(/*上行容量=*/1'600'000,
                                      /*下行容量=*/10'000'000,
                                      /*单向时延毫秒=*/15,
                                      /*最大队列毫秒=*/100);
    ASSERT_TRUE(algo_proxy.Start());
    algo_proxy.SetEndpointB(boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address("127.0.0.1"), relay.udp_port()));

    EngineConfig cfg;
    cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
    cfg.signaling_or_moq_url =
        "moq://127.0.0.1:" + std::to_string(algo_proxy.port_a());
    cfg.publish_codec = RTC_CODEC_H264;
    cfg.enable_simulcast = false;
    cfg.min_bitrate_bps = 150'000;
    cfg.start_bitrate_bps = 1'000'000;
    cfg.max_bitrate_bps = 3'500'000;
    cfg.quic_cc_algo = algo;

    ClosedLoopCcObserver obs(/*初始高清码率=*/1'000'000);
    auto eng = RtcVideoEngine::Create(cfg, &obs);
    const std::string peer_name =
        "peer_" + std::string(QuicCcAlgoName(algo));
    ASSERT_EQ(eng->JoinRoom("cc_matrix_room", peer_name), RTC_OK);
    ASSERT_TRUE(obs.WaitConnected(4000));

    std::atomic<bool> stop_t{false};
    std::thread writer([&]() {
      uint64_t ts = 5'000'000;
      uint32_t idx = 0;
      auto next_t = std::chrono::steady_clock::now();
      while (!stop_t.load(std::memory_order_acquire)) {
        bool la = false, ha = true, li = false, hi = false;
        uint32_t lb = 0, hb = 1'000'000;
        obs.GetEncoderState(false, &la, &lb, &ha, &hb, &li, &hi);
        const bool idr = (idx % 20 == 0) || hi;
        const size_t sz =
            std::max<size_t>(100, static_cast<size_t>(hb / (30 * 8)));
        const auto bytes = BuildClosedLoopAnnexBFrame(RTC_CODEC_H264, idr, sz);
        rtc_encoded_frame_t f{};
        f.data = bytes.data();
        f.size = bytes.size();
        f.capture_ts_us = ts;
        f.is_keyframe = idr;
        f.layer = RTC_STREAM_LAYER_HIGH;
        eng->PushVideoFrame(f);
        ++idx;
        ts += 33'333;
        next_t += std::chrono::microseconds(33'333);
        std::this_thread::sleep_until(next_t);
      }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    algo_proxy.ResetPhaseTelemetry();
    uint64_t hi_sum_kbps = 0;
    for (int s = 0; s < 10; ++s) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      hi_sum_kbps += obs.TotalAllocatedKbps(false);
    }
    const uint32_t hi_alloc_kbps = static_cast<uint32_t>(hi_sum_kbps / 10);
    const auto hi_tel = algo_proxy.SnapshotPhaseTelemetry();

    algo_proxy.SetUplinkCapacityBps(600'000);
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    algo_proxy.ResetPhaseTelemetry();
    uint64_t lo_sum_kbps = 0;
    for (int s = 0; s < 8; ++s) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      lo_sum_kbps += obs.TotalAllocatedKbps(false);
    }
    const uint32_t lo_alloc_kbps = static_cast<uint32_t>(lo_sum_kbps / 8);
    const auto lo_tel = algo_proxy.SnapshotPhaseTelemetry();

    stop_t.store(true, std::memory_order_release);
    writer.join();

    std::cout << "  [" << std::left << std::setw(8)
              << QuicCcAlgoName(algo) << std::right << "] "
              << "1600k阶段: 分配=" << std::setw(4) << hi_alloc_kbps
              << " kbps, 出站=" << std::setw(6) << hi_tel.uplink_egress_kbps
              << " kbps | 600k限速阶段: 分配=" << std::setw(4) << lo_alloc_kbps
              << " kbps, 出站=" << std::setw(6) << lo_tel.uplink_egress_kbps
              << " kbps, P50排队=" << lo_tel.queue_delay_p50_ms << " ms\n";

    EXPECT_GE(hi_alloc_kbps, 950u) << QuicCcAlgoName(algo);
    EXPECT_LE(lo_alloc_kbps, 680u) << QuicCcAlgoName(algo);
    EXPECT_LT(lo_alloc_kbps, hi_alloc_kbps) << QuicCcAlgoName(algo);

    eng->LeaveRoom();
    algo_proxy.Stop();
  }
  std::cout << "-----------------------------------------------------------------------------------------------------\n";

  relay.Stop();
}

// 4. 无线弱网随机丢包（8% 上行随机丢包 + 1800 kbps 物理限速 + 40ms RTT）下
//    WebRTC P2P（GoogCC + FlexFEC + RTX）与 IETF MoQ（BBRv2 + QUIC 流重传）的抗丢包拥塞控制实测。
TEST(RtcRealCongestionControlTest, WirelessRandomLossResilienceWebRtcAndMoq) {
  RtcVideoEngine::SetMinLogSeverity(LoggingSeverity::kWarning);

  // ---------------- 场景 A：WebRTC P2P 在 8% 随机无线丢包 + 1800 kbps 限速下的稳态表现 ----------------
  RealUdpBottleneckProxy p2p_proxy(/*上行容量=*/1'800'000,
                                   /*下行容量=*/10'000'000,
                                   /*单向时延毫秒=*/20,
                                   /*最大队列毫秒=*/140);
  ASSERT_TRUE(p2p_proxy.Start());

  EngineConfig p2p_cfg;
  p2p_cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  p2p_cfg.publish_codec = RTC_CODEC_H264;
  p2p_cfg.min_bitrate_bps = 150'000;
  p2p_cfg.start_bitrate_bps = 1'000'000;
  p2p_cfg.max_bitrate_bps = 3'000'000;
  p2p_cfg.enable_flexfec = true;
  p2p_cfg.zero_playout_delay = true;

  ClosedLoopCcObserver p2p_pub_obs(/*初始高清码率=*/1'000'000);
  ClosedLoopCcObserver p2p_sub_obs(/*初始高清码率=*/1'000'000);
  auto p2p_pub = RtcVideoEngine::Create(p2p_cfg, &p2p_pub_obs);
  auto p2p_sub = RtcVideoEngine::Create(p2p_cfg, &p2p_sub_obs);

  ASSERT_EQ(p2p_pub->JoinRoom("lossy_p2p", "cam"), RTC_OK);
  ASSERT_EQ(p2p_sub->JoinRoom("lossy_p2p", "viewer"), RTC_OK);

  std::string raw_offer;
  ASSERT_EQ(p2p_pub->CreateLocalOffer(&raw_offer), RTC_OK);
  uint16_t pub_port = 0;
  const std::string prox_offer =
      RewriteSdpCandidatesToProxy(raw_offer, p2p_proxy.port_b(), &pub_port);
  p2p_proxy.SetEndpointA(boost::asio::ip::udp::endpoint(
      boost::asio::ip::make_address("127.0.0.1"), pub_port));

  std::string raw_ans;
  ASSERT_EQ(p2p_sub->SetRemoteDescription("offer", prox_offer, &raw_ans),
            RTC_OK);
  uint16_t sub_port = 0;
  const std::string prox_ans =
      RewriteSdpCandidatesToProxy(raw_ans, p2p_proxy.port_a(), &sub_port);
  p2p_proxy.SetEndpointB(boost::asio::ip::udp::endpoint(
      boost::asio::ip::make_address("127.0.0.1"), sub_port));
  ASSERT_EQ(p2p_pub->SetRemoteDescription("answer", prox_ans, nullptr), RTC_OK);

  ASSERT_TRUE(p2p_pub_obs.WaitConnected(5000));
  ASSERT_TRUE(p2p_sub_obs.WaitConnected(5000));

  // 握手完成后注入 8% 无线随机丢包
  p2p_proxy.SetUplinkRandomLossProb(0.08);

  std::atomic<bool> stop_p2p{false};
  std::thread p2p_writer([&]() {
    uint64_t ts = 8'000'000;
    uint32_t idx = 0;
    auto next_t = std::chrono::steady_clock::now();
    while (!stop_p2p.load(std::memory_order_acquire)) {
      bool la = false, ha = true, li = false, hi = false;
      uint32_t lb = 0, hb = 1'000'000;
      p2p_pub_obs.GetEncoderState(false, &la, &lb, &ha, &hb, &li, &hi);
      const bool idr = (idx % 20 == 0) || hi;
      const size_t sz =
          std::max<size_t>(120, static_cast<size_t>(hb / (30 * 8)));
      const auto nalu = BuildClosedLoopAnnexBFrame(RTC_CODEC_H264, idr, sz);
      rtc_encoded_frame_t f{};
      f.data = nalu.data();
      f.size = nalu.size();
      f.capture_ts_us = ts;
      f.is_keyframe = idr;
      f.layer = RTC_STREAM_LAYER_HIGH;
      p2p_pub->PushVideoFrame(f);
      ++idx;
      ts += 33'333;
      next_t += std::chrono::microseconds(33'333);
      std::this_thread::sleep_until(next_t);
    }
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  p2p_proxy.ResetPhaseTelemetry();
  const uint64_t p2p_dec_before = p2p_sub_obs.decoded_frames();
  uint64_t p2p_alloc_sum = 0;
  for (int i = 0; i < 24; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    p2p_alloc_sum += p2p_pub_obs.TotalAllocatedKbps(false);
  }
  const uint32_t p2p_lossy_alloc_kbps = static_cast<uint32_t>(p2p_alloc_sum / 24);
  const auto p2p_lossy_tel = p2p_proxy.SnapshotPhaseTelemetry();
  const uint64_t p2p_lossy_decoded = p2p_sub_obs.decoded_frames() - p2p_dec_before;

  stop_p2p.store(true, std::memory_order_release);
  p2p_writer.join();
  p2p_pub->LeaveRoom();
  p2p_sub->LeaveRoom();
  p2p_proxy.Stop();

  // ---------------- 场景 B：IETF MoQ (BBRv2) 在 8% 随机无线丢包 + 1800 kbps 限速下的稳态表现 ----------------
  EmbeddedMoqRelayServer moq_relay("127.0.0.1");
  ASSERT_TRUE(moq_relay.Start(0));

  RealUdpBottleneckProxy moq_proxy(/*上行容量=*/1'800'000,
                                   /*下行容量=*/10'000'000,
                                   /*单向时延毫秒=*/20,
                                   /*最大队列毫秒=*/140);
  ASSERT_TRUE(moq_proxy.Start());
  moq_proxy.SetEndpointB(boost::asio::ip::udp::endpoint(
      boost::asio::ip::make_address("127.0.0.1"), moq_relay.udp_port()));

  EngineConfig moq_sub_cfg;
  moq_sub_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
  moq_sub_cfg.signaling_or_moq_url =
      "moq://127.0.0.1:" + std::to_string(moq_relay.udp_port());
  moq_sub_cfg.zero_playout_delay = true;

  ClosedLoopCcObserver moq_sub_obs;
  auto moq_sub = RtcVideoEngine::Create(moq_sub_cfg, &moq_sub_obs);
  ASSERT_EQ(moq_sub->JoinRoom("lossy_moq", "sub"), RTC_OK);
  ASSERT_TRUE(moq_sub_obs.WaitConnected(5000));

  EngineConfig moq_pub_cfg = moq_sub_cfg;
  moq_pub_cfg.signaling_or_moq_url =
      "moq://127.0.0.1:" + std::to_string(moq_proxy.port_a());
  moq_pub_cfg.publish_codec = RTC_CODEC_H265;
  moq_pub_cfg.enable_simulcast = false;
  moq_pub_cfg.min_bitrate_bps = 150'000;
  moq_pub_cfg.start_bitrate_bps = 1'000'000;
  moq_pub_cfg.max_bitrate_bps = 3'000'000;
  moq_pub_cfg.moq_delivery_timeout_ms = 400;
  moq_pub_cfg.quic_cc_algo = RTC_QUIC_CC_BBR2;

  ClosedLoopCcObserver moq_pub_obs(/*初始高清码率=*/1'000'000);
  auto moq_pub = RtcVideoEngine::Create(moq_pub_cfg, &moq_pub_obs);
  ASSERT_EQ(moq_pub->JoinRoom("lossy_moq", "pub"), RTC_OK);
  ASSERT_TRUE(moq_pub_obs.WaitConnected(5000));

  std::string track_id;
  ASSERT_TRUE(moq_sub_obs.WaitRemoteTrack(&track_id, 5000));
  ASSERT_EQ(moq_sub->SubscribeTrack(track_id, RTC_STREAM_LAYER_HIGH), RTC_OK);
  std::this_thread::sleep_for(std::chrono::milliseconds(60));

  moq_proxy.SetUplinkRandomLossProb(0.08);

  std::atomic<bool> stop_moq{false};
  std::thread moq_writer([&]() {
    uint64_t ts = 9'000'000;
    uint32_t idx = 0;
    auto next_t = std::chrono::steady_clock::now();
    while (!stop_moq.load(std::memory_order_acquire)) {
      bool la = false, ha = true, li = false, hi = false;
      uint32_t lb = 0, hb = 1'000'000;
      moq_pub_obs.GetEncoderState(false, &la, &lb, &ha, &hb, &li, &hi);
      const bool idr = (idx % 20 == 0) || hi;
      const size_t sz =
          std::max<size_t>(120, static_cast<size_t>(hb / (30 * 8)));
      const auto nalu = BuildClosedLoopAnnexBFrame(RTC_CODEC_H265, idr, sz);
      rtc_encoded_frame_t f{};
      f.data = nalu.data();
      f.size = nalu.size();
      f.capture_ts_us = ts;
      f.is_keyframe = idr;
      f.layer = RTC_STREAM_LAYER_HIGH;
      moq_pub->PushVideoFrame(f);
      ++idx;
      ts += 33'333;
      next_t += std::chrono::microseconds(33'333);
      std::this_thread::sleep_until(next_t);
    }
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  moq_proxy.ResetPhaseTelemetry();
  const uint64_t moq_dec_before = moq_sub_obs.decoded_frames();
  uint64_t moq_alloc_sum = 0;
  for (int i = 0; i < 24; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    moq_alloc_sum += moq_pub_obs.TotalAllocatedKbps(false);
  }
  const uint32_t moq_lossy_alloc_kbps = static_cast<uint32_t>(moq_alloc_sum / 24);
  const auto moq_lossy_tel = moq_proxy.SnapshotPhaseTelemetry();
  const uint64_t moq_lossy_decoded = moq_sub_obs.decoded_frames() - moq_dec_before;

  stop_moq.store(true, std::memory_order_release);
  moq_writer.join();
  moq_sub->LeaveRoom();
  moq_pub->LeaveRoom();
  moq_proxy.Stop();
  moq_relay.Stop();

  std::cout << "\n========== [无线弱网 8% 随机丢包 + 1800 kbps 限速 + 40ms RTT 抗丢包实测对比] ==========\n"
            << std::fixed << std::setprecision(1)
            << "  [WebRTC P2P GoogCC+FlexFEC+RTX] 编码分配均值=" << p2p_lossy_alloc_kbps
            << " kbps | 网卡入站=" << p2p_lossy_tel.uplink_ingress_kbps << " kbps"
            << " | 瓶颈出站=" << p2p_lossy_tel.uplink_egress_kbps << " kbps"
            << " | 实测丢包=" << (p2p_lossy_tel.drop_ratio * 100.0) << "%"
            << " | 排队P50=" << p2p_lossy_tel.queue_delay_p50_ms << " ms"
            << " | 恢复解码帧=" << p2p_lossy_decoded << "\n"
            << "  [IETF MoQ   BBRv2+QUIC-STREAM ] 编码分配均值=" << moq_lossy_alloc_kbps
            << " kbps | 网卡入站=" << moq_lossy_tel.uplink_ingress_kbps << " kbps"
            << " | 瓶颈出站=" << moq_lossy_tel.uplink_egress_kbps << " kbps"
            << " | 实测丢包=" << (moq_lossy_tel.drop_ratio * 100.0) << "%"
            << " | 排队P50=" << moq_lossy_tel.queue_delay_p50_ms << " ms"
            << " | 恢复解码帧=" << moq_lossy_decoded << "\n"
            << "========================================================================================\n";

  // 验证在 8% 随机丢包下两者均未发生码率崩溃（保持高吞吐且总速率不超 1800k 瓶颈），并利用 FEC/RTX/QUIC ARQ 持续解码视频帧
  EXPECT_GE(p2p_lossy_alloc_kbps, 750u);
  EXPECT_LE(p2p_lossy_alloc_kbps, 1750u);
  EXPECT_GT(p2p_lossy_decoded, 35u);

  EXPECT_GE(moq_lossy_alloc_kbps, 750u);
  EXPECT_LE(moq_lossy_alloc_kbps, 1750u);
  EXPECT_GT(moq_lossy_decoded, 35u);
}

}  // namespace
}  // namespace rtc
