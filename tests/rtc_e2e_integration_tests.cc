#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <gtest/gtest.h>

#include "call/webrtc_p2p_backend.h"
#include "moq/http3_webtransport.h"
#include "moq/moq_transport.h"
#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"
#include "rtc_base/task_queue.h"
#include "rtc_video_engine.hpp"
#include "rtc_video_sdk.h"
#include "server/embedded_moq_relay.h"
#include "server/p2p_ws_signaling_server.h"
#include "server/stun_turn_relay_server.h"

namespace rtc {
namespace {

// 零媒体转发、纯 JSON 信令的 WebSocket 转发服务，用于一对一 P2P 配对测试。
class MinimalP2pWsSignalingServer {
 public:
  MinimalP2pWsSignalingServer()
      : queue_("test-ws-sig", TaskQueuePriority::kNormal),
        acceptor_(queue_.io_context()) {}

  ~MinimalP2pWsSignalingServer() { Stop(); }

  bool Start() {
    bool ok = false;
    queue_.Invoke([this, &ok]() {
      boost::system::error_code ec;
      const boost::asio::ip::tcp::endpoint ep(
          boost::asio::ip::make_address("127.0.0.1"), 0);
      acceptor_.open(ep.protocol(), ec);
      if (ec) return;
      acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
      acceptor_.bind(ep, ec);
      if (ec) return;
      acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
      if (ec) return;
      port_ = acceptor_.local_endpoint(ec).port();
      ok = !ec;
      if (ok) {
        DoAccept();
      }
    });
    return ok;
  }

  void Stop() {
    if (stopped_.exchange(true)) {
      return;
    }
    queue_.Invoke([this]() {
      boost::system::error_code ec;
      acceptor_.close(ec);
      for (auto& [id, sess] : peers_) {
        (void)id;
        sess->Close();
      }
      peers_.clear();
    });
    queue_.Shutdown();
  }

  uint16_t port() const { return port_; }

 private:
  struct ClientConn : public std::enable_shared_from_this<ClientConn> {
    MinimalP2pWsSignalingServer* srv = nullptr;
    boost::beast::websocket::stream<boost::asio::ip::tcp::socket> ws;
    boost::beast::flat_buffer rx_buf;
    std::string room_id;
    std::string peer_id;

    ClientConn(MinimalP2pWsSignalingServer* s,
               boost::asio::ip::tcp::socket sock)
        : srv(s), ws(std::move(sock)) {}

    void Start() {
      auto self = shared_from_this();
      ws.async_accept([self](boost::system::error_code ec) {
        if (!ec) {
          self->DoRead();
        }
      });
    }

    void Send(const std::string& text) {
      boost::system::error_code ec;
      ws.text(true);
      ws.write(boost::asio::buffer(text), ec);
    }

    void Close() {
      boost::system::error_code ec;
      ws.next_layer().close(ec);
    }

    void DoRead() {
      auto self = shared_from_this();
      ws.async_read(rx_buf, [self](boost::system::error_code ec, size_t /*n*/) {
        if (ec) {
          return;
        }
        const std::string text = boost::beast::buffers_to_string(self->rx_buf.data());
        self->rx_buf.consume(self->rx_buf.size());
        self->srv->OnMessage(self, text);
        self->DoRead();
      });
    }
  };

  void DoAccept() {
    acceptor_.async_accept(
        [this](boost::system::error_code ec, boost::asio::ip::tcp::socket sock) {
          if (ec) {
            return;
          }
          std::make_shared<ClientConn>(this, std::move(sock))->Start();
          DoAccept();
        });
  }

  void OnMessage(const std::shared_ptr<ClientConn>& sender,
                 const std::string& raw) {
    const auto msg = JsonObject::Parse(raw);
    if (!msg.has_value()) {
      return;
    }
    const std::string type = msg->GetString("type");
    if (type == "join") {
      sender->room_id = msg->GetString("room_id");
      sender->peer_id = msg->GetString("peer_id");
      peers_[sender->peer_id] = sender;

      for (const auto& [other_id, other] : peers_) {
        if (other_id == sender->peer_id || other->room_id != sender->room_id) {
          continue;
        }
        // 房间内已有对端作为发起方向新加入的对端发起 SDP Offer。
        JsonObject notify_existing;
        notify_existing.SetString("type", "peer_joined");
        notify_existing.SetString("peer_id", sender->peer_id);
        notify_existing.SetUint32("initiator", 1);
        other->Send(notify_existing.Serialize());

        JsonObject notify_new;
        notify_new.SetString("type", "peer_joined");
        notify_new.SetString("peer_id", other->peer_id);
        notify_new.SetUint32("initiator", 0);
        sender->Send(notify_new.Serialize());
      }
      return;
    }

    // 将 offer / answer / candidate 信令转发给同一房间内的对端。
    for (const auto& [other_id, other] : peers_) {
      if (other_id != sender->peer_id && other->room_id == sender->room_id) {
        other->Send(raw);
      }
    }
  }

  TaskQueueBoost queue_;
  boost::asio::ip::tcp::acceptor acceptor_;
  std::map<std::string, std::shared_ptr<ClientConn>> peers_;
  uint16_t port_ = 0;
  std::atomic<bool> stopped_{false};
};

class TestPeerObserver final : public IRtcEventObserver {
 public:
  void OnEncoderBitrateAllocation(rtc_stream_layer_e layer,
                                  bool layer_active,
                                  uint32_t target_bitrate_bps,
                                  uint32_t /*target_fps*/) override {
    std::lock_guard<std::mutex> lk(mu_);
    ++bitrate_callbacks_;
    last_target_bps_[layer] = layer_active ? target_bitrate_bps : 0;
    cv_.notify_all();
  }

  void OnEncoderForceIdr(rtc_stream_layer_e /*layer*/) override {
    std::lock_guard<std::mutex> lk(mu_);
    ++force_idr_requests_;
    cv_.notify_all();
  }

  void OnRemoteTrackPublished(const std::string& /*peer_id*/,
                              const std::string& track_id,
                              rtc_video_codec_e /*codec*/) override {
    std::lock_guard<std::mutex> lk(mu_);
    discovered_tracks_.push_back(track_id);
    cv_.notify_all();
  }

  void OnRemoteTrackUnpublished(const std::string& /*peer_id*/,
                                const std::string& /*track_id*/) override {}

  void OnRemoteEncodedFrame(const std::string& /*peer_id*/,
                            const std::string& /*track_id*/,
                            const rtc_encoded_frame_t& frame) override {
    std::lock_guard<std::mutex> lk(mu_);
    ++decoded_frames_;
    last_received_size_ = frame.size;
    cv_.notify_all();
  }

  void OnConnectionState(rtc_connection_state_e state,
                         int /*reason_code*/) override {
    std::lock_guard<std::mutex> lk(mu_);
    conn_state_ = state;
    cv_.notify_all();
  }

  void OnLocalIceCandidate(const std::string& /*sdp_mid*/,
                           int /*sdp_mline_index*/,
                           const std::string& candidate) override {
    std::lock_guard<std::mutex> lk(mu_);
    local_candidates_.push_back(candidate);
    cv_.notify_all();
  }

  void OnDataChannelMessage(const std::string& /*peer_id*/,
                            int /*channel_id*/,
                            bool /*is_binary*/,
                            const uint8_t* data,
                            size_t size) override {
    std::lock_guard<std::mutex> lk(mu_);
    dc_messages_.emplace_back(reinterpret_cast<const char*>(data), size);
    cv_.notify_all();
  }

  bool WaitForDataMessages(size_t min_count, int timeout_ms = 3000) {
    std::unique_lock<std::mutex> lk(mu_);
    return cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms), [this, min_count]() {
      return dc_messages_.size() >= min_count;
    });
  }

  bool WaitConnected(int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lk(mu_);
    return cv_.wait_for(
        lk, std::chrono::milliseconds(timeout_ms),
        [this]() { return conn_state_ == RTC_CONN_STATE_CONNECTED; });
  }

  bool WaitForSpecificRemoteTrack(const std::string& target_track,
                                  int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lk(mu_);
    return cv_.wait_for(
        lk, std::chrono::milliseconds(timeout_ms), [this, &target_track]() {
          for (const auto& t : discovered_tracks_) {
            if (t == target_track) {
              return true;
            }
          }
          return false;
        });
  }

  bool WaitForDecodedFrames(int min_frames, int timeout_ms = 6000) {
    std::unique_lock<std::mutex> lk(mu_);
    return cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                        [this, min_frames]() {
                          return decoded_frames_ >= min_frames;
                        });
  }

  int decoded_frames() const {
    std::lock_guard<std::mutex> lk(mu_);
    return decoded_frames_;
  }

  int bitrate_callbacks() const {
    std::lock_guard<std::mutex> lk(mu_);
    return bitrate_callbacks_;
  }

 private:
  mutable std::mutex mu_;
  std::condition_variable cv_;
  rtc_connection_state_e conn_state_ = RTC_CONN_STATE_IDLE;
  std::vector<std::string> discovered_tracks_;
  std::vector<std::string> local_candidates_;
  std::vector<std::string> dc_messages_;
  int decoded_frames_ = 0;
  size_t last_received_size_ = 0;
  int bitrate_callbacks_ = 0;
  uint32_t last_target_bps_[2]{0, 0};
  int force_idr_requests_ = 0;
};

std::vector<uint8_t> BuildSyntheticH264Frame(bool is_idr,
                                             size_t payload_bytes) {
  std::vector<uint8_t> out;
  if (is_idr) {
    const uint8_t sps_pps_idr[] = {
        0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xE0, 0x1F,
        0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80,
        0x00, 0x00, 0x00, 0x01, 0x65, 0x88};
    out.insert(out.end(), sps_pps_idr, sps_pps_idr + sizeof(sps_pps_idr));
  } else {
    const uint8_t p_slice[] = {0x00, 0x00, 0x00, 0x01, 0x41, 0x9A};
    out.insert(out.end(), p_slice, p_slice + sizeof(p_slice));
  }
  out.resize(out.size() + payload_bytes, 0x5A);
  return out;
}

std::vector<uint8_t> BuildSyntheticH265Frame(bool is_idr,
                                             size_t payload_bytes) {
  std::vector<uint8_t> out;
  if (is_idr) {
    const uint8_t params[] = {
        0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x60,
        0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xC1, 0x73,
        0x00, 0x00, 0x00, 0x01, 0x26, 0x01};
    out.insert(out.end(), params, params + sizeof(params));
  } else {
    const uint8_t trail[] = {0x00, 0x00, 0x00, 0x01, 0x02, 0x01};
    out.insert(out.end(), trail, trail + sizeof(trail));
  }
  out.resize(out.size() + payload_bytes, 0xA5);
  return out;
}

// 1. 无信令服务器、浏览器风格 SDP Offer/Answer 直连双向 WebRTC P2P 流媒体传输
TEST(RtcE2ETest, WebRtcPureP2pDirectBrowserSdpBidirectionalStreaming) {
  RtcVideoEngine::SetMinLogSeverity(LoggingSeverity::kInfo);
  RingBufferLogSink ring_logs(256);
  RtcVideoEngine::AddLogSink(&ring_logs, LoggingSeverity::kInfo);

  EngineConfig p2p_cfg;
  p2p_cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  p2p_cfg.publish_codec = RTC_CODEC_H264;
  p2p_cfg.enable_flexfec = true;
  p2p_cfg.zero_playout_delay = true;

  TestPeerObserver browser_obs;
  TestPeerObserver device_obs;
  auto browser_peer = RtcVideoEngine::Create(p2p_cfg, &browser_obs);
  auto device_peer = RtcVideoEngine::Create(p2p_cfg, &device_obs);

  ASSERT_EQ(browser_peer->JoinRoom("lan_p2p", "chrome_viewer"), RTC_OK);
  ASSERT_EQ(device_peer->JoinRoom("lan_p2p", "rk3588_ipc"), RTC_OK);

  // 浏览器端创建 W3C 标准 SDP Offer -> 嵌入式设备端设置远端 Offer 并生成返回 Answer
  std::string offer_sdp;
  ASSERT_EQ(browser_peer->CreateLocalOffer(&offer_sdp), RTC_OK);
  EXPECT_NE(offer_sdp.find("profile-level-id=42e01f"), std::string::npos);
  EXPECT_NE(offer_sdp.find("packetization-mode=1"), std::string::npos);

  std::string answer_sdp;
  ASSERT_EQ(device_peer->SetRemoteDescription("offer", offer_sdp, &answer_sdp),
            RTC_OK);
  EXPECT_NE(answer_sdp.find("a=setup:active"), std::string::npos);

  ASSERT_EQ(browser_peer->SetRemoteDescription("answer", answer_sdp, nullptr),
            RTC_OK);

  ASSERT_TRUE(browser_obs.WaitConnected());
  ASSERT_TRUE(device_obs.WaitConnected());

  // 通过 P2P 直连双向推流 H.264 视频帧（中间零媒体服务器转发！）
  uint64_t ts_us = 1'000'000;
  for (int i = 0; i < 18; ++i) {
    const bool is_idr = (i % 6) == 0;
    const auto h264_bytes =
        BuildSyntheticH264Frame(is_idr, is_idr ? 4800 : 1600);

    rtc_encoded_frame_t frame{};
    frame.data = h264_bytes.data();
    frame.size = h264_bytes.size();
    frame.capture_ts_us = ts_us;
    frame.is_keyframe = is_idr;
    frame.layer = RTC_STREAM_LAYER_HIGH;

    device_peer->PushVideoFrame(frame);
    browser_peer->PushVideoFrame(frame);

    ts_us += 33'333;
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
  }

  EXPECT_TRUE(browser_obs.WaitForDecodedFrames(12, 4000));
  EXPECT_TRUE(device_obs.WaitForDecodedFrames(12, 4000));
  EXPECT_GT(device_obs.bitrate_callbacks(), 0);
  EXPECT_GT(ring_logs.Size(), 5u);

  browser_peer->LeaveRoom();
  device_peer->LeaveRoom();
  RtcVideoEngine::RemoveLogSink(&ring_logs);
}

// 2. 基于 WebSocket 信令、在 10% 真实 UDP 丢包弱网下的纯 WebRTC P2P 传输
TEST(RtcE2ETest, WebRtcPureP2pViaWsSignalingUnderWeakNetworkLoss) {
  MinimalP2pWsSignalingServer ws_sig;
  ASSERT_TRUE(ws_sig.Start());
  const std::string ws_url =
      "ws://127.0.0.1:" + std::to_string(ws_sig.port());

  EngineConfig cfg;
  cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  cfg.signaling_or_moq_url = ws_url;
  cfg.publish_codec = RTC_CODEC_H265;
  cfg.enable_flexfec = true;
  cfg.zero_playout_delay = true;

  SdkTaskQueues rx_queues;
  TestPeerObserver pub_obs;
  TestPeerObserver sub_obs;

  auto pub_engine = RtcVideoEngine::Create(cfg, &pub_obs);

  // 在接收端直接使用 WebRtcP2pBackend，以便在 P2P Socket 上注入 10% 的 UDP 丢包，
  // 同时验证 NACK/RTX + FlexFEC + GoogCC 的弱网抗丢包恢复能力！
  class DirectObserverAdapter final : public ISessionBackendObserver {
   public:
    explicit DirectObserverAdapter(TestPeerObserver* obs) : obs_(obs) {}
    void OnBackendConnectionState(rtc_connection_state_e s, int r) override {
      obs_->OnConnectionState(s, r);
    }
    void OnBackendTargetTransferRate(const TargetTransferRate& rate) override {
      obs_->OnEncoderBitrateAllocation(
          RTC_STREAM_LAYER_HIGH, true,
          static_cast<uint32_t>(rate.target_rate.bps()), 30);
    }
    void OnBackendForceKeyFrame(SpatialLayer /*l*/) override {
      obs_->OnEncoderForceIdr(RTC_STREAM_LAYER_HIGH);
    }
    void OnBackendRemoteTrackPublished(const std::string& p,
                                       const std::string& t,
                                       VideoCodec c) override {
      obs_->OnRemoteTrackPublished(p, t, static_cast<rtc_video_codec_e>(c));
    }
    void OnBackendRemoteTrackUnpublished(const std::string& p,
                                         const std::string& t) override {
      obs_->OnRemoteTrackUnpublished(p, t);
    }
    void OnBackendDecodableFrame(const std::string& p,
                                 const std::string& t,
                                 EncodedVideoFrame f) override {
      rtc_encoded_frame_t cf{};
      cf.data = f.data.data();
      cf.size = f.data.size();
      cf.is_keyframe = f.dep.is_keyframe;
      obs_->OnRemoteEncodedFrame(p, t, cf);
    }
    void OnBackendStatsSnapshot(const rtc_network_stats_t& /*s*/) override {}

   private:
    TestPeerObserver* obs_;
  } rx_adapter(&sub_obs);

  WebRtcP2pBackend rx_p2p(Clock::GetRealTimeClock(), &rx_queues, cfg,
                          &rx_adapter);

  ASSERT_EQ(pub_engine->JoinRoom("uav_p2p_room", "uav_sender"), RTC_OK);
  ASSERT_EQ(rx_p2p.StartSession("uav_p2p_room", "ground_receiver"), RTC_OK);

  ASSERT_TRUE(pub_obs.WaitConnected());
  ASSERT_TRUE(sub_obs.WaitConnected());

  // 直接在 P2P 接收端的 ICE Socket 上注入 10% 的 UDP 接收丢包！
  rx_p2p.SetSimulatedRxDropRate(0.10);

  uint64_t ts_us = 2'000'000;
  for (int i = 0; i < 24; ++i) {
    const bool is_idr = (i % 8) == 0;
    const auto h265_bytes =
        BuildSyntheticH265Frame(is_idr, is_idr ? 5200 : 2000);
    rtc_encoded_frame_t frame{};
    frame.data = h265_bytes.data();
    frame.size = h265_bytes.size();
    frame.capture_ts_us = ts_us;
    frame.is_keyframe = is_idr;
    frame.layer = RTC_STREAM_LAYER_HIGH;
    pub_engine->PushVideoFrame(frame);

    ts_us += 33'333;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  const bool recovered_ok = sub_obs.WaitForDecodedFrames(12, 4000);
  RTC_LOG(kInfo) << "Pure WebRTC P2P (10% loss) summary: decoded="
                 << sub_obs.decoded_frames()
                 << " pub_bwe_cbs=" << pub_obs.bitrate_callbacks();
  EXPECT_TRUE(recovered_ok);
  EXPECT_GT(pub_obs.bitrate_callbacks(), 0);

  rx_p2p.StopSession();
  rx_queues.ShutdownAll();
  pub_engine->LeaveRoom();
  ws_sig.Stop();
}

// 3. 基于 Boost.Asio QUIC v1 承载的 IETF MoQ 一对多（1 对 2 Simulcast）中继拉流与弱网传输
TEST(RtcE2ETest, MoqAsioQuicOneToManyRelayUnderWeakNetworkLoss) {
  EmbeddedMoqRelayServer moq_relay("127.0.0.1");
  ASSERT_TRUE(moq_relay.Start(0));
  const std::string moq_url =
      "moq://127.0.0.1:" + std::to_string(moq_relay.udp_port());

  EngineConfig moq_cfg;
  moq_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
  moq_cfg.signaling_or_moq_url = moq_url;
  moq_cfg.publish_codec = RTC_CODEC_H265;
  moq_cfg.enable_simulcast = true;
  moq_cfg.zero_playout_delay = true;
  moq_cfg.moq_delivery_timeout_ms = 500;

  TestPeerObserver pub_obs;
  TestPeerObserver sub1_obs;
  TestPeerObserver sub2_obs;

  auto pub_engine = RtcVideoEngine::Create(moq_cfg, &pub_obs);
  auto sub1_engine = RtcVideoEngine::Create(moq_cfg, &sub1_obs);
  auto sub2_engine = RtcVideoEngine::Create(moq_cfg, &sub2_obs);

  ASSERT_EQ(sub1_engine->JoinRoom("drone_moq", "ground_hd"), RTC_OK);
  ASSERT_EQ(sub2_engine->JoinRoom("drone_moq", "mobile_ld"), RTC_OK);
  ASSERT_TRUE(sub1_obs.WaitConnected());
  ASSERT_TRUE(sub2_obs.WaitConnected());

  ASSERT_EQ(pub_engine->JoinRoom("drone_moq", "uav_01"), RTC_OK);
  ASSERT_TRUE(pub_obs.WaitConnected());

  ASSERT_TRUE(sub1_obs.WaitForSpecificRemoteTrack("uav_01"));
  ASSERT_TRUE(sub2_obs.WaitForSpecificRemoteTrack("uav_01"));

  ASSERT_EQ(sub1_engine->SubscribeTrack("uav_01", RTC_STREAM_LAYER_HIGH),
            RTC_OK);
  ASSERT_EQ(sub2_engine->SubscribeTrack("uav_01", RTC_STREAM_LAYER_LOW),
            RTC_OK);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  moq_relay.SetSimulatedDropRates(0.05, 0.10);

  uint64_t ts_us = 500'000;
  for (int i = 0; i < 24; ++i) {
    const bool is_idr = (i % 8) == 0;
    const auto low_nalu = BuildSyntheticH265Frame(is_idr, is_idr ? 1500 : 500);
    const auto high_nalu =
        BuildSyntheticH265Frame(is_idr, is_idr ? 5200 : 1800);

    rtc_encoded_frame_t low_f{};
    low_f.data = low_nalu.data();
    low_f.size = low_nalu.size();
    low_f.capture_ts_us = ts_us;
    low_f.is_keyframe = is_idr;
    low_f.layer = RTC_STREAM_LAYER_LOW;
    pub_engine->PushVideoFrame(low_f);

    rtc_encoded_frame_t high_f = low_f;
    high_f.data = high_nalu.data();
    high_f.size = high_nalu.size();
    high_f.layer = RTC_STREAM_LAYER_HIGH;
    pub_engine->PushVideoFrame(high_f);

    if (i == 9) {
      sub1_engine->SwitchSubscribedLayer("uav_01", RTC_STREAM_LAYER_LOW);
    }

    ts_us += 33'333;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  const bool ok_sub1 = sub1_obs.WaitForDecodedFrames(10, 4000);
  const bool ok_sub2 = sub2_obs.WaitForDecodedFrames(10, 4000);
  RTC_LOG(kInfo) << "MoQ Asio QUIC E2E summary: sub1_decoded="
                 << sub1_obs.decoded_frames()
                 << " sub2_decoded=" << sub2_obs.decoded_frames()
                 << " pub_bwe_cbs=" << pub_obs.bitrate_callbacks();

  EXPECT_TRUE(ok_sub1);
  EXPECT_TRUE(ok_sub2);
  EXPECT_GT(pub_obs.bitrate_callbacks(), 0);

  sub1_engine->LeaveRoom();
  sub2_engine->LeaveRoom();
  pub_engine->LeaveRoom();
  moq_relay.Stop();
}

// 4. 验证纯 C99 ABI 接口的 WebRTC P2P SDP 协商与 MoQ QUIC 连接能力
TEST(RtcE2ETest, PureC99AbiWebRtcP2pAndMoqConnect) {
  rtc_set_log_level(RTC_LOG_INFO);

  // 第一部分：通过纯 C99 接口完成 WebRTC P2P Offer/Answer 创建与协商
  rtc_config_t p2p_cfg{};
  p2p_cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  p2p_cfg.publish_codec = RTC_CODEC_H264;
  p2p_cfg.enable_flexfec = true;
  rtc_callbacks_t empty_cbs{};

  rtc_client_t* c_offerer = rtc_client_create(&p2p_cfg, &empty_cbs, nullptr);
  rtc_client_t* c_answerer = rtc_client_create(&p2p_cfg, &empty_cbs, nullptr);
  ASSERT_NE(c_offerer, nullptr);
  ASSERT_NE(c_answerer, nullptr);

  char offer_buf[4096]{};
  char answer_buf[4096]{};
  ASSERT_EQ(rtc_client_create_offer(c_offerer, offer_buf, sizeof(offer_buf)),
            RTC_OK);
  ASSERT_EQ(rtc_client_set_remote_description(c_answerer, "offer", offer_buf,
                                              answer_buf, sizeof(answer_buf)),
            RTC_OK);
  ASSERT_EQ(rtc_client_set_remote_description(c_offerer, "answer", answer_buf,
                                              nullptr, 0),
            RTC_OK);

  rtc_client_destroy(c_offerer);
  rtc_client_destroy(c_answerer);

  // 第二部分：通过纯 C99 接口建立基于 Boost.Asio QUIC v1 的 IETF MoQ 连接
  EmbeddedMoqRelayServer moq_relay("127.0.0.1");
  ASSERT_TRUE(moq_relay.Start(0));
  const std::string moq_url =
      "moq://127.0.0.1:" + std::to_string(moq_relay.udp_port());

  struct CConnWaiter {
    std::mutex mu;
    std::condition_variable cv;
    bool connected = false;
  } waiter;

  rtc_config_t moq_cfg{};
  moq_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
  moq_cfg.signaling_or_moq_url = moq_url.c_str();
  moq_cfg.publish_codec = RTC_CODEC_H264;
  moq_cfg.enable_simulcast = true;
  moq_cfg.moq_delivery_timeout_ms = 250;

  rtc_callbacks_t cbs{};
  cbs.on_connection_state = [](void* ud, rtc_connection_state_e st,
                               int /*reason*/) {
    auto* w = static_cast<CConnWaiter*>(ud);
    if (st == RTC_CONN_STATE_CONNECTED) {
      std::lock_guard<std::mutex> lk(w->mu);
      w->connected = true;
      w->cv.notify_all();
    }
  };

  rtc_client_t* client = rtc_client_create(&moq_cfg, &cbs, &waiter);
  ASSERT_NE(client, nullptr);
  ASSERT_EQ(rtc_client_join_room(client, "c_abi_room", "c_peer"), RTC_OK);
  {
    std::unique_lock<std::mutex> lk(waiter.mu);
    EXPECT_TRUE(waiter.cv.wait_for(lk, std::chrono::milliseconds(3000),
                                   [&waiter]() { return waiter.connected; }));
  }
  EXPECT_EQ(rtc_client_leave_room(client), RTC_OK);
  rtc_client_destroy(client);
  moq_relay.Stop();
}

// 5. 验证 WebRTC P2P 在丢包环境下音视频级 H.264 与双向 SCTP DataChannel（文本+24KB大二进制）并发互通
TEST(RtcE2ETest, WebRtcP2pVideoAndDataChannelLossyBidirectionalE2E) {
  rtc_set_log_level(RTC_LOG_INFO);

  class DcP2pObserver final : public IRtcEventObserver {
   public:
    void BindTrickle(RtcVideoEngine* peer) {
      std::lock_guard<std::mutex> lk(mu_);
      trickle_peer_ = peer;
    }
    void OnEncoderBitrateAllocation(rtc_stream_layer_e,
                                    bool,
                                    uint32_t,
                                    uint32_t) override {}
    void OnEncoderForceIdr(rtc_stream_layer_e) override {}
    void OnRemoteTrackPublished(const std::string&,
                                const std::string&,
                                rtc_video_codec_e) override {}
    void OnRemoteTrackUnpublished(const std::string&,
                                  const std::string&) override {}
    void OnRemoteEncodedFrame(const std::string&,
                              const std::string&,
                              const rtc_encoded_frame_t&) override {
      std::lock_guard<std::mutex> lk(mu_);
      ++frames_;
      cv_.notify_all();
    }
    void OnConnectionState(rtc_connection_state_e st, int) override {
      std::lock_guard<std::mutex> lk(mu_);
      if (st == RTC_CONN_STATE_CONNECTED) {
        connected_ = true;
        cv_.notify_all();
      }
    }
    void OnLocalIceCandidate(const std::string&,
                             int,
                             const std::string& cand) override {
      RtcVideoEngine* p = nullptr;
      {
        std::lock_guard<std::mutex> lk(mu_);
        p = trickle_peer_;
      }
      if (p != nullptr) {
        p->AddRemoteIceCandidate(cand);
      }
    }
    void OnDataChannelState(const std::string& /*peer_id*/,
                            int channel_id,
                            const std::string& label,
                            rtc_data_channel_state_e state) override {
      std::lock_guard<std::mutex> lk(mu_);
      if (state == RTC_DATA_CHANNEL_OPEN) {
        open_channels_[label] = channel_id;
        cv_.notify_all();
      }
    }
    void OnDataChannelMessage(const std::string& /*peer_id*/,
                              int /*channel_id*/,
                              bool is_binary,
                              const uint8_t* data,
                              size_t size) override {
      std::lock_guard<std::mutex> lk(mu_);
      if (is_binary) {
        rx_binaries_.emplace_back(data, data + size);
      } else {
        rx_texts_.emplace_back(reinterpret_cast<const char*>(data), size);
      }
      cv_.notify_all();
    }

    std::mutex mu_;
    std::condition_variable cv_;
    RtcVideoEngine* trickle_peer_ = nullptr;
    bool connected_ = false;
    int frames_ = 0;
    std::map<std::string, int> open_channels_;
    std::vector<std::string> rx_texts_;
    std::vector<std::vector<uint8_t>> rx_binaries_;
  };

  EngineConfig cfg;
  cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  cfg.publish_codec = RTC_CODEC_H264;
  cfg.enable_flexfec = true;
  cfg.enable_datachannel = true;

  DcP2pObserver obs_a;
  DcP2pObserver obs_b;
  auto eng_a = RtcVideoEngine::Create(cfg, &obs_a);
  auto eng_b = RtcVideoEngine::Create(cfg, &obs_b);
  obs_a.BindTrickle(eng_b.get());
  obs_b.BindTrickle(eng_a.get());

  // 连接前预创建可靠控制通道并预发一条启动握手消息
  DataChannelConfig dc_cfg;
  dc_cfg.label = "ptz_control";
  dc_cfg.protocol = "json";
  dc_cfg.ordered = true;
  const int ch_a = eng_a->CreateDataChannel(dc_cfg);
  ASSERT_GE(ch_a, 0);
  ASSERT_EQ(eng_a->SendTextData(ch_a, "{\"cmd\":\"pan_left\",\"deg\":15}"),
            RTC_OK);

  eng_a->JoinRoom("dc_p2p_room", "robot_a");
  eng_b->JoinRoom("dc_p2p_room", "console_b");

  std::string offer_sdp;
  std::string answer_sdp;
  ASSERT_EQ(eng_a->CreateLocalOffer(&offer_sdp), RTC_OK);
  EXPECT_NE(offer_sdp.find("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"),
            std::string::npos);
  ASSERT_EQ(eng_b->SetRemoteDescription("offer", offer_sdp, &answer_sdp),
            RTC_OK);
  EXPECT_NE(answer_sdp.find("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"),
            std::string::npos);
  ASSERT_EQ(eng_a->SetRemoteDescription("answer", answer_sdp, nullptr), RTC_OK);

  {
    std::unique_lock<std::mutex> lk(obs_b.mu_);
    ASSERT_TRUE(obs_b.cv_.wait_for(lk, std::chrono::milliseconds(4000), [&]() {
      return obs_b.open_channels_.count("ptz_control") > 0 &&
             !obs_b.rx_texts_.empty();
    }));
    EXPECT_EQ(obs_b.rx_texts_[0], "{\"cmd\":\"pan_left\",\"deg\":15}");
  }

  // 对端 B 直接复用接收到的双向通道 ID 回复 24KB 二进制地图块与 ACK 文本，同时 A 推送视频帧
  int ch_b_reply = -1;
  {
    std::lock_guard<std::mutex> lk(obs_b.mu_);
    ch_b_reply = obs_b.open_channels_["ptz_control"];
  }
  std::vector<uint8_t> map_tile(24 * 1024, 0);
  for (size_t i = 0; i < map_tile.size(); ++i) {
    map_tile[i] = static_cast<uint8_t>((i * 29 + 7) & 0xFFu);
  }
  ASSERT_EQ(eng_b->SendData(ch_b_reply, map_tile.data(), map_tile.size(), true),
            RTC_OK);
  ASSERT_EQ(eng_b->SendTextData(ch_b_reply, "{\"ack\":\"ok\"}"), RTC_OK);

  const uint8_t h264_idr[] = {0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xE0,
                              0x1F, 0x00, 0x00, 0x00, 0x01, 0x68, 0xCE,
                              0x3C, 0x80, 0x00, 0x00, 0x00, 0x01, 0x65,
                              0x88, 0x84, 0x21};
  for (int i = 0; i < 6; ++i) {
    rtc_encoded_frame_t vf{};
    vf.data = h264_idr;
    vf.size = sizeof(h264_idr);
    vf.capture_ts_us = 1'000'000 + static_cast<uint64_t>(i) * 33'333;
    vf.is_keyframe = true;
    eng_a->PushVideoFrame(vf);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  {
    std::unique_lock<std::mutex> lk(obs_a.mu_);
    ASSERT_TRUE(obs_a.cv_.wait_for(lk, std::chrono::milliseconds(4000), [&]() {
      return !obs_a.rx_binaries_.empty() && !obs_a.rx_texts_.empty();
    }));
    EXPECT_EQ(obs_a.rx_binaries_[0], map_tile);
    EXPECT_EQ(obs_a.rx_texts_[0], "{\"ack\":\"ok\"}");
  }
  {
    std::unique_lock<std::mutex> lk(obs_b.mu_);
    ASSERT_TRUE(obs_b.cv_.wait_for(lk, std::chrono::milliseconds(3000),
                                   [&]() { return obs_b.frames_ >= 3; }));
  }

  obs_a.BindTrickle(nullptr);
  obs_b.BindTrickle(nullptr);
  eng_a->LeaveRoom();
  eng_b->LeaveRoom();
}

// 6. 验证 IETF MoQ Relay 一对多广播数据通道与反向控制指令回传
TEST(RtcE2ETest, MoqRelayMultiPeerDataChannelBroadcastAndReplyE2E) {
  EmbeddedMoqRelayServer relay("127.0.0.1");
  ASSERT_TRUE(relay.Start(0));
  const std::string moq_url =
      "moq://127.0.0.1:" + std::to_string(relay.udp_port());

  class MoqDcObserver final : public IRtcEventObserver {
   public:
    void OnEncoderBitrateAllocation(rtc_stream_layer_e,
                                    bool,
                                    uint32_t,
                                    uint32_t) override {}
    void OnEncoderForceIdr(rtc_stream_layer_e) override {}
    void OnRemoteTrackPublished(const std::string&,
                                const std::string&,
                                rtc_video_codec_e) override {}
    void OnRemoteTrackUnpublished(const std::string&,
                                  const std::string&) override {}
    void OnRemoteEncodedFrame(const std::string&,
                              const std::string&,
                              const rtc_encoded_frame_t&) override {}
    void OnConnectionState(rtc_connection_state_e st, int) override {
      std::lock_guard<std::mutex> lk(mu_);
      if (st == RTC_CONN_STATE_CONNECTED) {
        connected_ = true;
        cv_.notify_all();
      }
    }
    void OnDataChannelState(const std::string& peer_id,
                            int channel_id,
                            const std::string& label,
                            rtc_data_channel_state_e state) override {
      std::lock_guard<std::mutex> lk(mu_);
      if (state == RTC_DATA_CHANNEL_OPEN) {
        label_to_cid_[label] = channel_id;
      } else if (state == RTC_DATA_CHANNEL_CLOSED) {
        ++closed_events_;
      }
      (void)peer_id;
      cv_.notify_all();
    }
    void OnDataChannelMessage(const std::string& peer_id,
                              int /*channel_id*/,
                              bool is_binary,
                              const uint8_t* data,
                              size_t size) override {
      std::lock_guard<std::mutex> lk(mu_);
      if (is_binary) {
        binaries_.emplace_back(
            peer_id, std::vector<uint8_t>(data, data + size));
      } else {
        texts_.emplace_back(
            peer_id, std::string(reinterpret_cast<const char*>(data), size));
      }
      cv_.notify_all();
    }

    std::mutex mu_;
    std::condition_variable cv_;
    bool connected_ = false;
    int closed_events_ = 0;
    std::map<std::string, int> label_to_cid_;
    std::vector<std::pair<std::string, std::string>> texts_;
    std::vector<std::pair<std::string, std::vector<uint8_t>>> binaries_;
  };

  EngineConfig cfg;
  cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
  cfg.signaling_or_moq_url = moq_url;
  cfg.enable_datachannel = true;

  MoqDcObserver drone_obs;
  MoqDcObserver viewer1_obs;
  MoqDcObserver viewer2_obs;
  auto drone = RtcVideoEngine::Create(cfg, &drone_obs);
  auto viewer1 = RtcVideoEngine::Create(cfg, &viewer1_obs);
  auto viewer2 = RtcVideoEngine::Create(cfg, &viewer2_obs);

  drone->JoinRoom("moq_dc_room", "drone_pub");
  viewer1->JoinRoom("moq_dc_room", "viewer_1");
  viewer2->JoinRoom("moq_dc_room", "viewer_2");

  auto wait_conn = [](MoqDcObserver& o) {
    std::unique_lock<std::mutex> lk(o.mu_);
    return o.cv_.wait_for(lk, std::chrono::milliseconds(4000),
                          [&]() { return o.connected_; });
  };
  ASSERT_TRUE(wait_conn(drone_obs));
  ASSERT_TRUE(wait_conn(viewer1_obs));
  ASSERT_TRUE(wait_conn(viewer2_obs));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  // 无人机创建有序遥测通道 + 无序限生存期传感器通道，向两个观众一对多广播
  DataChannelConfig tel_cfg;
  tel_cfg.label = "uav_telemetry";
  tel_cfg.ordered = true;
  const int tel_ch = drone->CreateDataChannel(tel_cfg);
  ASSERT_GE(tel_ch, 0);

  DataChannelConfig fast_cfg;
  fast_cfg.label = "imu_fast";
  fast_cfg.ordered = false;
  fast_cfg.max_packet_lifetime_ms = 120;
  const int imu_ch = drone->CreateDataChannel(fast_cfg);
  ASSERT_GE(imu_ch, 0);

  ASSERT_EQ(drone->SendTextData(tel_ch, "{\"alt_m\":128.5,\"bat\":92}"),
            RTC_OK);
  std::vector<uint8_t> imu_pkt(16 * 1024, 0xA5);
  for (size_t i = 0; i < imu_pkt.size(); ++i) {
    imu_pkt[i] = static_cast<uint8_t>((i * 17 + 3) & 0xFFu);
  }
  ASSERT_EQ(drone->SendData(imu_ch, imu_pkt.data(), imu_pkt.size(), true),
            RTC_OK);

  auto wait_broadcast = [&](MoqDcObserver& vo) {
    std::unique_lock<std::mutex> lk(vo.mu_);
    return vo.cv_.wait_for(lk, std::chrono::milliseconds(4000), [&]() {
      return !vo.texts_.empty() && !vo.binaries_.empty();
    });
  };
  ASSERT_TRUE(wait_broadcast(viewer1_obs));
  ASSERT_TRUE(wait_broadcast(viewer2_obs));
  EXPECT_EQ(viewer1_obs.texts_[0].first, "drone_pub");
  EXPECT_EQ(viewer1_obs.texts_[0].second, "{\"alt_m\":128.5,\"bat\":92}");
  EXPECT_EQ(viewer1_obs.binaries_[0].second, imu_pkt);
  EXPECT_EQ(viewer2_obs.texts_[0].second, "{\"alt_m\":128.5,\"bat\":92}");
  EXPECT_EQ(viewer2_obs.binaries_[0].second, imu_pkt);

  // viewer_1 直接在接收到的通道上发送反向返航控制指令，验证无人机与 viewer_2 同步收到且标识来源为 viewer_1
  int v1_tel_cid = -1;
  {
    std::lock_guard<std::mutex> lk(viewer1_obs.mu_);
    v1_tel_cid = viewer1_obs.label_to_cid_["uav_telemetry"];
  }
  ASSERT_GE(v1_tel_cid, 0);
  ASSERT_EQ(viewer1->SendTextData(v1_tel_cid, "{\"cmd\":\"return_to_home\"}"),
            RTC_OK);

  {
    std::unique_lock<std::mutex> lk(drone_obs.mu_);
    ASSERT_TRUE(drone_obs.cv_.wait_for(lk, std::chrono::milliseconds(4000),
                                       [&]() { return !drone_obs.texts_.empty(); }));
    EXPECT_EQ(drone_obs.texts_[0].first, "viewer_1");
    EXPECT_EQ(drone_obs.texts_[0].second, "{\"cmd\":\"return_to_home\"}");
  }

  // 关闭无人机遥测通道并校验远端收到 CLOSED 通知
  EXPECT_EQ(drone->CloseDataChannel(tel_ch), RTC_OK);
  {
    std::unique_lock<std::mutex> lk(viewer2_obs.mu_);
    EXPECT_TRUE(viewer2_obs.cv_.wait_for(
        lk, std::chrono::milliseconds(3000),
        [&]() { return viewer2_obs.closed_events_ > 0; }));
  }

  viewer1->LeaveRoom();
  viewer2->LeaveRoom();
  drone->LeaveRoom();
  relay.Stop();
}

// 7. 验证纯 C99 ABI 数据通道接口在 WebRTC P2P 与 IETF MoQ 双模式下的收发闭环
TEST(RtcE2ETest, PureC99AbiDataChannelWebRtcP2pAndMoqE2E) {
  struct CDataCtx {
    std::mutex mu;
    std::condition_variable cv;
    rtc_client_t* peer_for_trickle = nullptr;
    bool connected = false;
    int rx_cid = -1;
    std::string rx_msg;
  };

  auto fill_cbs = [](rtc_callbacks_t* cbs) {
    std::memset(cbs, 0, sizeof(*cbs));
    cbs->on_connection_state = [](void* ud, rtc_connection_state_e st, int) {
      auto* c = static_cast<CDataCtx*>(ud);
      if (st == RTC_CONN_STATE_CONNECTED) {
        std::lock_guard<std::mutex> lk(c->mu);
        c->connected = true;
        c->cv.notify_all();
      }
    };
    cbs->on_local_ice_candidate = [](void* ud, const char*, int,
                                     const char* cand) {
      auto* c = static_cast<CDataCtx*>(ud);
      rtc_client_t* p = nullptr;
      {
        std::lock_guard<std::mutex> lk(c->mu);
        p = c->peer_for_trickle;
      }
      if (p != nullptr) {
        rtc_client_add_remote_ice_candidate(p, cand);
      }
    };
    cbs->on_data_channel_state = [](void* ud, const char*, int cid, const char*,
                                    rtc_data_channel_state_e st) {
      auto* c = static_cast<CDataCtx*>(ud);
      if (st == RTC_DATA_CHANNEL_OPEN) {
        std::lock_guard<std::mutex> lk(c->mu);
        c->rx_cid = cid;
        c->cv.notify_all();
      }
    };
    cbs->on_data_channel_message = [](void* ud, const char*, int, bool,
                                      const uint8_t* data, size_t sz) {
      auto* c = static_cast<CDataCtx*>(ud);
      std::lock_guard<std::mutex> lk(c->mu);
      c->rx_msg.assign(reinterpret_cast<const char*>(data), sz);
      c->cv.notify_all();
    };
  };

  // (A) C99 WebRTC P2P DataChannel
  {
    rtc_config_t cfg{};
    cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
    cfg.publish_codec = RTC_CODEC_H264;
    rtc_callbacks_t cbs{};
    fill_cbs(&cbs);

    CDataCtx ctx_a;
    CDataCtx ctx_b;
    rtc_client_t* ca = rtc_client_create(&cfg, &cbs, &ctx_a);
    rtc_client_t* cb = rtc_client_create(&cfg, &cbs, &ctx_b);
    ctx_a.peer_for_trickle = cb;
    ctx_b.peer_for_trickle = ca;

    rtc_data_channel_init_t dc_init;
    rtc_data_channel_init_default(&dc_init, "c99_p2p_dc");
    const int cid = rtc_client_create_data_channel(ca, &dc_init);
    ASSERT_GE(cid, 0);

    const char* kMsg = "hello_from_c99_webrtc_dc";
    ASSERT_EQ(rtc_client_send_data(ca, cid,
                                   reinterpret_cast<const uint8_t*>(kMsg),
                                   std::strlen(kMsg), false),
              RTC_OK);

    char offer[4096]{};
    char answer[4096]{};
    ASSERT_EQ(rtc_client_create_offer(ca, offer, sizeof(offer)), RTC_OK);
    ASSERT_EQ(rtc_client_set_remote_description(cb, "offer", offer, answer,
                                                sizeof(answer)),
              RTC_OK);
    ASSERT_EQ(rtc_client_set_remote_description(ca, "answer", answer, nullptr,
                                                0),
              RTC_OK);

    {
      std::unique_lock<std::mutex> lk(ctx_b.mu);
      ASSERT_TRUE(ctx_b.cv.wait_for(lk, std::chrono::milliseconds(4000), [&]() {
        return ctx_b.rx_msg == kMsg;
      }));
    }
    EXPECT_EQ(rtc_client_close_data_channel(ca, cid), RTC_OK);
    ctx_a.peer_for_trickle = nullptr;
    ctx_b.peer_for_trickle = nullptr;
    rtc_client_destroy(ca);
    rtc_client_destroy(cb);
  }

  // (B) C99 IETF MoQ DataChannel
  {
    EmbeddedMoqRelayServer relay("127.0.0.1");
    ASSERT_TRUE(relay.Start(0));
    const std::string moq_url =
        "moq://127.0.0.1:" + std::to_string(relay.udp_port());

    rtc_config_t cfg{};
    cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
    cfg.signaling_or_moq_url = moq_url.c_str();
    cfg.publish_codec = RTC_CODEC_H264;
    rtc_callbacks_t cbs{};
    fill_cbs(&cbs);

    CDataCtx ctx_pub;
    CDataCtx ctx_sub;
    rtc_client_t* cpub = rtc_client_create(&cfg, &cbs, &ctx_pub);
    rtc_client_t* csub = rtc_client_create(&cfg, &cbs, &ctx_sub);
    ASSERT_EQ(rtc_client_join_room(cpub, "c99_moq_dc", "pub"), RTC_OK);
    ASSERT_EQ(rtc_client_join_room(csub, "c99_moq_dc", "sub"), RTC_OK);

    {
      std::unique_lock<std::mutex> lk(ctx_sub.mu);
      ASSERT_TRUE(ctx_sub.cv.wait_for(lk, std::chrono::milliseconds(3000),
                                      [&]() { return ctx_sub.connected; }));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    rtc_data_channel_init_t dc_init;
    rtc_data_channel_init_default(&dc_init, "c99_moq_cmd");
    const int cid = rtc_client_create_data_channel(cpub, &dc_init);
    ASSERT_GE(cid, 0);
    const char* kMoqMsg = "hello_from_c99_moq_dc";
    ASSERT_EQ(rtc_client_send_data(cpub, cid,
                                   reinterpret_cast<const uint8_t*>(kMoqMsg),
                                   std::strlen(kMoqMsg), false),
              RTC_OK);

    {
      std::unique_lock<std::mutex> lk(ctx_sub.mu);
      ASSERT_TRUE(ctx_sub.cv.wait_for(lk, std::chrono::milliseconds(3000), [&]() {
        return ctx_sub.rx_msg == kMoqMsg;
      }));
    }
    rtc_client_leave_room(csub);
    rtc_client_leave_room(cpub);
    rtc_client_destroy(csub);
    rtc_client_destroy(cpub);
    relay.Stop();
  }
}

// 8. 基于真实 UDP QUIC v1（ALPN "h3"）的 HTTP/3 请求响应与原生 WebTransport 双向流、单向流及数据报互通测试
TEST(RtcE2ETest, Http3RequestsAndRawWebTransportStreamsAndDatagrams) {
  TaskQueueBoost srv_queue("h3-wt-srv", TaskQueuePriority::kHigh);
  TaskQueueBoost cli_queue("h3-wt-cli", TaskQueuePriority::kHigh);

  struct ServerEchoVisitor : public IQuicServerVisitor {
    std::shared_ptr<QuicServerSessionHandle> active_wt;
    std::mutex mu;
    std::condition_variable cv;
    std::string rx_uni;
    std::string rx_dgram;

    void OnServerSessionConnected(
        std::shared_ptr<QuicServerSessionHandle> session) override {
      std::lock_guard<std::mutex> lk(mu);
      active_wt = std::move(session);
      cv.notify_all();
    }
    void OnServerSessionDisconnected(uint64_t /*session_id*/,
                                     int /*error_code*/) override {}
    void OnServerStreamOpened(uint64_t /*session_id*/,
                              uint64_t /*stream_id*/,
                              bool /*unidirectional*/) override {}
    void OnServerStreamData(uint64_t /*session_id*/,
                            uint64_t stream_id,
                            ArrayView<const uint8_t> data,
                            bool fin) override {
      const bool is_uni = (stream_id & 0x02u) != 0;
      std::shared_ptr<QuicServerSessionHandle> sess;
      {
        std::lock_guard<std::mutex> lk(mu);
        sess = active_wt;
        if (is_uni) {
          rx_uni.append(reinterpret_cast<const char*>(data.data()),
                        data.size());
          if (fin && sess) {
            const uint64_t s_uni = sess->OpenUnidirectionalStream(8, 100);
            const std::string reply = "srv_uni:" + rx_uni;
            sess->WriteStream(
                s_uni,
                MakeArrayView(reinterpret_cast<const uint8_t*>(reply.data()),
                              reply.size()),
                true);
          }
          cv.notify_all();
          return;
        }
      }
      if (sess && (!data.empty() || fin)) {
        sess->WriteStream(stream_id, data, fin);
      }
    }
    void OnServerStreamReset(uint64_t /*session_id*/,
                             uint64_t /*stream_id*/,
                             uint64_t /*app_error_code*/) override {}
    void OnServerDatagramReceived(uint64_t /*session_id*/,
                                  ArrayView<const uint8_t> data) override {
      std::shared_ptr<QuicServerSessionHandle> sess;
      {
        std::lock_guard<std::mutex> lk(mu);
        rx_dgram.assign(reinterpret_cast<const char*>(data.data()),
                        data.size());
        sess = active_wt;
        cv.notify_all();
      }
      if (sess) {
        const std::string echo = "dgram_ack:" + std::string(
            reinterpret_cast<const char*>(data.data()), data.size());
        sess->SendDatagram(MakeArrayView(
            reinterpret_cast<const uint8_t*>(echo.data()), echo.size()));
      }
    }
  } srv_visitor;

  AsioHttp3WebTransportServer h3_server(
      Clock::GetRealTimeClock(), &srv_queue, &srv_visitor, "127.0.0.1",
      {"moqt-17", "wt-echo"}, [](const Http3Request& req) {
        Http3Response resp;
        resp.status = 200;
        resp.headers.push_back({"content-type", "text/plain"});
        const std::string text = req.method + ":" + req.path + ":" +
                                 std::string(req.body.begin(), req.body.end());
        resp.body.assign(text.begin(), text.end());
        return resp;
      });
  ASSERT_TRUE(h3_server.Start(0));

  struct ClientWtObserver : public IMoqQuicEngineObserver {
    std::mutex mu;
    std::condition_variable cv;
    bool connected = false;
    std::string bidi_echo;
    std::string srv_uni_msg;
    std::string dgram_reply;

    void OnQuicConnected() override {
      std::lock_guard<std::mutex> lk(mu);
      connected = true;
      cv.notify_all();
    }
    void OnQuicDisconnected(int /*error_code*/) override {}
    void OnStreamOpened(uint64_t /*stream_id*/,
                        bool /*unidirectional*/) override {}
    void OnStreamData(uint64_t stream_id,
                      ArrayView<const uint8_t> data,
                      bool /*fin*/) override {
      std::lock_guard<std::mutex> lk(mu);
      const bool is_uni = (stream_id & 0x02u) != 0;
      if (is_uni) {
        srv_uni_msg.append(reinterpret_cast<const char*>(data.data()),
                           data.size());
      } else {
        bidi_echo.append(reinterpret_cast<const char*>(data.data()),
                         data.size());
      }
      cv.notify_all();
    }
    void OnStreamReset(uint64_t /*stream_id*/,
                       uint64_t /*app_error_code*/) override {}
    void OnDatagramReceived(ArrayView<const uint8_t> data) override {
      std::lock_guard<std::mutex> lk(mu);
      dgram_reply.assign(reinterpret_cast<const char*>(data.data()),
                         data.size());
      cv.notify_all();
    }
  } cli_obs;

  const std::string authority =
      "127.0.0.1:" + std::to_string(h3_server.local_port());
  auto raw_cli = std::make_shared<AsioQuicClientEngine>(
      Clock::GetRealTimeClock(), &cli_queue);
  auto wt_cli = std::make_shared<WebTransportClientEngine>(
      raw_cli, authority, "/wt", std::vector<std::string>{"moqt-17"});
  wt_cli->SetObserver(&cli_obs);
  ASSERT_EQ(wt_cli->Connect("127.0.0.1", h3_server.local_port(), "h3"), 0);

  {
    std::unique_lock<std::mutex> lk(cli_obs.mu);
    ASSERT_TRUE(cli_obs.cv.wait_for(lk, std::chrono::milliseconds(3000),
                                    [&]() { return cli_obs.connected; }));
  }
  EXPECT_EQ(wt_cli->negotiated_wt_protocol(), "moqt-17");

  // 1) 在同一条 HTTP/3 连接上并发测试 POST 请求与 QPACK 响应。
  std::mutex h3_mu;
  std::condition_variable h3_cv;
  bool h3_done = false;
  Http3Response got_h3_resp;
  Http3Request post_req;
  post_req.method = "POST";
  post_req.path = "/api/echo";
  const std::string req_payload = "hello_http3";
  post_req.body.assign(req_payload.begin(), req_payload.end());
  ASSERT_EQ(wt_cli->SendHttp3Request(post_req,
                                     [&](const Http3Response& r) {
                                       std::lock_guard<std::mutex> lk(h3_mu);
                                       got_h3_resp = r;
                                       h3_done = true;
                                       h3_cv.notify_all();
                                     }),
            RTC_OK);
  {
    std::unique_lock<std::mutex> lk(h3_mu);
    ASSERT_TRUE(h3_cv.wait_for(lk, std::chrono::milliseconds(3000),
                               [&]() { return h3_done; }));
  }
  EXPECT_EQ(got_h3_resp.status, 200);
  EXPECT_EQ(std::string(got_h3_resp.body.begin(), got_h3_resp.body.end()),
            "POST:/api/echo:hello_http3");

  // 2) 测试 WebTransport 0x41 双向流、0x54 单向流与 RFC 9297 数据报双向往返。
  const uint64_t bidi_sid = wt_cli->OpenBidirectionalStream();
  const std::string bidi_msg = "wt_bidi_ping";
  wt_cli->WriteStream(
      bidi_sid,
      MakeArrayView(reinterpret_cast<const uint8_t*>(bidi_msg.data()),
                    bidi_msg.size()),
      true);

  const uint64_t uni_sid = wt_cli->OpenUnidirectionalStream(8, 100);
  const std::string uni_msg = "wt_uni_push";
  wt_cli->WriteStream(
      uni_sid,
      MakeArrayView(reinterpret_cast<const uint8_t*>(uni_msg.data()),
                    uni_msg.size()),
      true);

  const std::string dg_msg = "wt_fast_datagram";
  ASSERT_EQ(wt_cli->SendDatagram(MakeArrayView(
                reinterpret_cast<const uint8_t*>(dg_msg.data()), dg_msg.size())),
            RTC_OK);

  {
    std::unique_lock<std::mutex> lk(cli_obs.mu);
    ASSERT_TRUE(cli_obs.cv.wait_for(lk, std::chrono::milliseconds(3000), [&]() {
      return cli_obs.bidi_echo == bidi_msg &&
             cli_obs.srv_uni_msg == "srv_uni:wt_uni_push" &&
             cli_obs.dgram_reply == "dgram_ack:wt_fast_datagram";
    }));
  }

  wt_cli->Close(0);
  h3_server.Stop();
  cli_queue.Shutdown();
  srv_queue.Shutdown();
}

// 9. 验证基于 WebTransport over HTTP/3（https://）与原生 QUIC（moqt://）同端口混联互通的 MOQT draft-17 视频与数据通道
TEST(RtcE2ETest, MoqDraft17OverWebTransportAndCrossProtocolInterop) {
  EmbeddedMoqRelayServer moq_relay("127.0.0.1");
  ASSERT_TRUE(moq_relay.Start(0));

  const std::string wt_url =
      "https://127.0.0.1:" + std::to_string(moq_relay.udp_port()) + "/moq";
  const std::string native_moqt_url =
      "moqt://127.0.0.1:" + std::to_string(moq_relay.udp_port()) + "/moq";

  EngineConfig wt_pub_cfg;
  wt_pub_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT;
  wt_pub_cfg.signaling_or_moq_url = wt_url;
  wt_pub_cfg.publish_codec = RTC_CODEC_H265;
  wt_pub_cfg.enable_simulcast = true;
  wt_pub_cfg.zero_playout_delay = true;
  wt_pub_cfg.enable_datachannel = true;

  EngineConfig wt_sub_cfg = wt_pub_cfg;
  wt_sub_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;  // 通过 https:// 自动选择 WebTransport

  EngineConfig quic_sub_cfg = wt_pub_cfg;
  quic_sub_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
  quic_sub_cfg.signaling_or_moq_url = native_moqt_url;  // 通过 moqt:// 选择原生 QUIC ALPN "moqt-17"

  TestPeerObserver pub_obs;
  TestPeerObserver wt_sub_obs;
  TestPeerObserver quic_sub_obs;

  auto pub_eng = RtcVideoEngine::Create(wt_pub_cfg, &pub_obs);
  auto wt_sub_eng = RtcVideoEngine::Create(wt_sub_cfg, &wt_sub_obs);
  auto quic_sub_eng = RtcVideoEngine::Create(quic_sub_cfg, &quic_sub_obs);

  ASSERT_EQ(wt_sub_eng->JoinRoom("hybrid_room", "browser_wt_sub"), RTC_OK);
  ASSERT_EQ(quic_sub_eng->JoinRoom("hybrid_room", "native_quic_sub"), RTC_OK);
  ASSERT_TRUE(wt_sub_obs.WaitConnected());
  ASSERT_TRUE(quic_sub_obs.WaitConnected());

  ASSERT_EQ(pub_eng->JoinRoom("hybrid_room", "wt_cam_pub"), RTC_OK);
  ASSERT_TRUE(pub_obs.WaitConnected());

  // 校验 WebTransport 订阅端与原生 QUIC 订阅端均通过 SUBSCRIBE_NAMESPACE + NAMESPACE 发现该发布端。
  ASSERT_TRUE(wt_sub_obs.WaitForSpecificRemoteTrack("wt_cam_pub"));
  ASSERT_TRUE(quic_sub_obs.WaitForSpecificRemoteTrack("wt_cam_pub"));

  ASSERT_EQ(wt_sub_eng->SubscribeTrack("wt_cam_pub", RTC_STREAM_LAYER_HIGH),
            RTC_OK);
  ASSERT_EQ(quic_sub_eng->SubscribeTrack("wt_cam_pub", RTC_STREAM_LAYER_LOW),
            RTC_OK);
  std::this_thread::sleep_for(std::chrono::milliseconds(60));

  // 测试可靠流数据通道与零重传 OBJECT_DATAGRAM 数据通道跨 WebTransport <-> 原生 QUIC 广播。
  DataChannelConfig rel_dc;
  rel_dc.label = "cmd_reliable";
  rel_dc.ordered = true;
  const int rel_ch = pub_eng->CreateDataChannel(rel_dc);
  ASSERT_GE(rel_ch, 0);

  DataChannelConfig dgram_dc;
  dgram_dc.label = "pose_datagram";
  dgram_dc.ordered = false;
  dgram_dc.max_retransmits = 0;
  const int dg_ch = pub_eng->CreateDataChannel(dgram_dc);
  ASSERT_GE(dg_ch, 0);

  ASSERT_EQ(pub_eng->SendTextData(rel_ch, "reliable_over_wt"), RTC_OK);
  ASSERT_EQ(pub_eng->SendTextData(dg_ch, "datagram_over_wt"), RTC_OK);

  uint64_t ts_us = 100'000;
  for (int i = 0; i < 16; ++i) {
    const bool is_idr = (i % 8) == 0;
    const auto low_nalu = BuildSyntheticH265Frame(is_idr, is_idr ? 1200 : 450);
    const auto high_nalu = BuildSyntheticH265Frame(is_idr, is_idr ? 4000 : 1400);

    rtc_encoded_frame_t low_f{};
    low_f.data = low_nalu.data();
    low_f.size = low_nalu.size();
    low_f.capture_ts_us = ts_us;
    low_f.is_keyframe = is_idr;
    low_f.layer = RTC_STREAM_LAYER_LOW;
    pub_eng->PushVideoFrame(low_f);

    rtc_encoded_frame_t high_f = low_f;
    high_f.data = high_nalu.data();
    high_f.size = high_nalu.size();
    high_f.layer = RTC_STREAM_LAYER_HIGH;
    pub_eng->PushVideoFrame(high_f);

    if (i == 7) {
      wt_sub_eng->SwitchSubscribedLayer("wt_cam_pub", RTC_STREAM_LAYER_LOW);
    }
    ts_us += 33'333;
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
  }

  EXPECT_TRUE(wt_sub_obs.WaitForDecodedFrames(10, 4000));
  EXPECT_TRUE(quic_sub_obs.WaitForDecodedFrames(10, 4000));
  EXPECT_TRUE(wt_sub_obs.WaitForDataMessages(2, 3000));
  EXPECT_TRUE(quic_sub_obs.WaitForDataMessages(2, 3000));

  pub_eng->LeaveRoom();
  wt_sub_eng->LeaveRoom();
  quic_sub_eng->LeaveRoom();
  moq_relay.Stop();
}

TEST(RtcE2ETest, WebRtcStunDomainNameResolutionSrflxInW3cSdpOffer) {
  RtcVideoEngine::SetMinLogSeverity(LoggingSeverity::kInfo);

  // 在 127.0.0.1 随机端口运行真实 STUN Binding 响应器，通过域名 `stun:localhost:<port>` 配置 WebRTC 引擎。
  boost::asio::io_context stun_ioc;
  boost::asio::ip::udp::socket stun_sock(
      stun_ioc,
      boost::asio::ip::udp::endpoint(
          boost::asio::ip::make_address_v4("127.0.0.1"), 0));
  const uint16_t stun_port = stun_sock.local_endpoint().port();
  std::atomic<bool> stop_stun{false};
  std::thread stun_thread([&]() {
    std::array<uint8_t, 512> rx{};
    boost::asio::ip::udp::endpoint cli_ep;
    stun_sock.non_blocking(true);
    while (!stop_stun.load(std::memory_order_acquire)) {
      boost::system::error_code ec;
      const size_t n =
          stun_sock.receive_from(boost::asio::buffer(rx), cli_ep, 0, ec);
      if (!ec && n >= 20) {
        auto req = StunMessage::Parse(MakeArrayView(rx.data(), n), "");
        if (req.has_value() &&
            req->type() == StunMessageType::kBindingRequest) {
          StunMessage resp(StunMessageType::kBindingResponse);
          resp.set_transaction_id(req->transaction_id());
          resp.set_xor_mapped_address(boost::asio::ip::udp::endpoint(
              boost::asio::ip::make_address_v4("203.0.113.99"), 51000));
          const auto wire = resp.Serialize("", true);
          stun_sock.send_to(boost::asio::buffer(wire), cli_ep, 0, ec);
        }
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
      }
    }
  });

  TestPeerObserver offerer_obs;
  TestPeerObserver answerer_obs;

  EngineConfig offer_cfg;
  offer_cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  offer_cfg.publish_codec = RTC_CODEC_H265;
  offer_cfg.ice_servers.push_back(
      {"stun:localhost:" + std::to_string(stun_port), "", ""});

  EngineConfig ans_cfg;
  ans_cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  ans_cfg.publish_codec = RTC_CODEC_H265;

  auto offerer = RtcVideoEngine::Create(offer_cfg, &offerer_obs);
  auto answerer = RtcVideoEngine::Create(ans_cfg, &answerer_obs);

  offerer->JoinRoom("stun_dns_room", "peer_a");
  answerer->JoinRoom("stun_dns_room", "peer_b");

  std::string offer_sdp;
  ASSERT_EQ(offerer->CreateLocalOffer(&offer_sdp), RTC_OK);
  EXPECT_NE(offer_sdp.find("203.0.113.99 51000 typ srflx"), std::string::npos);

  std::string answer_sdp;
  ASSERT_EQ(answerer->SetRemoteDescription("offer", offer_sdp, &answer_sdp),
            RTC_OK);
  ASSERT_EQ(offerer->SetRemoteDescription("answer", answer_sdp, nullptr),
            RTC_OK);

  ASSERT_TRUE(offerer_obs.WaitConnected(4000));
  ASSERT_TRUE(answerer_obs.WaitConnected(4000));

  for (int i = 0; i < 12; ++i) {
    const auto nalu = BuildSyntheticH265Frame(i == 0, 1200);
    rtc_encoded_frame_t f{};
    f.data = nalu.data();
    f.size = nalu.size();
    f.capture_ts_us = 1'000'000ULL + static_cast<uint64_t>(i) * 33'333ULL;
    f.is_keyframe = (i == 0);
    f.layer = RTC_STREAM_LAYER_HIGH;
    offerer->PushVideoFrame(f);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
  }
  EXPECT_TRUE(answerer_obs.WaitForDecodedFrames(8, 3000));

  offerer->LeaveRoom();
  answerer->LeaveRoom();
  stop_stun.store(true, std::memory_order_release);
  stun_thread.join();
}

// 辅助函数：剔除 SDP 中除 `typ relay` 以外的所有 host/srflx 候选，100% 强制走 TURN 中继转发。
std::string KeepOnlyRelayCandidatesInSdp(const std::string& sdp) {
  std::istringstream iss(sdp);
  std::string line;
  std::string out;
  while (std::getline(iss, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.rfind("a=candidate:", 0) == 0 &&
        line.find(" typ relay") == std::string::npos) {
      continue;
    }
    out += line + "\r\n";
  }
  return out;
}

bool ReceiveUdpWithTimeout(boost::asio::ip::udp::socket* sock,
                           std::vector<uint8_t>* out_pkt,
                           int timeout_ms = 1000) {
  sock->non_blocking(true);
  std::array<uint8_t, 2048> buf{};
  boost::asio::ip::udp::endpoint from;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    boost::system::error_code ec;
    const size_t n = sock->receive_from(boost::asio::buffer(buf), from, 0, ec);
    if (!ec && n > 0) {
      out_pkt->assign(buf.data(), buf.data() + n);
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return false;
}

// 11. 验证类 coturn STUN/TURN 服务的长期凭证鉴权、TURN REST API、对端权限隔离、ChannelData 与发卡弯直通
TEST(RtcE2ETest, StunTurnRelayServerAuthRestApiChannelDataAndHairpinning) {
  StunTurnServerConfig cfg;
  cfg.bind_ip = "127.0.0.1";
  cfg.relay_bind_ip = "127.0.0.1";
  cfg.port = 0;
  cfg.external_ip = "198.51.100.200";
  cfg.realm = "rtc.prod";
  cfg.static_users["alice"] = "alice_pwd";
  cfg.rest_api_secret = "coturn_shared_secret_2026";
  cfg.min_relay_port = 52000;
  cfg.max_relay_port = 52100;

  StunTurnRelayServer turn_srv(cfg);
  ASSERT_TRUE(turn_srv.Start());
  ASSERT_GT(turn_srv.port(), 0);

  const boost::asio::ip::udp::endpoint srv_ep(
      boost::asio::ip::make_address_v4("127.0.0.1"), turn_srv.port());

  boost::asio::io_context ioc;
  boost::asio::ip::udp::socket sock_a(
      ioc, boost::asio::ip::udp::endpoint(
               boost::asio::ip::make_address_v4("127.0.0.1"), 0));
  boost::asio::ip::udp::socket sock_b(
      ioc, boost::asio::ip::udp::endpoint(
               boost::asio::ip::make_address_v4("127.0.0.1"), 0));

  // 1) 无状态 STUN Binding 请求校验。
  StunMessage bind_req(StunMessageType::kBindingRequest);
  const auto bind_wire = bind_req.Serialize("", true);
  sock_a.send_to(boost::asio::buffer(bind_wire), srv_ep);
  std::vector<uint8_t> rx_pkt;
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_a, &rx_pkt));
  auto bind_resp = StunMessage::Parse(rx_pkt, "");
  ASSERT_TRUE(bind_resp.has_value());
  EXPECT_EQ(bind_resp->type(), StunMessageType::kBindingResponse);
  ASSERT_TRUE(bind_resp->xor_mapped_address().has_value());
  EXPECT_EQ(bind_resp->xor_mapped_address()->port(),
            sock_a.local_endpoint().port());

  // 2) 未鉴权 Allocate 请求必须返回 401 Unauthorized 质询并携带 REALM 与 NONCE。
  StunMessage unauth_alloc(StunMessageType::kAllocateRequest);
  unauth_alloc.set_requested_transport(17);
  sock_a.send_to(boost::asio::buffer(unauth_alloc.Serialize("", true)), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_a, &rx_pkt));
  auto challenge = StunMessage::Parse(rx_pkt, "");
  ASSERT_TRUE(challenge.has_value());
  EXPECT_EQ(challenge->type(), StunMessageType::kAllocateErrorResponse);
  ASSERT_TRUE(challenge->error_code().has_value());
  EXPECT_EQ(*challenge->error_code(), 401);
  EXPECT_EQ(challenge->realm().value_or(""), "rtc.prod");
  ASSERT_TRUE(challenge->nonce().has_value());
  ASSERT_FALSE(challenge->nonce()->empty());
  const std::string nonce_a = *challenge->nonce();

  // 3) 错误密码必须拒绝并累计 auth_failures。
  StunMessage bad_alloc(StunMessageType::kAllocateRequest);
  bad_alloc.set_requested_transport(17);
  bad_alloc.set_username("alice");
  bad_alloc.set_realm("rtc.prod");
  bad_alloc.set_nonce(nonce_a);
  const std::string bad_key =
      StunMessage::ComputeLongTermKey("alice", "rtc.prod", "wrong");
  sock_a.send_to(boost::asio::buffer(bad_alloc.Serialize(bad_key, true)),
                 srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_a, &rx_pkt));
  auto bad_resp = StunMessage::Parse(rx_pkt, "");
  ASSERT_TRUE(bad_resp.has_value());
  EXPECT_EQ(*bad_resp->error_code(), 401);

  // 4) Alice 使用静态长期凭证成功分配中继端口（映射为 external_ip 198.51.100.200）。
  const std::string key_a =
      StunMessage::ComputeLongTermKey("alice", "rtc.prod", "alice_pwd");
  StunMessage alloc_a(StunMessageType::kAllocateRequest);
  alloc_a.set_requested_transport(17);
  alloc_a.set_username("alice");
  alloc_a.set_realm("rtc.prod");
  alloc_a.set_nonce(nonce_a);
  sock_a.send_to(boost::asio::buffer(alloc_a.Serialize(key_a, true)), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_a, &rx_pkt));
  auto alloc_a_resp = StunMessage::Parse(rx_pkt, key_a);
  ASSERT_TRUE(alloc_a_resp.has_value());
  EXPECT_EQ(alloc_a_resp->type(), StunMessageType::kAllocateResponse);
  ASSERT_TRUE(alloc_a_resp->xor_relayed_address().has_value());
  const auto relay_ep_a = *alloc_a_resp->xor_relayed_address();
  EXPECT_EQ(relay_ep_a.address().to_string(), "198.51.100.200");
  EXPECT_GE(relay_ep_a.port(), 52000);
  EXPECT_LE(relay_ep_a.port(), 52100);

  // 5) Bob 先验证过期 TURN REST API 凭证被拒，随后使用有效动态 HMAC-SHA1 凭证成功分配。
  sock_b.send_to(boost::asio::buffer(unauth_alloc.Serialize("", true)), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_b, &rx_pkt));
  auto chal_b = StunMessage::Parse(rx_pkt, "");
  ASSERT_TRUE(chal_b.has_value());
  ASSERT_TRUE(chal_b->nonce().has_value());
  const std::string nonce_b = *chal_b->nonce();

  const int64_t now_unix = static_cast<int64_t>(std::time(nullptr));
  const std::string expired_user = std::to_string(now_unix - 120) + ":bob";
  const std::string expired_pass = StunTurnRelayServer::ComputeRestApiPassword(
      cfg.rest_api_secret, expired_user);
  const std::string expired_key = StunMessage::ComputeLongTermKey(
      expired_user, "rtc.prod", expired_pass);
  StunMessage exp_alloc(StunMessageType::kAllocateRequest);
  exp_alloc.set_requested_transport(17);
  exp_alloc.set_username(expired_user);
  exp_alloc.set_realm("rtc.prod");
  exp_alloc.set_nonce(nonce_b);
  sock_b.send_to(boost::asio::buffer(exp_alloc.Serialize(expired_key, true)),
                 srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_b, &rx_pkt));
  auto exp_resp = StunMessage::Parse(rx_pkt, "");
  ASSERT_TRUE(exp_resp.has_value());
  EXPECT_EQ(*exp_resp->error_code(), 401);

  const std::string valid_rest_user = std::to_string(now_unix + 600) + ":bob";
  const std::string valid_rest_pass =
      StunTurnRelayServer::ComputeRestApiPassword(cfg.rest_api_secret,
                                                  valid_rest_user);
  const std::string key_b = StunMessage::ComputeLongTermKey(
      valid_rest_user, "rtc.prod", valid_rest_pass);
  StunMessage alloc_b(StunMessageType::kAllocateRequest);
  alloc_b.set_requested_transport(17);
  alloc_b.set_username(valid_rest_user);
  alloc_b.set_realm("rtc.prod");
  alloc_b.set_nonce(nonce_b);
  sock_b.send_to(boost::asio::buffer(alloc_b.Serialize(key_b, true)), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_b, &rx_pkt));
  auto alloc_b_resp = StunMessage::Parse(rx_pkt, key_b);
  ASSERT_TRUE(alloc_b_resp.has_value());
  EXPECT_EQ(alloc_b_resp->type(), StunMessageType::kAllocateResponse);
  ASSERT_TRUE(alloc_b_resp->xor_relayed_address().has_value());
  const auto relay_ep_b = *alloc_b_resp->xor_relayed_address();
  EXPECT_NE(relay_ep_a.port(), relay_ep_b.port());

  // 6) 验证对端权限校验与同机发卡弯（Hairpinning）：Bob 未授权前必须丢弃，授权后收到 Data Indication。
  StunMessage perm_a(StunMessageType::kCreatePermissionRequest);
  perm_a.set_username("alice");
  perm_a.set_realm("rtc.prod");
  perm_a.set_nonce(nonce_a);
  perm_a.add_xor_peer_address(relay_ep_b);
  sock_a.send_to(boost::asio::buffer(perm_a.Serialize(key_a, true)), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_a, &rx_pkt));
  EXPECT_EQ(StunMessage::Parse(rx_pkt, key_a)->type(),
            StunMessageType::kCreatePermissionResponse);

  const std::string ind_text = "hairpin_indication_msg";
  StunMessage send_a(StunMessageType::kSendIndication);
  send_a.set_xor_peer_address(relay_ep_b);
  send_a.set_data(MakeArrayView(
      reinterpret_cast<const uint8_t*>(ind_text.data()), ind_text.size()));
  sock_a.send_to(boost::asio::buffer(send_a.Serialize("", true)), srv_ep);
  // Bob 尚未对 198.51.100.200 开通权限，不应收到转发包。
  EXPECT_FALSE(ReceiveUdpWithTimeout(&sock_b, &rx_pkt, 60));

  StunMessage perm_b(StunMessageType::kCreatePermissionRequest);
  perm_b.set_username(valid_rest_user);
  perm_b.set_realm("rtc.prod");
  perm_b.set_nonce(nonce_b);
  perm_b.add_xor_peer_address(relay_ep_a);
  sock_b.send_to(boost::asio::buffer(perm_b.Serialize(key_b, true)), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_b, &rx_pkt));
  EXPECT_EQ(StunMessage::Parse(rx_pkt, key_b)->type(),
            StunMessageType::kCreatePermissionResponse);

  sock_a.send_to(boost::asio::buffer(send_a.Serialize("", true)), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_b, &rx_pkt));
  auto got_ind = StunMessage::Parse(rx_pkt, "");
  ASSERT_TRUE(got_ind.has_value());
  EXPECT_EQ(got_ind->type(), StunMessageType::kDataIndication);
  ASSERT_TRUE(got_ind->xor_peer_address().has_value());
  EXPECT_EQ(*got_ind->xor_peer_address(), relay_ep_a);
  ASSERT_TRUE(got_ind->data().has_value());
  EXPECT_EQ(std::string(got_ind->data()->begin(), got_ind->data()->end()),
            ind_text);

  // 7) 双方绑定不同 ChannelNumber（Alice=0x4005，Bob=0x4000），验证 4 字节 ChannelData 发卡弯互转。
  StunMessage ch_a(StunMessageType::kChannelBindRequest);
  ch_a.set_username("alice");
  ch_a.set_realm("rtc.prod");
  ch_a.set_nonce(nonce_a);
  ch_a.set_channel_number(0x4005);
  ch_a.set_xor_peer_address(relay_ep_b);
  sock_a.send_to(boost::asio::buffer(ch_a.Serialize(key_a, true)), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_a, &rx_pkt));
  EXPECT_EQ(StunMessage::Parse(rx_pkt, key_a)->type(),
            StunMessageType::kChannelBindResponse);

  StunMessage ch_b(StunMessageType::kChannelBindRequest);
  ch_b.set_username(valid_rest_user);
  ch_b.set_realm("rtc.prod");
  ch_b.set_nonce(nonce_b);
  ch_b.set_channel_number(0x4000);
  ch_b.set_xor_peer_address(relay_ep_a);
  sock_b.send_to(boost::asio::buffer(ch_b.Serialize(key_b, true)), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_b, &rx_pkt));
  EXPECT_EQ(StunMessage::Parse(rx_pkt, key_b)->type(),
            StunMessageType::kChannelBindResponse);

  const std::string fast_msg = "zero_overhead_turn_channel_data";
  const auto ch_pkt = TurnChannelDataCodec::Wrap(
      0x4000, MakeArrayView(reinterpret_cast<const uint8_t*>(fast_msg.data()),
                            fast_msg.size()));
  sock_b.send_to(boost::asio::buffer(ch_pkt), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_a, &rx_pkt));
  ASSERT_TRUE(TurnChannelDataCodec::IsChannelData(rx_pkt));
  uint16_t rx_ch = 0;
  ArrayView<const uint8_t> rx_body;
  ASSERT_TRUE(TurnChannelDataCodec::Unwrap(rx_pkt, &rx_ch, &rx_body));
  EXPECT_EQ(rx_ch, 0x4005);
  EXPECT_EQ(std::string(rx_body.begin(), rx_body.end()), fast_msg);

  // 8) 发送 LIFETIME=0 的 Refresh 主动释放 Alice 中继会话并校验运行指标快照。
  StunMessage rel_a(StunMessageType::kRefreshRequest);
  rel_a.set_username("alice");
  rel_a.set_realm("rtc.prod");
  rel_a.set_nonce(nonce_a);
  rel_a.set_lifetime(0);
  sock_a.send_to(boost::asio::buffer(rel_a.Serialize(key_a, true)), srv_ep);
  ASSERT_TRUE(ReceiveUdpWithTimeout(&sock_a, &rx_pkt));
  auto rel_resp = StunMessage::Parse(rx_pkt, key_a);
  ASSERT_TRUE(rel_resp.has_value());
  EXPECT_EQ(rel_resp->type(), StunMessageType::kRefreshResponse);
  ASSERT_TRUE(rel_resp->lifetime().has_value());
  EXPECT_EQ(*rel_resp->lifetime(), 0u);

  const StunTurnStatsSnapshot stats = turn_srv.GetStatsSnapshot();
  EXPECT_EQ(stats.stun_binding_requests, 1u);
  EXPECT_EQ(stats.total_allocations, 2u);
  EXPECT_EQ(stats.active_allocations, 1u);
  EXPECT_GE(stats.relayed_packets, 2u);
  EXPECT_GT(stats.relayed_bytes, 0u);
  // 仅计入携带凭证但校验失败（密码错误 + 过期 REST 令牌）的真实鉴权失败次数，正常首包 401 质询不误报为失败。
  EXPECT_EQ(stats.auth_failures, 2u);

  turn_srv.Stop();
}

// 12. 模拟双对称型 NAT 阻断直连（剔除全部 host/srflx 候选），验证 100% 经由 TURN 中继的 WebRTC 视频与 DataChannel 互通
TEST(RtcE2ETest, WebRtcP2pForcedSymmetricNatTurnRelayMediaAndDataChannel) {
  StunTurnServerConfig turn_cfg;
  turn_cfg.bind_ip = "127.0.0.1";
  turn_cfg.relay_bind_ip = "127.0.0.1";
  turn_cfg.port = 0;
  // 使用本机不存在的 RFC 5737 测试网段作为 external_ip，物理杜绝任何本机直连绕过 TURN 的可能！
  turn_cfg.external_ip = "198.51.100.77";
  turn_cfg.realm = "rtc.symnat";
  turn_cfg.rest_api_secret = "symnat_hmac_secret";

  StunTurnRelayServer turn_srv(turn_cfg);
  ASSERT_TRUE(turn_srv.Start());
  const std::string turn_uri = "turn:127.0.0.1:" +
                               std::to_string(turn_srv.port()) +
                               "?transport=udp";

  const int64_t exp_ts = static_cast<int64_t>(std::time(nullptr)) + 1800;
  const std::string user_a = std::to_string(exp_ts) + ":cam_a";
  const std::string pass_a = StunTurnRelayServer::ComputeRestApiPassword(
      turn_cfg.rest_api_secret, user_a);
  const std::string user_b = std::to_string(exp_ts) + ":viewer_b";
  const std::string pass_b = StunTurnRelayServer::ComputeRestApiPassword(
      turn_cfg.rest_api_secret, user_b);

  TestPeerObserver obs_a;
  TestPeerObserver obs_b;

  EngineConfig cfg_a;
  cfg_a.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  cfg_a.publish_codec = RTC_CODEC_H265;
  cfg_a.enable_datachannel = true;
  cfg_a.ice_servers.push_back({turn_uri, user_a, pass_a});

  EngineConfig cfg_b = cfg_a;
  cfg_b.ice_servers.clear();
  cfg_b.ice_servers.push_back({turn_uri, user_b, pass_b});

  auto peer_a = RtcVideoEngine::Create(cfg_a, &obs_a);
  auto peer_b = RtcVideoEngine::Create(cfg_b, &obs_b);

  ASSERT_EQ(peer_a->JoinRoom("forced_turn_room", "cam_a"), RTC_OK);
  ASSERT_EQ(peer_b->JoinRoom("forced_turn_room", "viewer_b"), RTC_OK);

  DataChannelConfig dc_cfg;
  dc_cfg.label = "ptz_over_turn";
  dc_cfg.ordered = true;
  const int dc_id = peer_a->CreateDataChannel(dc_cfg);
  ASSERT_GE(dc_id, 0);

  std::string raw_offer;
  ASSERT_EQ(peer_a->CreateLocalOffer(&raw_offer), RTC_OK);
  const std::string relay_only_offer = KeepOnlyRelayCandidatesInSdp(raw_offer);
  EXPECT_NE(relay_only_offer.find("198.51.100.77"), std::string::npos);
  EXPECT_NE(relay_only_offer.find(" typ relay"), std::string::npos);
  EXPECT_EQ(relay_only_offer.find(" typ host"), std::string::npos);

  std::string raw_answer;
  ASSERT_EQ(
      peer_b->SetRemoteDescription("offer", relay_only_offer, &raw_answer),
      RTC_OK);
  const std::string relay_only_answer =
      KeepOnlyRelayCandidatesInSdp(raw_answer);
  EXPECT_NE(relay_only_answer.find("198.51.100.77"), std::string::npos);
  EXPECT_NE(relay_only_answer.find(" typ relay"), std::string::npos);
  EXPECT_EQ(relay_only_answer.find(" typ host"), std::string::npos);

  ASSERT_EQ(peer_a->SetRemoteDescription("answer", relay_only_answer, nullptr),
            RTC_OK);

  ASSERT_TRUE(obs_a.WaitConnected(5000));
  ASSERT_TRUE(obs_b.WaitConnected(5000));

  for (int i = 0; i < 15; ++i) {
    const auto nalu = BuildSyntheticH265Frame(i == 0, i == 0 ? 2200 : 800);
    rtc_encoded_frame_t frame{};
    frame.data = nalu.data();
    frame.size = nalu.size();
    frame.capture_ts_us = 2'000'000ULL + static_cast<uint64_t>(i) * 33'333ULL;
    frame.is_keyframe = (i == 0);
    frame.layer = RTC_STREAM_LAYER_HIGH;
    peer_a->PushVideoFrame(frame);
    if (i == 3) {
      peer_a->SendTextData(dc_id, "pan_left_via_turn_relay");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
  }

  EXPECT_TRUE(obs_b.WaitForDecodedFrames(10, 4000));
  EXPECT_TRUE(obs_b.WaitForDataMessages(1, 3000));

  const StunTurnStatsSnapshot relay_stats = turn_srv.GetStatsSnapshot();
  EXPECT_EQ(relay_stats.active_allocations, 2u);
  // 全部 ICE 连通性检查、DTLS 握手、SRTP H.265 视频与 SCTP DataChannel 均经由 TURN 中继转发。
  EXPECT_GT(relay_stats.relayed_packets, 25u);
  EXPECT_GT(relay_stats.relayed_bytes, 10000u);

  peer_a->LeaveRoom();
  peer_b->LeaveRoom();
  turn_srv.Stop();
}

// 13. 验证 `rtc_p2p_ws_signaling_server` 可执行文件默认不开启 TURN、传入 `--enable-turn` 时同进程协同开启信令+TURN 服务
TEST(RtcE2ETest, SignalingBinaryOptionalTurnFlagCoDeployment) {
  char self_exe[1024] = {};
  const ssize_t exe_len =
      ::readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
  ASSERT_GT(exe_len, 0);
  const std::string exe_path(self_exe, static_cast<size_t>(exe_len));
  const size_t slash = exe_path.find_last_of('/');
  ASSERT_NE(slash, std::string::npos);
  const std::string sig_bin =
      exe_path.substr(0, slash) + "/rtc_p2p_ws_signaling_server";
  ASSERT_EQ(::access(sig_bin.c_str(), X_OK), 0);

  const std::string ws_port_file =
      "/tmp/rtc_test_ws_port_" + std::to_string(::getpid()) + ".txt";
  const std::string turn_port_file =
      "/tmp/rtc_test_turn_port_" + std::to_string(::getpid()) + ".txt";
  ::unlink(ws_port_file.c_str());
  ::unlink(turn_port_file.c_str());

  auto read_port_file = [](const std::string& path, uint16_t* out_port) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(3000);
    while (std::chrono::steady_clock::now() < deadline) {
      FILE* fp = std::fopen(path.c_str(), "r");
      if (fp != nullptr) {
        unsigned p = 0;
        const int matched = std::fscanf(fp, "%u", &p);
        std::fclose(fp);
        if (matched == 1 && p > 0 && p <= 65535) {
          *out_port = static_cast<uint16_t>(p);
          return true;
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
    return false;
  };

  // 阶段 A：默认不带 `--enable-turn` 启动，确认仅写入信令端口，不启动 TURN 服务。
  const pid_t pid_default = ::fork();
  ASSERT_GE(pid_default, 0);
  if (pid_default == 0) {
    ::execl(sig_bin.c_str(), sig_bin.c_str(), "127.0.0.1", "0", "--port-file",
            ws_port_file.c_str(), "--turn-port-file", turn_port_file.c_str(),
            static_cast<char*>(nullptr));
    ::_exit(127);
  }
  uint16_t default_ws_port = 0;
  ASSERT_TRUE(read_port_file(ws_port_file, &default_ws_port));
  EXPECT_NE(::access(turn_port_file.c_str(), F_OK), 0);
  ::kill(pid_default, SIGTERM);
  int status = 0;
  ::waitpid(pid_default, &status, 0);
  ::unlink(ws_port_file.c_str());

  // 阶段 B：传入 `--enable-turn` 协同开启 WebSocket 信令与内置 STUN/TURN 服务。
  const pid_t pid_turn = ::fork();
  ASSERT_GE(pid_turn, 0);
  if (pid_turn == 0) {
    ::execl(sig_bin.c_str(), sig_bin.c_str(), "127.0.0.1", "0", "--port-file",
            ws_port_file.c_str(), "--enable-turn", "--turn-port", "0",
            "--turn-port-file", turn_port_file.c_str(), "--turn-user",
            "cli_user:cli_pass", "--realm", "rtc.cli",
            static_cast<char*>(nullptr));
    ::_exit(127);
  }

  uint16_t ws_port = 0;
  uint16_t turn_port = 0;
  ASSERT_TRUE(read_port_file(ws_port_file, &ws_port));
  ASSERT_TRUE(read_port_file(turn_port_file, &turn_port));

  TestPeerObserver pub_obs;
  TestPeerObserver sub_obs;
  EngineConfig cfg;
  cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  cfg.signaling_or_moq_url =
      "ws://127.0.0.1:" + std::to_string(ws_port) + "/ws";
  cfg.publish_codec = RTC_CODEC_H264;
  cfg.ice_servers.push_back(
      {"stun:127.0.0.1:" + std::to_string(turn_port), "", ""});
  cfg.ice_servers.push_back(
      {"turn:127.0.0.1:" + std::to_string(turn_port) + "?transport=udp",
       "cli_user", "cli_pass"});

  auto pub = RtcVideoEngine::Create(cfg, &pub_obs);
  auto sub = RtcVideoEngine::Create(cfg, &sub_obs);
  ASSERT_EQ(pub->JoinRoom("cli_coturn_room", "pub_node"), RTC_OK);
  ASSERT_EQ(sub->JoinRoom("cli_coturn_room", "sub_node"), RTC_OK);
  ASSERT_TRUE(pub_obs.WaitConnected(5000));
  ASSERT_TRUE(sub_obs.WaitConnected(5000));

  for (int i = 0; i < 12; ++i) {
    const auto nalu = BuildSyntheticH264Frame(i == 0, 1100);
    rtc_encoded_frame_t frame{};
    frame.data = nalu.data();
    frame.size = nalu.size();
    frame.capture_ts_us = 3'000'000ULL + static_cast<uint64_t>(i) * 33'333ULL;
    frame.is_keyframe = (i == 0);
    frame.layer = RTC_STREAM_LAYER_HIGH;
    pub->PushVideoFrame(frame);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
  }
  EXPECT_TRUE(sub_obs.WaitForDecodedFrames(8, 3000));

  pub->LeaveRoom();
  sub->LeaveRoom();

  ::kill(pid_turn, SIGTERM);
  ::waitpid(pid_turn, &status, 0);
  ::unlink(ws_port_file.c_str());
  ::unlink(turn_port_file.c_str());
}

}  // namespace
}  // namespace rtc
