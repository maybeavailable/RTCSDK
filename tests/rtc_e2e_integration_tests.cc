#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <gtest/gtest.h>

#include "call/webrtc_p2p_backend.h"
#include "moq/moq_transport.h"
#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"
#include "rtc_base/task_queue.h"
#include "rtc_video_engine.hpp"
#include "rtc_video_sdk.h"
#include "server/embedded_moq_relay.h"

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

}  // namespace
}  // namespace rtc
