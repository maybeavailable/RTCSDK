// 纯现代 C++17 动态库（`librtc_video_sdk.so`）外部隔离集成测试。
// 本测试仅依赖 `include/` 公共头文件并仅链接 `rtc_video_sdk` 共享库，
// 用于验证外部业务进程在无内部头文件与第三方依赖头文件的情况下可正常编译、链接与互通。

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "rtc_video_engine.hpp"

namespace {

// 验证通过 `librtc_video_sdk.so` 导出的日志接收器与 5 种内置 QUIC 拥塞控制工厂。
TEST(Cpp17SharedSdkTest, LogSinkAndBuiltinQuicCongestionControllers) {
  class CaptureLogSink final : public rtc::LogSink {
   public:
    void OnLogMessage(const rtc::LogEntryView& entry,
                      std::string_view /*formatted_line*/) override {
      std::lock_guard<std::mutex> lock(mu_);
      ++count_;
      last_msg_ = std::string(entry.message);
    }

    size_t Count() const {
      std::lock_guard<std::mutex> lock(mu_);
      return count_;
    }

   private:
    mutable std::mutex mu_;
    size_t count_ = 0;
    std::string last_msg_;
  };

  rtc::RtcVideoEngine::SetLogToStderr(false);
  rtc::RtcVideoEngine::SetMinLogSeverity(rtc::LoggingSeverity::kInfo);
  CaptureLogSink sink;
  rtc::RtcVideoEngine::AddLogSink(&sink, rtc::LoggingSeverity::kInfo);

  const rtc_quic_cc_algo_e algos[] = {
      RTC_QUIC_CC_BBR, RTC_QUIC_CC_BBR2, RTC_QUIC_CC_CUBIC,
      RTC_QUIC_CC_COPA, RTC_QUIC_CC_NEWRENO};
  for (rtc_quic_cc_algo_e algo : algos) {
    const std::string_view expected_name = rtc::QuicCcAlgoName(algo);
    EXPECT_FALSE(expected_name.empty());
    EXPECT_NE(expected_name, "Unknown");

    auto cc = rtc::CreateBuiltinQuicCongestionController(algo, 1200);
    ASSERT_NE(cc, nullptr);
    EXPECT_EQ(cc->Name(), expected_name);
    EXPECT_GT(cc->GetCongestionWindowBytes(), 0u);

    auto factory = rtc::CreateBuiltinQuicCcFactory(algo);
    ASSERT_NE(factory, nullptr);
    auto from_factory = factory->Create(1200);
    ASSERT_NE(from_factory, nullptr);
    EXPECT_EQ(from_factory->Name(), expected_name);
  }

  rtc::EngineConfig cfg;
  cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  auto engine = rtc::RtcVideoEngine::Create(cfg, nullptr);
  ASSERT_NE(engine, nullptr);
  engine.reset();
  EXPECT_GT(sink.Count(), 0u);

  rtc::RtcVideoEngine::RemoveLogSink(&sink);
  rtc::RtcVideoEngine::SetLogToStderr(true);
}

// 验证仅链接 `librtc_video_sdk.so` 时的 WebRTC P2P 直连协商与双向数据通道闭环。
TEST(Cpp17SharedSdkTest, WebRtcP2pOfferAnswerAndDataChannel) {
  class PeerObserver final : public rtc::IRtcEventObserver {
   public:
    void BindPeer(rtc::RtcVideoEngine* peer) {
      std::lock_guard<std::mutex> lock(mu);
      peer_ = peer;
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
                              const rtc_encoded_frame_t&) override {}
    void OnConnectionState(rtc_connection_state_e state, int) override {
      if (state == RTC_CONN_STATE_CONNECTED) {
        std::lock_guard<std::mutex> lock(mu);
        connected = true;
        cv.notify_all();
      }
    }
    void OnLocalIceCandidate(const std::string&,
                             int,
                             const std::string& cand) override {
      rtc::RtcVideoEngine* p = nullptr;
      {
        std::lock_guard<std::mutex> lock(mu);
        p = peer_;
      }
      if (p != nullptr) {
        p->AddRemoteIceCandidate(cand);
      }
    }
    void OnDataChannelMessage(const std::string&,
                              int,
                              bool,
                              const uint8_t* data,
                              size_t size) override {
      std::lock_guard<std::mutex> lock(mu);
      rx_text.assign(reinterpret_cast<const char*>(data), size);
      cv.notify_all();
    }

    std::mutex mu;
    std::condition_variable cv;
    bool connected = false;
    std::string rx_text;

   private:
    rtc::RtcVideoEngine* peer_ = nullptr;
  };

  rtc::EngineConfig cfg;
  cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  cfg.publish_codec = RTC_CODEC_H264;
  cfg.enable_flexfec = true;

  PeerObserver obs_a;
  PeerObserver obs_b;
  auto peer_a = rtc::RtcVideoEngine::Create(cfg, &obs_a);
  auto peer_b = rtc::RtcVideoEngine::Create(cfg, &obs_b);
  ASSERT_NE(peer_a, nullptr);
  ASSERT_NE(peer_b, nullptr);

  obs_a.BindPeer(peer_b.get());
  obs_b.BindPeer(peer_a.get());

  rtc::DataChannelConfig dc_cfg;
  dc_cfg.label = "shared_sdk_dc";
  const int dc_id = peer_a->CreateDataChannel(dc_cfg);
  ASSERT_GE(dc_id, 0);

  constexpr std::string_view kPayload = "pure_cpp17_shared_sdk_ok";
  ASSERT_EQ(peer_a->SendTextData(dc_id, kPayload), RTC_OK);

  std::string offer_sdp;
  std::string answer_sdp;
  ASSERT_EQ(peer_a->CreateLocalOffer(&offer_sdp), RTC_OK);
  ASSERT_EQ(peer_b->SetRemoteDescription("offer", offer_sdp, &answer_sdp),
            RTC_OK);
  ASSERT_EQ(peer_a->SetRemoteDescription("answer", answer_sdp, nullptr),
            RTC_OK);

  {
    std::unique_lock<std::mutex> lock(obs_b.mu);
    ASSERT_TRUE(obs_b.cv.wait_for(lock, std::chrono::milliseconds(4000), [&]() {
      return obs_b.rx_text == kPayload;
    }));
  }

  EXPECT_EQ(peer_a->CloseDataChannel(dc_id), RTC_OK);
  obs_a.BindPeer(nullptr);
  obs_b.BindPeer(nullptr);
}

}  // namespace
