// 兼容浏览器的 WebRTC P2P HTTP 网关与自测 SDK 使用示例：
//
// 模式 1（浏览器交互式实时推拉流）：
//   运行命令：./rtc_example_browser_p2p 8080
//   在 Chrome / Edge / Firefox / Safari 中打开 http://127.0.0.1:8080 并点击
//   "Start P2P Video"，直接与 SDK 进行 W3C WebRTC P2P 协商，并在 <video> 标签中
//   实时渲染真实的 ITU-T H.264 Baseline 色彩循环视频帧。
//
// 模式 2（自动化端到端验证）：
//   运行命令：./rtc_example_browser_p2p --self-test
//   在临时端口上启动 HTTP 网关，由模拟浏览器对端发起真实的 HTTP POST
//   `/api/offer` W3C SDP 协商，验证端到端 DTLS-SRTP 媒体帧传输后以状态码 0 退出。

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"
#include "rtc_base/task_queue.h"
#include "rtc_video_engine.hpp"

namespace {

namespace http = boost::beast::http;
using tcp = boost::asio::ip::tcp;

constexpr size_t kMaxConcurrentHttpClients = 64;

bool IsAllowedLocalOrigin(std::string_view origin) {
  if (origin.empty()) {
    return true;
  }
  for (std::string_view pfx :
       {"http://127.0.0.1", "https://127.0.0.1", "http://localhost",
        "https://localhost", "http://[::1]", "https://[::1]"}) {
    if (origin.size() >= pfx.size() &&
        origin.substr(0, pfx.size()) == pfx &&
        (origin.size() == pfx.size() || origin[pfx.size()] == ':')) {
      return true;
    }
  }
  return false;
}

std::atomic<bool> g_quit{false};
void OnSignal(int /*sig*/) { g_quit.store(true); }

constexpr const char kBrowserHtmlPage[] = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Embedded RTCSDK - Browser WebRTC P2P Live Demo</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc;
           display: flex; flex-direction: column; align-items: center; padding: 2rem; }
    video { width: 480px; height: 360px; background: #020617; border-radius: 12px;
            border: 1px solid #334155; image-rendering: pixelated; margin: 1rem 0; }
    button { background: #2563eb; color: #fff; border: none; padding: 0.7rem 1.4rem;
             border-radius: 8px; font-size: 1rem; cursor: pointer; }
    pre { background: #1e293b; padding: 1rem; border-radius: 8px; width: 640px;
          max-height: 220px; overflow: auto; font-size: 0.85rem; }
  </style>
</head>
<body>
  <h2>Embedded RTCSDK &harr; Browser WebRTC P2P + DataChannel</h2>
  <video id="remoteVideo" autoplay playsinline muted controls></video>
  <div style="display:flex; gap:0.6rem; margin-bottom:0.8rem;">
    <button onclick="startP2P()">Start P2P Video + DataChannel</button>
    <input id="dcInput" value="PTZ:ZOOM_IN" style="padding:0.6rem; border-radius:8px; border:1px solid #475569; background:#0f172a; color:#f8fafc;">
    <button onclick="sendDcMsg()">Send DataChannel</button>
  </div>
  <pre id="logBox">Ready. Click "Start P2P Video + DataChannel" to connect.</pre>
  <script>
    let activeDc = null;
    const log = (m) => {
      const el = document.getElementById('logBox');
      el.textContent += '\n' + m;
      el.scrollTop = el.scrollHeight;
    };
    function sendDcMsg() {
      const txt = document.getElementById('dcInput').value;
      if (activeDc && activeDc.readyState === 'open') {
        activeDc.send(txt);
        log('[DC TX] ' + txt);
      } else {
        log('DataChannel not open yet');
      }
    }
    async function startP2P() {
      const pc = new RTCPeerConnection();
      pc.addTransceiver('video', { direction: 'recvonly' });
      activeDc = pc.createDataChannel('browser_ctrl');
      activeDc.onopen = () => {
        log('WebRTC DataChannel [browser_ctrl] OPEN!');
        activeDc.send('HELLO_EMBEDDED_SDK');
      };
      activeDc.onmessage = (ev) => log('[DC RX] ' + ev.data);
      pc.ontrack = (ev) => {
        log('Received remote H.264 track from Embedded RTCSDK!');
        document.getElementById('remoteVideo').srcObject = ev.streams[0];
      };
      pc.oniceconnectionstatechange = () => log('ICE state: ' + pc.iceConnectionState);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await new Promise((resolve) => {
        if (pc.iceGatheringState === 'complete') return resolve();
        pc.onicegatheringstatechange = () => {
          if (pc.iceGatheringState === 'complete') resolve();
        };
        setTimeout(resolve, 500);
      });
      log('Sending W3C SDP Offer to /api/offer ...');
      const resp = await fetch('/api/offer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/sdp' },
        body: pc.localDescription.sdp
      });
      const answerSdp = await resp.text();
      await pc.setRemoteDescription({ type: 'answer', sdp: answerSdp });
      log('Applied Embedded RTCSDK SDP Answer!');
    }
  </script>
</body>
</html>
)HTML";

// 生成比特级精确的 ITU-T H.264 Constrained Baseline (42e01f) 16x16 I_PCM
// Annex-B 视频帧，带广播级色域范围 [16..235] 的 YUV420 色彩动画（可由
// Chrome / Firefox / Safari / FFmpeg / 硬件 VDEC 直接解码）。
std::vector<uint8_t> BuildValidH264IpcmColorFrame(int frame_index) {
  // SPS（16x16 Baseline 42e01f，poc_type=2）+ PPS（CAVLC）+ IDR I_PCM 帧头。
  static const uint8_t kAnnexBHeaders[] = {
      0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xE0, 0x1F, 0xDA, 0xF2,
      0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80,
      0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x86, 0x80,
  };
  std::vector<uint8_t> frame(kAnnexBHeaders,
                             kAnnexBHeaders + sizeof(kAnnexBHeaders));
  frame.reserve(sizeof(kAnnexBHeaders) + 385);

  const uint8_t y_val = static_cast<uint8_t>(40 + ((frame_index * 7) % 160));
  const uint8_t cb_val = static_cast<uint8_t>(60 + ((frame_index * 11) % 140));
  const uint8_t cr_val = static_cast<uint8_t>(180 - ((frame_index * 5) % 120));

  frame.insert(frame.end(), 256, y_val);
  frame.insert(frame.end(), 64, cb_val);
  frame.insert(frame.end(), 64, cr_val);
  frame.push_back(0x80);  // RBSP 切片尾部对齐比特（rbsp_slice_trailing_bits）
  return frame;
}

class GatewayObserver final : public rtc::IRtcEventObserver {
 public:
  void OnEncoderBitrateAllocation(rtc_stream_layer_e /*layer*/,
                                  bool /*layer_active*/,
                                  uint32_t target_bitrate_bps,
                                  uint32_t /*target_fps*/) override {
    RTC_LOG(kInfo) << "[BrowserGateway] Target bitrate="
                   << (target_bitrate_bps / 1000) << " kbps";
  }

  void OnEncoderForceIdr(rtc_stream_layer_e /*layer*/) override {}

  void OnRemoteTrackPublished(const std::string& /*peer_id*/,
                              const std::string& /*track_id*/,
                              rtc_video_codec_e /*codec*/) override {}

  void OnRemoteTrackUnpublished(const std::string& /*peer_id*/,
                                const std::string& /*track_id*/) override {}

  void OnRemoteEncodedFrame(const std::string& /*peer_id*/,
                            const std::string& /*track_id*/,
                            const rtc_encoded_frame_t& /*frame*/) override {}

  void BindEngine(rtc::RtcVideoEngine* eng) {
    std::lock_guard<std::mutex> lk(mu_);
    engine_ = eng;
  }

  void OnConnectionState(rtc_connection_state_e state,
                         int /*reason_code*/) override {
    connected_.store(state == RTC_CONN_STATE_CONNECTED,
                     std::memory_order_release);
  }

  void OnDataChannelMessage(const std::string& /*peer_id*/,
                            int channel_id,
                            bool /*is_binary*/,
                            const uint8_t* data,
                            size_t size) override {
    std::string rx(reinterpret_cast<const char*>(data), size);
    RTC_LOG(kInfo) << "[BrowserGateway] DataChannel RX: " << rx;
    std::lock_guard<std::mutex> lk(mu_);
    if (engine_ != nullptr) {
      engine_->SendTextData(channel_id, "ACK:" + rx);
    }
  }

  bool is_connected() const {
    return connected_.load(std::memory_order_acquire);
  }

 private:
  std::mutex mu_;
  rtc::RtcVideoEngine* engine_ = nullptr;
  std::atomic<bool> connected_{false};
};

class BrowserP2pHttpGateway {
 public:
  BrowserP2pHttpGateway()
      : http_queue_("http-gw", rtc::TaskQueuePriority::kNormal),
        acceptor_(http_queue_.io_context()) {}

  ~BrowserP2pHttpGateway() { Stop(); }

  BrowserP2pHttpGateway(const BrowserP2pHttpGateway&) = delete;
  BrowserP2pHttpGateway& operator=(const BrowserP2pHttpGateway&) = delete;

  bool Start(uint16_t port) {
    bool ok = false;
    http_queue_.Invoke([this, port, &ok]() {
      boost::system::error_code ec;
      const tcp::endpoint ep(boost::asio::ip::make_address("0.0.0.0"), port);
      acceptor_.open(ep.protocol(), ec);
      if (ec) return;
      acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
      acceptor_.bind(ep, ec);
      if (ec) return;
      acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
      if (ec) return;
      const uint16_t p = acceptor_.local_endpoint(ec).port();
      ok = !ec;
      if (ok) {
        bound_port_.store(p, std::memory_order_release);
        DoAccept();
      }
    });
    if (!ok) {
      return false;
    }

    pump_thread_ = std::thread([this]() { RunFramePumpLoop(); });
    return true;
  }

  void Stop() {
    if (stopped_.exchange(true)) {
      return;
    }
    bound_port_.store(0, std::memory_order_release);
    http_queue_.Invoke([this]() {
      boost::system::error_code ec;
      acceptor_.close(ec);
    });
    http_queue_.Shutdown();
    if (pump_thread_.joinable()) {
      pump_thread_.join();
    }
    std::lock_guard<std::mutex> lock(session_mu_);
    if (active_obs_) {
      active_obs_->BindEngine(nullptr);
    }
    if (active_engine_) {
      active_engine_->LeaveRoom();
      active_engine_.reset();
    }
  }

  uint16_t port() const { return bound_port_.load(std::memory_order_acquire); }

 private:
  void DoAccept() {
    acceptor_.async_accept([this](boost::system::error_code ec,
                                  tcp::socket socket) {
      if (ec || stopped_.load(std::memory_order_acquire)) {
        return;
      }
      if (active_http_clients_.load(std::memory_order_acquire) >=
          kMaxConcurrentHttpClients) {
        boost::system::error_code close_ec;
        socket.close(close_ec);
        DoAccept();
        return;
      }
      DoAccept();
      HandleHttpClientAsync(std::move(socket));
    });
  }

  void HandleHttpClientAsync(tcp::socket socket) {
    struct HttpConn {
      HttpConn(tcp::socket s, std::atomic<size_t>* counter)
          : stream(std::move(s)), active_counter(counter) {
        active_counter->fetch_add(1, std::memory_order_acq_rel);
        parser.body_limit(256 * 1024);
      }
      ~HttpConn() {
        active_counter->fetch_sub(1, std::memory_order_acq_rel);
      }
      boost::beast::tcp_stream stream;
      std::atomic<size_t>* active_counter;
      boost::beast::flat_buffer buffer;
      http::request_parser<http::string_body> parser;
      http::response<http::string_body> res;
    };
    auto conn =
        std::make_shared<HttpConn>(std::move(socket), &active_http_clients_);
    conn->stream.expires_after(std::chrono::seconds(5));
    http::async_read(
        conn->stream, conn->buffer, conn->parser,
        [this, conn](boost::system::error_code ec, size_t /*n*/) {
          if (ec || stopped_.load(std::memory_order_acquire)) {
            return;
          }
          auto req = conn->parser.release();
          conn->res =
              http::response<http::string_body>{http::status::ok, req.version()};
          const std::string origin(req[http::field::origin]);
          if (!IsAllowedLocalOrigin(origin)) {
            conn->res.result(http::status::forbidden);
            conn->res.body() = "Forbidden cross-origin request";
          } else {
            if (!origin.empty()) {
              conn->res.set(http::field::access_control_allow_origin, origin);
              conn->res.set(http::field::vary, "Origin");
            }
            if (req.method() == http::verb::options) {
              conn->res.set(http::field::access_control_allow_methods,
                            "GET, POST, OPTIONS");
              conn->res.set(http::field::access_control_allow_headers,
                            "Content-Type");
            } else if (req.method() == http::verb::get && req.target() == "/") {
              conn->res.set(http::field::content_type,
                            "text/html; charset=utf-8");
              conn->res.body() = kBrowserHtmlPage;
            } else if (req.method() == http::verb::post &&
                       req.target() == "/api/offer") {
              std::string answer_sdp;
              if (AcceptBrowserOffer(req.body(), &answer_sdp)) {
                conn->res.set(http::field::content_type, "application/sdp");
                conn->res.body() = std::move(answer_sdp);
              } else {
                conn->res.result(http::status::bad_request);
                conn->res.body() = "Invalid WebRTC SDP Offer";
              }
            } else {
              conn->res.result(http::status::not_found);
              conn->res.body() = "Not Found";
            }
          }

          conn->res.prepare_payload();
          conn->stream.expires_after(std::chrono::seconds(5));
          http::async_write(
              conn->stream, conn->res,
              [conn](boost::system::error_code /*wec*/, size_t /*wn*/) {
                boost::system::error_code sec;
                conn->stream.socket().shutdown(tcp::socket::shutdown_send, sec);
              });
        });
  }

  bool AcceptBrowserOffer(std::string_view offer_sdp,
                          std::string* out_answer_sdp) {
    std::lock_guard<std::mutex> lock(session_mu_);
    if (active_obs_) {
      active_obs_->BindEngine(nullptr);
    }
    if (active_engine_) {
      active_engine_->LeaveRoom();
      active_engine_.reset();
    }
    active_obs_ = std::make_unique<GatewayObserver>();

    rtc::EngineConfig cfg;
    cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
    cfg.publish_codec = RTC_CODEC_H264;
    cfg.enable_flexfec = true;
    cfg.zero_playout_delay = true;

    active_engine_ = rtc::RtcVideoEngine::Create(cfg, active_obs_.get());
    active_obs_->BindEngine(active_engine_.get());
    active_engine_->JoinRoom("browser_http_p2p", "embedded_gateway");
    return active_engine_->SetRemoteDescription("offer", offer_sdp,
                                                out_answer_sdp) == RTC_OK;
  }

  void RunFramePumpLoop() {
    uint64_t ts_us = 1'000'000;
    int frame_idx = 0;
    while (!stopped_.load(std::memory_order_acquire)) {
      {
        std::lock_guard<std::mutex> lock(session_mu_);
        if (active_engine_ && active_obs_ && active_obs_->is_connected()) {
          const auto h264_nalu = BuildValidH264IpcmColorFrame(frame_idx++);
          rtc_encoded_frame_t frame{};
          frame.data = h264_nalu.data();
          frame.size = h264_nalu.size();
          frame.capture_ts_us = ts_us;
          frame.is_keyframe = true;
          frame.layer = RTC_STREAM_LAYER_HIGH;
          active_engine_->PushVideoFrame(frame);
        }
      }
      ts_us += 33'333;
      std::this_thread::sleep_for(std::chrono::milliseconds(33));
    }
  }

  rtc::TaskQueueBoost http_queue_;
  tcp::acceptor acceptor_;
  std::atomic<uint16_t> bound_port_{0};
  std::atomic<size_t> active_http_clients_{0};
  std::atomic<bool> stopped_{false};
  std::thread pump_thread_;

  std::mutex session_mu_;
  std::unique_ptr<GatewayObserver> active_obs_;
  std::unique_ptr<rtc::RtcVideoEngine> active_engine_;
};

int RunAutomatedBrowserSelfTest() {
  BrowserP2pHttpGateway gateway;
  if (!gateway.Start(0)) {
    RTC_LOG(kError) << "Failed to bind BrowserP2pHttpGateway";
    return 1;
  }

  class SimulatedBrowserObserver final : public rtc::IRtcEventObserver {
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
                              const rtc_encoded_frame_t&) override {
      std::lock_guard<std::mutex> lock(mu_);
      ++frames_received_;
      cv_.notify_all();
    }
    void OnConnectionState(rtc_connection_state_e, int) override {}
    void OnDataChannelMessage(const std::string&,
                              int,
                              bool,
                              const uint8_t* data,
                              size_t size) override {
      std::lock_guard<std::mutex> lock(mu_);
      last_dc_reply_.assign(reinterpret_cast<const char*>(data), size);
      cv_.notify_all();
    }

    bool WaitFramesAndDcReply(int target, int timeout_ms) {
      std::unique_lock<std::mutex> lock(mu_);
      return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                          [this, target]() {
                            return frames_received_ >= target &&
                                   last_dc_reply_ == "ACK:PING_FROM_CHROME";
                          });
    }
    int frames_received() const {
      std::lock_guard<std::mutex> lock(mu_);
      return frames_received_;
    }
    std::string dc_reply() const {
      std::lock_guard<std::mutex> lock(mu_);
      return last_dc_reply_;
    }

   private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    int frames_received_ = 0;
    std::string last_dc_reply_;
  } browser_obs;

  rtc::EngineConfig browser_cfg;
  browser_cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  browser_cfg.publish_codec = RTC_CODEC_H264;
  auto browser_client = rtc::RtcVideoEngine::Create(browser_cfg, &browser_obs);
  rtc::DataChannelConfig dc_cfg;
  dc_cfg.label = "browser_ctrl";
  const int dc_id = browser_client->CreateDataChannel(dc_cfg);
  browser_client->SendTextData(dc_id, "PING_FROM_CHROME");
  browser_client->JoinRoom("browser_http_p2p", "simulated_chrome");

  std::string offer_sdp;
  if (browser_client->CreateLocalOffer(&offer_sdp) != RTC_OK) {
    return 2;
  }

  // 向内嵌网关发送真实的 HTTP POST /api/offer 请求
  boost::asio::io_context ioc;
  boost::system::error_code ec;
  tcp::socket sock(ioc);
  sock.connect(
      tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), gateway.port()),
      ec);
  if (ec) {
    return 3;
  }

  http::request<http::string_body> req{http::verb::post, "/api/offer", 11};
  req.set(http::field::host, "127.0.0.1");
  req.set(http::field::content_type, "application/sdp");
  req.body() = offer_sdp;
  req.prepare_payload();
  http::write(sock, req, ec);
  if (ec) {
    return 4;
  }

  boost::beast::flat_buffer rx_buf;
  http::response<http::string_body> res;
  http::read(sock, rx_buf, res, ec);
  sock.shutdown(tcp::socket::shutdown_both, ec);
  if (res.result() != http::status::ok || res.body().empty()) {
    return 5;
  }

  if (browser_client->SetRemoteDescription("answer", res.body(), nullptr) !=
      RTC_OK) {
    return 6;
  }

  const bool got_video = browser_obs.WaitFramesAndDcReply(10, 4000);
  RTC_LOG(kInfo) << "=== Browser HTTP P2P Self-Test Summary: http_port="
                 << gateway.port()
                 << " h264_frames_received=" << browser_obs.frames_received()
                 << " dc_reply=" << browser_obs.dc_reply()
                 << " ===";

  browser_client->LeaveRoom();
  browser_client.reset();
  gateway.Stop();
  return got_video ? 0 : 7;
}

}  // namespace

int main(int argc, char** argv) {
  rtc::RtcVideoEngine::SetMinLogSeverity(rtc::LoggingSeverity::kInfo);

  for (int i = 1; i < argc; ++i) {
    if (std::string_view(argv[i]) == "--self-test") {
      return RunAutomatedBrowserSelfTest();
    }
  }

  uint16_t port = 8080;
  if (argc >= 2) {
    rtc::ParseUint16(argv[1], &port);
  }

  std::signal(SIGINT, &OnSignal);
  std::signal(SIGTERM, &OnSignal);

  BrowserP2pHttpGateway gateway;
  if (!gateway.Start(port)) {
    RTC_LOG(kError) << "Failed to start BrowserP2pHttpGateway on port " << port;
    return 1;
  }

  RTC_LOG(kInfo) << "Browser WebRTC P2P Live Demo listening at http://127.0.0.1:"
                 << gateway.port() << "/ (Press Ctrl+C to stop)";
  while (!g_quit.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  gateway.Stop();
  return 0;
}
