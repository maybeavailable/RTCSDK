#ifndef SRC_SIGNALING_WSS_SIGNALING_CLIENT_H_
#define SRC_SIGNALING_WSS_SIGNALING_CLIENT_H_

// 基于 Boost.Beast + OpenSSL 构建的异步 WebSocket / WSS 信令客户端，
// 严格在 SDK 隔离的信令队列（SignalingQueue）上串行执行。

#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"

namespace rtc {

class ISignalingTransport {
 public:
  ISignalingTransport() = default;
  virtual ~ISignalingTransport() = default;

  ISignalingTransport(const ISignalingTransport&) = delete;
  ISignalingTransport& operator=(const ISignalingTransport&) = delete;

  void set_on_connected(std::function<void()> cb) {
    on_connected_ = std::move(cb);
  }
  void set_on_message(std::function<void(const std::string&)> cb) {
    on_message_ = std::move(cb);
  }
  void set_on_closed(std::function<void(int, const std::string&)> cb) {
    on_closed_ = std::move(cb);
  }

  virtual void Connect(const std::string& url) = 0;
  virtual void SendText(const std::string& payload) = 0;
  virtual void Close() = 0;

 protected:
  std::function<void()> on_connected_;
  std::function<void(const std::string&)> on_message_;
  std::function<void(int, const std::string&)> on_closed_;
};

class BoostBeastSignalingClient final : public ISignalingTransport {
 public:
  explicit BoostBeastSignalingClient(TaskQueueBoost* signaling_queue);
  ~BoostBeastSignalingClient() override;

  void Connect(const std::string& url) override;
  void SendText(const std::string& payload) override;
  void Close() override;

 private:
  struct ParsedUrl {
    bool use_tls = false;
    std::string host;
    std::string port;
    std::string target = "/";
  };

  static bool ParseWsUrl(std::string_view url, ParsedUrl* out);
  void DoReadLoop();
  void FlushWriteQueue();
  void Fail(int code, std::string_view where);

  TaskQueueBoost* const sig_queue_;
  SequenceChecker sig_checker_;

  boost::asio::ip::tcp::resolver resolver_;
  boost::asio::ssl::context ssl_ctx_;
  std::unique_ptr<boost::beast::websocket::stream<boost::beast::tcp_stream>>
      ws_plain_;
  std::unique_ptr<boost::beast::websocket::stream<
      boost::beast::ssl_stream<boost::beast::tcp_stream>>>
      ws_tls_;

  boost::beast::flat_buffer read_buf_;
  std::deque<std::string> write_queue_;
  bool connected_ = false;
  bool writing_ = false;
  bool use_tls_ = false;
  ScopedTaskSafety safety_;
};

}  // namespace rtc

#endif  // SRC_SIGNALING_WSS_SIGNALING_CLIENT_H_
