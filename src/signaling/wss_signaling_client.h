#ifndef SRC_SIGNALING_WSS_SIGNALING_CLIENT_H_
#define SRC_SIGNALING_WSS_SIGNALING_CLIENT_H_

// 基于 Boost.Beast + OpenSSL 构建的异步 WebSocket / WSS 信令客户端，
// 严格在 SDK 隔离的信令队列（SignalingQueue）上串行执行。

#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
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
    std::lock_guard<std::mutex> lock(cb_mu_);
    on_connected_ = std::move(cb);
  }
  void set_on_message(std::function<void(const std::string&)> cb) {
    std::lock_guard<std::mutex> lock(cb_mu_);
    on_message_ = std::move(cb);
  }
  void set_on_closed(std::function<void(int, const std::string&)> cb) {
    std::lock_guard<std::mutex> lock(cb_mu_);
    on_closed_ = std::move(cb);
  }

  virtual void Connect(const std::string& url) = 0;
  virtual void SendText(const std::string& payload) = 0;
  virtual void Close() = 0;

 protected:
  mutable std::mutex cb_mu_;
  std::function<void()> on_connected_;
  std::function<void(const std::string&)> on_message_;
  std::function<void(int, const std::string&)> on_closed_;
};

class BoostBeastSignalingClient final : public ISignalingTransport {
 public:
  explicit BoostBeastSignalingClient(TaskQueueBoost* signaling_queue);
  ~BoostBeastSignalingClient() override;

  void SetTlsOptions(bool verify_peer,
                     std::string ca_cert_path = {},
                     std::string pinned_cert_sha256 = {});

  void Connect(const std::string& url) override;
  void SendText(const std::string& payload) override;
  void Close() override;

 private:
  struct ParsedUrl {
    bool use_tls = false;
    bool is_ipv6 = false;
    std::string host;
    std::string port;
    std::string host_header;
    std::string target = "/";
  };

  struct Session;

  static bool ParseWsUrl(std::string_view url, ParsedUrl* out);
  static void CancelSessionStreams(const std::shared_ptr<Session>& sess);
  void DoReadLoop(const std::shared_ptr<Session>& sess);
  void FlushWriteQueue(const std::shared_ptr<Session>& sess);
  void Fail(const std::shared_ptr<Session>& sess,
            int code,
            std::string_view where);

  TaskQueueBoost* const sig_queue_;
  SequenceChecker sig_checker_;
  bool tls_verify_peer_ = true;
  std::string tls_ca_cert_path_;
  std::string tls_pinned_cert_sha256_;
  std::shared_ptr<Session> session_;
  ScopedTaskSafety safety_;
};

}  // namespace rtc

#endif  // SRC_SIGNALING_WSS_SIGNALING_CLIENT_H_
