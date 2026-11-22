#include "signaling/wss_signaling_client.h"

#include <chrono>

#include <openssl/tls1.h>

#include "rtc_base/logging.h"

namespace rtc {

BoostBeastSignalingClient::BoostBeastSignalingClient(
    TaskQueueBoost* signaling_queue)
    : sig_queue_(signaling_queue),
      sig_checker_(signaling_queue),
      resolver_(signaling_queue->io_context()),
      ssl_ctx_(boost::asio::ssl::context::tlsv12_client),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {
  ssl_ctx_.set_default_verify_paths();
  ssl_ctx_.set_verify_mode(boost::asio::ssl::verify_none);
}

BoostBeastSignalingClient::~BoostBeastSignalingClient() {
  sig_queue_->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&sig_checker_);
    safety_.flag()->SetNotAlive();
    Close();
  });
}

bool BoostBeastSignalingClient::ParseWsUrl(std::string_view url,
                                           ParsedUrl* out) {
  size_t pos = 0;
  if (url.substr(0, 6) == "wss://") {
    out->use_tls = true;
    out->port = "443";
    pos = 6;
  } else if (url.substr(0, 5) == "ws://") {
    out->use_tls = false;
    out->port = "80";
    pos = 5;
  } else {
    return false;
  }

  const size_t slash = url.find('/', pos);
  const std::string_view authority =
      (slash == std::string_view::npos) ? url.substr(pos)
                                        : url.substr(pos, slash - pos);
  out->target =
      (slash == std::string_view::npos) ? "/" : std::string(url.substr(slash));

  const size_t colon = authority.rfind(':');
  if (colon != std::string_view::npos) {
    out->host = std::string(authority.substr(0, colon));
    out->port = std::string(authority.substr(colon + 1));
  } else {
    out->host = std::string(authority);
  }
  return !out->host.empty();
}

void BoostBeastSignalingClient::Connect(const std::string& url) {
  sig_queue_->PostTask(SafeTask(safety_.flag(), [this, url]() {
    RTC_DCHECK_RUN_ON(&sig_checker_);
    ParsedUrl parsed;
    if (!ParseWsUrl(url, &parsed)) {
      Fail(-1, "Invalid ws/wss URL");
      return;
    }
    use_tls_ = parsed.use_tls;
    RTC_LOG(kInfo) << "Connecting signaling WebSocket to " << url;

    resolver_.async_resolve(
        parsed.host, parsed.port,
        SafeTask(
            safety_.flag(),
            [this, parsed](
                boost::beast::error_code ec,
                boost::asio::ip::tcp::resolver::results_type results) {
              RTC_DCHECK_RUN_ON(&sig_checker_);
              if (ec) {
                Fail(ec.value(), "DNS resolve failed");
                return;
              }
              if (use_tls_) {
                ws_tls_ = std::make_unique<boost::beast::websocket::stream<
                    boost::beast::ssl_stream<boost::beast::tcp_stream>>>(
                    sig_queue_->io_context(), ssl_ctx_);
                SSL_set_tlsext_host_name(ws_tls_->next_layer().native_handle(),
                                         parsed.host.c_str());
                boost::beast::get_lowest_layer(*ws_tls_).expires_after(
                    std::chrono::seconds(10));
                boost::beast::get_lowest_layer(*ws_tls_).async_connect(
                    results,
                    SafeTask(
                        safety_.flag(),
                        [this, parsed](
                            boost::beast::error_code ec2,
                            boost::asio::ip::tcp::resolver::results_type::
                                endpoint_type) {
                          if (ec2) {
                            Fail(ec2.value(), "TCP connect failed");
                            return;
                          }
                          ws_tls_->next_layer().async_handshake(
                              boost::asio::ssl::stream_base::client,
                              SafeTask(
                                  safety_.flag(),
                                  [this, parsed](boost::beast::error_code ec3) {
                                    if (ec3) {
                                      Fail(ec3.value(), "TLS handshake failed");
                                      return;
                                    }
                                    boost::beast::get_lowest_layer(*ws_tls_)
                                        .expires_never();
                                    ws_tls_->set_option(
                                        boost::beast::websocket::stream_base::
                                            timeout::suggested(
                                                boost::beast::role_type::
                                                    client));
                                    ws_tls_->async_handshake(
                                        parsed.host, parsed.target,
                                        SafeTask(
                                            safety_.flag(),
                                            [this](
                                                boost::beast::error_code ec4) {
                                              if (ec4) {
                                                Fail(ec4.value(),
                                                     "WSS handshake failed");
                                                return;
                                              }
                                              connected_ = true;
                                              RTC_LOG(kInfo)
                                                  << "WSS signaling connected";
                                              if (on_connected_) {
                                                on_connected_();
                                              }
                                              FlushWriteQueue();
                                              DoReadLoop();
                                            }));
                                  }));
                        }));
              } else {
                ws_plain_ = std::make_unique<
                    boost::beast::websocket::stream<boost::beast::tcp_stream>>(
                    sig_queue_->io_context());
                boost::beast::get_lowest_layer(*ws_plain_).expires_after(
                    std::chrono::seconds(10));
                boost::beast::get_lowest_layer(*ws_plain_).async_connect(
                    results,
                    SafeTask(
                        safety_.flag(),
                        [this, parsed](
                            boost::beast::error_code ec2,
                            boost::asio::ip::tcp::resolver::results_type::
                                endpoint_type) {
                          if (ec2) {
                            Fail(ec2.value(), "TCP connect failed");
                            return;
                          }
                          boost::beast::get_lowest_layer(*ws_plain_)
                              .expires_never();
                          ws_plain_->set_option(
                              boost::beast::websocket::stream_base::timeout::
                                  suggested(boost::beast::role_type::client));
                          ws_plain_->async_handshake(
                              parsed.host, parsed.target,
                              SafeTask(safety_.flag(),
                                       [this](boost::beast::error_code ec3) {
                                         if (ec3) {
                                           Fail(ec3.value(),
                                                "WS handshake failed");
                                           return;
                                         }
                                         connected_ = true;
                                         RTC_LOG(kInfo)
                                             << "WS signaling connected";
                                         if (on_connected_) {
                                           on_connected_();
                                         }
                                         FlushWriteQueue();
                                         DoReadLoop();
                                       }));
                        }));
              }
            }));
  }));
}

void BoostBeastSignalingClient::SendText(const std::string& payload) {
  sig_queue_->PostTask(SafeTask(safety_.flag(), [this, payload]() {
    RTC_DCHECK_RUN_ON(&sig_checker_);
    write_queue_.push_back(payload);
    if (connected_ && !writing_) {
      FlushWriteQueue();
    }
  }));
}

void BoostBeastSignalingClient::FlushWriteQueue() {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  if (!connected_ || writing_ || write_queue_.empty()) {
    return;
  }
  writing_ = true;

  auto on_written = SafeTask(
      safety_.flag(), [this](boost::beast::error_code ec, std::size_t) {
        RTC_DCHECK_RUN_ON(&sig_checker_);
        writing_ = false;
        if (ec) {
          Fail(ec.value(), "WS write error");
          return;
        }
        write_queue_.pop_front();
        if (!write_queue_.empty()) {
          FlushWriteQueue();
        }
      });

  if (use_tls_ && ws_tls_) {
    ws_tls_->text(true);
    ws_tls_->async_write(boost::asio::buffer(write_queue_.front()),
                         std::move(on_written));
  } else if (ws_plain_) {
    ws_plain_->text(true);
    ws_plain_->async_write(boost::asio::buffer(write_queue_.front()),
                           std::move(on_written));
  }
}

void BoostBeastSignalingClient::DoReadLoop() {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  if (!connected_) {
    return;
  }

  auto on_read = SafeTask(
      safety_.flag(), [this](boost::beast::error_code ec, std::size_t) {
        RTC_DCHECK_RUN_ON(&sig_checker_);
        if (ec) {
          Fail(ec.value(), "WS closed");
          return;
        }
        const std::string msg =
            boost::beast::buffers_to_string(read_buf_.data());
        read_buf_.consume(read_buf_.size());
        if (on_message_) {
          on_message_(msg);
        }
        DoReadLoop();
      });

  if (use_tls_ && ws_tls_) {
    ws_tls_->async_read(read_buf_, std::move(on_read));
  } else if (ws_plain_) {
    ws_plain_->async_read(read_buf_, std::move(on_read));
  }
}

void BoostBeastSignalingClient::Close() {
  connected_ = false;
  if (ws_tls_) {
    boost::beast::get_lowest_layer(*ws_tls_).close();
    ws_tls_.reset();
  }
  if (ws_plain_) {
    boost::beast::get_lowest_layer(*ws_plain_).close();
    ws_plain_.reset();
  }
  write_queue_.clear();
}

void BoostBeastSignalingClient::Fail(int code, std::string_view where) {
  connected_ = false;
  RTC_LOG(kWarning) << "Signaling WebSocket closed (" << where
                    << ", code=" << code << ")";
  if (on_closed_) {
    on_closed_(code, std::string(where));
  }
}

}  // namespace rtc
