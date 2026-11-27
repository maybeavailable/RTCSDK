#include "signaling/wss_signaling_client.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <iomanip>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {

int AcceptPeerCertForPinning(int /*preverify_ok*/, X509_STORE_CTX* /*ctx*/) {
  return 1;
}

std::string NormalizeSha256Hex(std::string_view input) {
  std::string out;
  out.reserve(64);
  for (unsigned char ch : input) {
    if (ch == ':' || ch == ' ' || ch == '\t') {
      continue;
    }
    if (!std::isxdigit(ch)) {
      return {};
    }
    out.push_back(static_cast<char>(std::toupper(ch)));
  }
  return (out.size() == 64) ? out : std::string{};
}

std::string ComputeLeafCertSha256Hex(X509* cert) {
  if (cert == nullptr) {
    return {};
  }
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int md_len = 0;
  if (X509_digest(cert, EVP_sha256(), md, &md_len) != 1 || md_len != 32) {
    return {};
  }
  std::ostringstream oss;
  oss << std::uppercase << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < md_len; ++i) {
    oss << std::setw(2) << static_cast<int>(md[i]);
  }
  return oss.str();
}

}  // namespace

struct BoostBeastSignalingClient::Session {
  static constexpr size_t kMaxPendingWrites = 256;
  static constexpr size_t kMaxInboundMessageBytes = 256 * 1024;

  explicit Session(boost::asio::io_context& io_ctx)
      : resolver(io_ctx),
        resolve_timer(io_ctx),
        ssl_ctx(boost::asio::ssl::context::tls_client) {
    boost::system::error_code ec;
    ssl_ctx.set_options(boost::asio::ssl::context::default_workarounds |
                            boost::asio::ssl::context::no_sslv2 |
                            boost::asio::ssl::context::no_sslv3 |
                            boost::asio::ssl::context::no_tlsv1 |
                            boost::asio::ssl::context::no_tlsv1_1,
                        ec);
    if (ec) {
      tls_init_error = "TLS options setup failed: " + ec.message();
    }
  }

  boost::asio::ip::tcp::resolver resolver;
  boost::asio::steady_timer resolve_timer;
  boost::asio::ssl::context ssl_ctx;
  std::string tls_init_error;
  std::unique_ptr<boost::beast::websocket::stream<boost::beast::tcp_stream>>
      ws_plain;
  std::unique_ptr<boost::beast::websocket::stream<
      boost::beast::ssl_stream<boost::beast::tcp_stream>>>
      ws_tls;
  boost::beast::flat_buffer read_buf;
  std::deque<std::string> write_queue;
  bool connected = false;
  bool writing = false;
  bool closed = false;
  bool use_tls = false;
};

BoostBeastSignalingClient::BoostBeastSignalingClient(
    TaskQueueBoost* signaling_queue)
    : sig_queue_(signaling_queue),
      sig_checker_(signaling_queue),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {}

BoostBeastSignalingClient::~BoostBeastSignalingClient() {
  sig_queue_->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&sig_checker_);
    safety_.flag()->SetNotAlive();
    CancelSessionStreams(session_);
    session_.reset();
  });
}

void BoostBeastSignalingClient::SetTlsOptions(
    bool verify_peer,
    std::string ca_cert_path,
    std::string pinned_cert_sha256) {
  sig_queue_->PostTask(SafeTask(
      safety_.flag(),
      [this, verify_peer, ca = std::move(ca_cert_path),
       pin = std::move(pinned_cert_sha256)]() mutable {
        RTC_DCHECK_RUN_ON(&sig_checker_);
        tls_verify_peer_ = verify_peer;
        tls_ca_cert_path_ = std::move(ca);
        tls_pinned_cert_sha256_ = std::move(pin);
      }));
}

void BoostBeastSignalingClient::CancelSessionStreams(
    const std::shared_ptr<Session>& sess) {
  if (!sess || sess->closed) {
    return;
  }
  sess->closed = true;
  sess->connected = false;
  sess->resolve_timer.cancel();
  sess->resolver.cancel();
  if (sess->ws_tls) {
    boost::beast::error_code ec;
    boost::beast::get_lowest_layer(*sess->ws_tls).cancel();
    boost::beast::get_lowest_layer(*sess->ws_tls).socket().close(ec);
  }
  if (sess->ws_plain) {
    boost::beast::error_code ec;
    boost::beast::get_lowest_layer(*sess->ws_plain).cancel();
    boost::beast::get_lowest_layer(*sess->ws_plain).socket().close(ec);
  }
}

bool BoostBeastSignalingClient::ParseWsUrl(std::string_view url,
                                           ParsedUrl* out) {
  if (out == nullptr || url.empty()) {
    return false;
  }
  while (!url.empty() && (url.front() == ' ' || url.front() == '\t')) {
    url.remove_prefix(1);
  }
  while (!url.empty() && (url.back() == ' ' || url.back() == '\t')) {
    url.remove_suffix(1);
  }
  for (unsigned char ch : url) {
    if (ch <= 0x20 || ch == 0x7F) {
      return false;
    }
  }

  auto starts_with_icase = [](std::string_view s,
                              std::string_view prefix) -> bool {
    if (s.size() < prefix.size()) {
      return false;
    }
    for (size_t i = 0; i < prefix.size(); ++i) {
      const unsigned char a = static_cast<unsigned char>(s[i]);
      const unsigned char b = static_cast<unsigned char>(prefix[i]);
      if (std::tolower(a) != std::tolower(b)) {
        return false;
      }
    }
    return true;
  };

  size_t pos = 0;
  std::string default_port;
  if (starts_with_icase(url, "wss://")) {
    out->use_tls = true;
    default_port = "443";
    pos = 6;
  } else if (starts_with_icase(url, "ws://")) {
    out->use_tls = false;
    default_port = "80";
    pos = 5;
  } else {
    return false;
  }
  out->port = default_port;
  out->is_ipv6 = false;

  const size_t delim = url.find_first_of("/?#", pos);
  const std::string_view authority =
      (delim == std::string_view::npos) ? url.substr(pos)
                                        : url.substr(pos, delim - pos);
  if (delim == std::string_view::npos) {
    out->target = "/";
  } else {
    std::string_view rest = url.substr(delim);
    const size_t hash = rest.find('#');
    if (hash != std::string_view::npos) {
      rest = rest.substr(0, hash);
    }
    if (rest.empty()) {
      out->target = "/";
    } else if (rest.front() == '/') {
      out->target = std::string(rest);
    } else {
      out->target = "/" + std::string(rest);
    }
  }

  // 严禁在 authority 中夹带 `@` userinfo 或控制字符，防止请求头注入与混淆攻击。
  if (authority.empty() || authority.find('@') != std::string_view::npos ||
      authority.find('\\') != std::string_view::npos) {
    return false;
  }
  for (unsigned char ch : out->target) {
    if (ch <= 0x20 || ch == 0x7F) {
      return false;
    }
  }

  if (authority.front() == '[') {
    const size_t rbr = authority.find(']');
    if (rbr == std::string_view::npos || rbr <= 1) {
      return false;
    }
    out->is_ipv6 = true;
    out->host = std::string(authority.substr(1, rbr - 1));
    if (rbr + 1 < authority.size()) {
      if (authority[rbr + 1] != ':') {
        return false;
      }
      const std::string_view port_sv = authority.substr(rbr + 2);
      uint16_t pnum = 0;
      if (!ParseUint16(port_sv, &pnum) || pnum == 0) {
        return false;
      }
      out->port = std::string(port_sv);
    }
  } else {
    const size_t colon = authority.rfind(':');
    if (colon != std::string_view::npos) {
      if (authority.find(':') != colon) {
        return false;
      }
      const std::string_view port_sv = authority.substr(colon + 1);
      uint16_t pnum = 0;
      if (!ParseUint16(port_sv, &pnum) || pnum == 0) {
        return false;
      }
      out->host = std::string(authority.substr(0, colon));
      out->port = std::string(port_sv);
    } else {
      out->host = std::string(authority);
    }
  }
  if (out->host.empty()) {
    return false;
  }
  for (unsigned char ch : out->host) {
    if (ch <= 0x20 || ch >= 0x7F || ch == '@' || ch == '/' || ch == '\\' ||
        ch == '?' || ch == '#' || ch == '[' || ch == ']') {
      return false;
    }
  }
  if (out->is_ipv6) {
    std::string v6_no_zone = out->host;
    const size_t pct = v6_no_zone.find('%');
    if (pct != std::string::npos) {
      if (pct == 0 || pct + 1 >= v6_no_zone.size()) {
        return false;
      }
      v6_no_zone.erase(pct);
    }
    boost::system::error_code v6_ec;
    const auto v6_addr = boost::asio::ip::make_address_v6(v6_no_zone, v6_ec);
    (void)v6_addr;
    if (v6_ec) {
      return false;
    }
  }

  const std::string bracketed_host =
      out->is_ipv6 ? ("[" + out->host + "]") : out->host;
  out->host_header = (out->port == default_port)
                         ? bracketed_host
                         : (bracketed_host + ":" + out->port);
  return true;
}

void BoostBeastSignalingClient::Connect(const std::string& url) {
  sig_queue_->PostTask(SafeTask(safety_.flag(), [this, url]() {
    RTC_DCHECK_RUN_ON(&sig_checker_);
    CancelSessionStreams(session_);
    auto sess = std::make_shared<Session>(sig_queue_->io_context());
    session_ = sess;

    ParsedUrl parsed;
    if (!ParseWsUrl(url, &parsed)) {
      Fail(sess, -1, "Invalid ws/wss URL");
      return;
    }
    sess->use_tls = parsed.use_tls;

    const std::string ca_path = tls_ca_cert_path_;
    std::string expected_pin_hex;
    if (!tls_pinned_cert_sha256_.empty()) {
      expected_pin_hex = NormalizeSha256Hex(tls_pinned_cert_sha256_);
      if (expected_pin_hex.empty()) {
        Fail(sess, -1, "Invalid pinned TLS SHA-256 certificate fingerprint");
        return;
      }
    }
    const bool verify_chain =
        tls_verify_peer_ && (expected_pin_hex.empty() || !ca_path.empty());

    if (sess->use_tls) {
      if (!sess->tls_init_error.empty()) {
        Fail(sess, -2, sess->tls_init_error);
        return;
      }
      boost::system::error_code tls_ec;
      if (verify_chain) {
        if (!ca_path.empty()) {
          sess->ssl_ctx.load_verify_file(ca_path, tls_ec);
          if (tls_ec) {
            Fail(sess, tls_ec.value(), "Failed to load TLS CA certificate");
            return;
          }
        } else {
          sess->ssl_ctx.set_default_verify_paths(tls_ec);
          if (tls_ec) {
            Fail(sess, tls_ec.value(),
                 "Failed to configure default TLS CA verify paths");
            return;
          }
        }
        sess->ssl_ctx.set_verify_mode(boost::asio::ssl::verify_peer, tls_ec);
        if (tls_ec) {
          Fail(sess, tls_ec.value(), "Failed to set TLS verify_peer mode");
          return;
        }
      } else if (!expected_pin_hex.empty()) {
        sess->ssl_ctx.set_verify_mode(boost::asio::ssl::verify_peer, tls_ec);
        if (tls_ec) {
          Fail(sess, tls_ec.value(), "Failed to set TLS pinning verify mode");
          return;
        }
        SSL_CTX_set_verify(sess->ssl_ctx.native_handle(),
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           &AcceptPeerCertForPinning);
      } else {
        sess->ssl_ctx.set_verify_mode(boost::asio::ssl::verify_none, tls_ec);
      }
    }

    RTC_LOG(kInfo) << "Connecting signaling WebSocket to " << url;

    const auto flag = safety_.flag();
    sess->resolve_timer.expires_after(std::chrono::seconds(10));
    sess->resolve_timer.async_wait(
        [this, flag, sess](boost::beast::error_code timer_ec) {
          if (timer_ec || sess->closed || !flag || !flag->alive()) {
            return;
          }
          RTC_DCHECK_RUN_ON(&sig_checker_);
          Fail(sess, boost::asio::error::timed_out, "DNS resolve timed out");
        });

    sess->resolver.async_resolve(
        parsed.host, parsed.port,
        [this, flag, sess, parsed, verify_chain, expected_pin_hex](
            boost::beast::error_code ec,
            boost::asio::ip::tcp::resolver::results_type results) {
          if (sess->closed || !flag || !flag->alive()) {
            return;
          }
          RTC_DCHECK_RUN_ON(&sig_checker_);
          sess->resolve_timer.cancel();
          if (ec) {
            Fail(sess, ec.value(), "DNS resolve failed");
            return;
          }
          if (sess->use_tls) {
            sess->ws_tls = std::make_unique<boost::beast::websocket::stream<
                boost::beast::ssl_stream<boost::beast::tcp_stream>>>(
                sig_queue_->io_context(), sess->ssl_ctx);
            sess->ws_tls->read_message_max(Session::kMaxInboundMessageBytes);
            SSL* ssl_handle = sess->ws_tls->next_layer().native_handle();
            if (ssl_handle == nullptr) {
              Fail(sess, -2, "Missing OpenSSL handle");
              return;
            }

            std::string host_no_zone = parsed.host;
            if (parsed.is_ipv6) {
              const size_t pct = host_no_zone.find('%');
              if (pct != std::string::npos) {
                host_no_zone.erase(pct);
              }
            }
            boost::system::error_code ip_ec;
            const auto parsed_ip =
                boost::asio::ip::make_address(host_no_zone, ip_ec);
            (void)parsed_ip;
            if (ip_ec) {
              if (SSL_set_tlsext_host_name(ssl_handle, host_no_zone.c_str()) !=
                  1) {
                Fail(sess, -2, "SSL_set_tlsext_host_name failed");
                return;
              }
              if (verify_chain) {
                SSL_set_hostflags(ssl_handle,
                                  X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                if (SSL_set1_host(ssl_handle, host_no_zone.c_str()) != 1) {
                  Fail(sess, -2, "SSL_set1_host failed");
                  return;
                }
              }
            } else if (verify_chain) {
              X509_VERIFY_PARAM* vpm = SSL_get0_param(ssl_handle);
              if (vpm == nullptr ||
                  X509_VERIFY_PARAM_set1_ip_asc(vpm, host_no_zone.c_str()) !=
                      1) {
                Fail(sess, -2, "X509_VERIFY_PARAM_set1_ip_asc failed");
                return;
              }
            }

            boost::beast::get_lowest_layer(*sess->ws_tls)
                .expires_after(std::chrono::seconds(10));
            boost::beast::get_lowest_layer(*sess->ws_tls)
                .async_connect(
                    results,
                    [this, flag, sess, parsed, expected_pin_hex](
                        boost::beast::error_code ec2,
                        boost::asio::ip::tcp::resolver::results_type::
                            endpoint_type) {
                      if (sess->closed || !flag || !flag->alive()) {
                        return;
                      }
                      RTC_DCHECK_RUN_ON(&sig_checker_);
                      if (ec2) {
                        Fail(sess, ec2.value(), "TCP connect failed");
                        return;
                      }
                      boost::beast::get_lowest_layer(*sess->ws_tls)
                          .expires_after(std::chrono::seconds(10));
                      sess->ws_tls->next_layer().async_handshake(
                          boost::asio::ssl::stream_base::client,
                          [this, flag, sess, parsed,
                           expected_pin_hex](boost::beast::error_code ec3) {
                            if (sess->closed || !flag || !flag->alive()) {
                              return;
                            }
                            RTC_DCHECK_RUN_ON(&sig_checker_);
                            if (ec3) {
                              Fail(sess, ec3.value(), "TLS handshake failed");
                              return;
                            }
                            if (!expected_pin_hex.empty()) {
                              X509* peer_cert = SSL_get1_peer_certificate(
                                  sess->ws_tls->next_layer().native_handle());
                              const std::string actual_hex =
                                  ComputeLeafCertSha256Hex(peer_cert);
                              if (peer_cert != nullptr) {
                                X509_free(peer_cert);
                              }
                              if (actual_hex != expected_pin_hex) {
                                Fail(sess, -3,
                                     "TLS pinned certificate SHA-256 mismatch");
                                return;
                              }
                            }
                            boost::beast::get_lowest_layer(*sess->ws_tls)
                                .expires_never();
                            auto ws_timeout = boost::beast::websocket::
                                stream_base::timeout::suggested(
                                    boost::beast::role_type::client);
                            ws_timeout.idle_timeout = std::chrono::seconds(60);
                            ws_timeout.keep_alive_pings = true;
                            sess->ws_tls->set_option(ws_timeout);
                            sess->ws_tls->async_handshake(
                                parsed.host_header, parsed.target,
                                [this, flag,
                                 sess](boost::beast::error_code ec4) {
                                  if (sess->closed || !flag || !flag->alive()) {
                                    return;
                                  }
                                  RTC_DCHECK_RUN_ON(&sig_checker_);
                                  if (ec4) {
                                    Fail(sess, ec4.value(),
                                         "WSS handshake failed");
                                    return;
                                  }
                                  sess->connected = true;
                                  RTC_LOG(kInfo) << "WSS signaling connected";
                                  std::function<void()> cb;
                                  {
                                    std::lock_guard<std::mutex> lk(cb_mu_);
                                    cb = on_connected_;
                                  }
                                  if (cb) {
                                    cb();
                                  }
                                  if (!sess->closed) {
                                    FlushWriteQueue(sess);
                                    DoReadLoop(sess);
                                  }
                                });
                          });
                    });
          } else {
            sess->ws_plain = std::make_unique<
                boost::beast::websocket::stream<boost::beast::tcp_stream>>(
                sig_queue_->io_context());
            sess->ws_plain->read_message_max(Session::kMaxInboundMessageBytes);
            boost::beast::get_lowest_layer(*sess->ws_plain)
                .expires_after(std::chrono::seconds(10));
            boost::beast::get_lowest_layer(*sess->ws_plain)
                .async_connect(
                    results,
                    [this, flag, sess, parsed](
                        boost::beast::error_code ec2,
                        boost::asio::ip::tcp::resolver::results_type::
                            endpoint_type) {
                      if (sess->closed || !flag || !flag->alive()) {
                        return;
                      }
                      RTC_DCHECK_RUN_ON(&sig_checker_);
                      if (ec2) {
                        Fail(sess, ec2.value(), "TCP connect failed");
                        return;
                      }
                      boost::beast::get_lowest_layer(*sess->ws_plain)
                          .expires_never();
                      auto ws_timeout =
                          boost::beast::websocket::stream_base::timeout::
                              suggested(boost::beast::role_type::client);
                      ws_timeout.idle_timeout = std::chrono::seconds(60);
                      ws_timeout.keep_alive_pings = true;
                      sess->ws_plain->set_option(ws_timeout);
                      sess->ws_plain->async_handshake(
                          parsed.host_header, parsed.target,
                          [this, flag, sess](boost::beast::error_code ec3) {
                            if (sess->closed || !flag || !flag->alive()) {
                              return;
                            }
                            RTC_DCHECK_RUN_ON(&sig_checker_);
                            if (ec3) {
                              Fail(sess, ec3.value(), "WS handshake failed");
                              return;
                            }
                            sess->connected = true;
                            RTC_LOG(kInfo) << "WS signaling connected";
                            std::function<void()> cb;
                            {
                              std::lock_guard<std::mutex> lk(cb_mu_);
                              cb = on_connected_;
                            }
                            if (cb) {
                              cb();
                            }
                            if (!sess->closed) {
                              FlushWriteQueue(sess);
                              DoReadLoop(sess);
                            }
                          });
                    });
          }
        });
  }));
}

void BoostBeastSignalingClient::SendText(const std::string& payload) {
  if (payload.size() > Session::kMaxInboundMessageBytes) {
    return;
  }
  sig_queue_->PostTask(SafeTask(safety_.flag(), [this, payload]() {
    RTC_DCHECK_RUN_ON(&sig_checker_);
    if (!session_ || session_->closed) {
      return;
    }
    if (session_->write_queue.size() >= Session::kMaxPendingWrites) {
      RTC_LOG(kWarning)
          << "Signaling write queue full, dropping outbound message";
      return;
    }
    session_->write_queue.push_back(payload);
    if (session_->connected && !session_->writing) {
      FlushWriteQueue(session_);
    }
  }));
}

void BoostBeastSignalingClient::FlushWriteQueue(
    const std::shared_ptr<Session>& sess) {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  if (!sess || sess->closed || !sess->connected || sess->writing ||
      sess->write_queue.empty()) {
    return;
  }
  sess->writing = true;

  const auto flag = safety_.flag();
  auto on_written = [this, flag, sess](boost::beast::error_code ec,
                                       std::size_t) {
    if (sess->closed || !flag || !flag->alive()) {
      return;
    }
    RTC_DCHECK_RUN_ON(&sig_checker_);
    sess->writing = false;
    if (ec) {
      Fail(sess, ec.value(), "WS write error");
      return;
    }
    if (!sess->write_queue.empty()) {
      sess->write_queue.pop_front();
    }
    if (!sess->write_queue.empty()) {
      FlushWriteQueue(sess);
    }
  };

  if (sess->use_tls && sess->ws_tls) {
    sess->ws_tls->text(true);
    sess->ws_tls->async_write(boost::asio::buffer(sess->write_queue.front()),
                              std::move(on_written));
  } else if (sess->ws_plain) {
    sess->ws_plain->text(true);
    sess->ws_plain->async_write(boost::asio::buffer(sess->write_queue.front()),
                                std::move(on_written));
  }
}

void BoostBeastSignalingClient::DoReadLoop(
    const std::shared_ptr<Session>& sess) {
  RTC_DCHECK_RUN_ON(&sig_checker_);
  if (!sess || sess->closed || !sess->connected) {
    return;
  }

  const auto flag = safety_.flag();
  auto on_read = [this, flag, sess](boost::beast::error_code ec, std::size_t) {
    if (sess->closed || !flag || !flag->alive()) {
      return;
    }
    RTC_DCHECK_RUN_ON(&sig_checker_);
    if (ec) {
      Fail(sess, ec.value(), "WS closed");
      return;
    }
    const std::string msg =
        boost::beast::buffers_to_string(sess->read_buf.data());
    sess->read_buf.consume(sess->read_buf.size());
    std::function<void(const std::string&)> cb;
    {
      std::lock_guard<std::mutex> lk(cb_mu_);
      cb = on_message_;
    }
    if (cb) {
      cb(msg);
    }
    if (!sess->closed) {
      DoReadLoop(sess);
    }
  };

  if (sess->use_tls && sess->ws_tls) {
    sess->ws_tls->async_read(sess->read_buf, std::move(on_read));
  } else if (sess->ws_plain) {
    sess->ws_plain->async_read(sess->read_buf, std::move(on_read));
  }
}

void BoostBeastSignalingClient::Close() {
  sig_queue_->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&sig_checker_);
    CancelSessionStreams(session_);
    session_.reset();
    safety_.Reset(PendingTaskSafetyFlag::CreateDetached());
  });
}

void BoostBeastSignalingClient::Fail(const std::shared_ptr<Session>& sess,
                                     int code,
                                     std::string_view where) {
  if (!sess || sess->closed) {
    return;
  }
  CancelSessionStreams(sess);
  if (session_ == sess) {
    session_.reset();
  }
  RTC_LOG(kWarning) << "Signaling WebSocket closed (" << where
                    << ", code=" << code << ")";
  std::function<void(int, const std::string&)> cb;
  {
    std::lock_guard<std::mutex> lk(cb_mu_);
    cb = on_closed_;
  }
  if (cb) {
    cb(code, std::string(where));
  }
}

}  // namespace rtc
