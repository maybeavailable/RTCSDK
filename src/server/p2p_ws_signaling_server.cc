#include "server/p2p_ws_signaling_server.h"

#include <deque>
#include <utility>
#include <vector>

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {

constexpr size_t kMaxPeersPerP2pRoom = 2;

bool ConstantTimeWsTokenEquals(std::string_view candidate,
                               std::string_view expected) {
  unsigned char d1[SHA256_DIGEST_LENGTH];
  unsigned char d2[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(candidate.data()),
         candidate.size(), d1);
  SHA256(reinterpret_cast<const unsigned char*>(expected.data()),
         expected.size(), d2);
  const int digest_eq = (CRYPTO_memcmp(d1, d2, SHA256_DIGEST_LENGTH) == 0);
  const int len_eq = (candidate.size() == expected.size());
  return (digest_eq & len_eq) != 0;
}

std::string MakeErrorJson(std::string_view code, std::string_view message) {
  JsonObject err;
  err.SetString("type", "error");
  err.SetString("code", code);
  err.SetString("message", message);
  return err.Serialize();
}

}  // namespace

struct P2pWsSignalingServer::ClientConn
    : public std::enable_shared_from_this<P2pWsSignalingServer::ClientConn> {
  static constexpr size_t kMaxPendingTxMessages = 256;
  static constexpr size_t kMaxInboundMessageBytes = 256 * 1024;

  uint64_t id = 0;
  P2pWsSignalingServer* srv = nullptr;
  boost::beast::websocket::stream<boost::beast::tcp_stream> ws;
  boost::beast::flat_buffer rx_buf;
  std::deque<std::shared_ptr<std::string>> tx_queue;
  bool writing = false;
  bool closing_after_write = false;
  bool closed = false;
  std::string room_id;
  std::string peer_id;
  bool left_notified = false;

  ClientConn(uint64_t conn_id,
             P2pWsSignalingServer* parent,
             boost::asio::ip::tcp::socket sock)
      : id(conn_id), srv(parent), ws(std::move(sock)) {
    ws.read_message_max(kMaxInboundMessageBytes);
    ws.set_option(boost::beast::websocket::stream_base::timeout::suggested(
        boost::beast::role_type::server));
  }

  void Start() {
    auto self = shared_from_this();
    ws.async_accept([self](boost::system::error_code ec) {
      if (self->closed) {
        return;
      }
      if (ec) {
        self->srv->OnClientDisconnected(self->id);
        return;
      }
      self->DoRead();
    });
  }

  void SendText(const std::string& text) {
    if (closed || closing_after_write) {
      return;
    }
    if (tx_queue.size() >= kMaxPendingTxMessages) {
      RTC_LOG(kWarning) << "P2P WS client conn=" << id
                        << " exceeded write queue limit, scheduling disconnect";
      ForceClose();
      const uint64_t conn_id = id;
      P2pWsSignalingServer* parent = srv;
      parent->queue_.PostTask(
          SafeTask(parent->safety_.flag(),
                   [parent, conn_id]() { parent->OnClientDisconnected(conn_id); }));
      return;
    }
    tx_queue.push_back(std::make_shared<std::string>(text));
    if (!writing) {
      DoWrite();
    }
  }

  void SendFinalErrorAndClose(const std::string& error_json) {
    if (closed || closing_after_write) {
      return;
    }
    closing_after_write = true;
    tx_queue.push_back(std::make_shared<std::string>(error_json));
    if (!writing) {
      DoWrite();
    }
  }

  void DoWrite() {
    if (closed || writing || tx_queue.empty()) {
      return;
    }
    writing = true;
    ws.text(true);
    auto self = shared_from_this();
    auto active_msg = tx_queue.front();
    ws.async_write(
        boost::asio::buffer(*active_msg),
        [self, active_msg](boost::system::error_code ec, size_t /*bytes*/) {
          self->writing = false;
          if (self->closed) {
            return;
          }
          if (ec) {
            self->srv->OnClientDisconnected(self->id);
            return;
          }
          if (!self->tx_queue.empty() &&
              self->tx_queue.front() == active_msg) {
            self->tx_queue.pop_front();
          }
          if (!self->tx_queue.empty()) {
            self->DoWrite();
            return;
          }
          if (self->closing_after_write) {
            self->ws.async_close(
                boost::beast::websocket::close_code::policy_error,
                [self](boost::system::error_code /*close_ec*/) {
                  if (!self->closed) {
                    self->srv->OnClientDisconnected(self->id);
                  }
                });
          }
        });
  }

  void ForceClose() {
    if (closed) {
      return;
    }
    closed = true;
    tx_queue.clear();
    boost::system::error_code ec;
    boost::beast::get_lowest_layer(ws).cancel();
    boost::beast::get_lowest_layer(ws).socket().close(ec);
  }

  void DoRead() {
    if (closed || closing_after_write) {
      return;
    }
    auto self = shared_from_this();
    ws.async_read(rx_buf, [self](boost::system::error_code ec, size_t /*n*/) {
      if (self->closed || self->closing_after_write) {
        return;
      }
      if (ec) {
        self->srv->OnClientDisconnected(self->id);
        return;
      }
      const std::string text =
          boost::beast::buffers_to_string(self->rx_buf.data());
      self->rx_buf.consume(self->rx_buf.size());
      self->srv->OnClientMessage(self, text);
      if (!self->closed && !self->closing_after_write) {
        self->DoRead();
      }
    });
  }
};

P2pWsSignalingServer::P2pWsSignalingServer(std::string bind_ip)
    : bind_ip_(std::move(bind_ip)),
      queue_("p2p-ws-sig", TaskQueuePriority::kNormal),
      checker_(&queue_),
      acceptor_(queue_.io_context()),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {}

P2pWsSignalingServer::~P2pWsSignalingServer() { Stop(); }

void P2pWsSignalingServer::SetRequiredAuthToken(std::string token) {
  std::lock_guard<std::mutex> lock(auth_mu_);
  required_auth_token_ = std::move(token);
}

std::string P2pWsSignalingServer::GetRequiredAuthTokenCopy() const {
  std::lock_guard<std::mutex> lock(auth_mu_);
  return required_auth_token_;
}

void P2pWsSignalingServer::RejectClientWithError(
    const std::shared_ptr<ClientConn>& client,
    std::string_view code,
    std::string_view message) {
  RTC_DCHECK_RUN_ON(&checker_);
  if (!client || client->closed) {
    return;
  }
  client->SendFinalErrorAndClose(MakeErrorJson(code, message));
  const uint64_t cid = client->id;
  queue_.PostDelayedTask(
      SafeTask(safety_.flag(),
               [this, cid]() {
                 RTC_DCHECK_RUN_ON(&checker_);
                 OnClientDisconnected(cid);
               }),
      TimeDelta::Millis(1000));
}

bool P2pWsSignalingServer::Start(uint16_t tcp_port) {
  bool ok = false;
  queue_.Invoke([this, tcp_port, &ok]() {
    RTC_DCHECK_RUN_ON(&checker_);
    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(bind_ip_, ec);
    if (ec) {
      return;
    }
    const boost::asio::ip::tcp::endpoint ep(addr, tcp_port);
    acceptor_.open(ep.protocol(), ec);
    if (ec) {
      return;
    }
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
    acceptor_.bind(ep, ec);
    if (ec) {
      acceptor_.close(ec);
      return;
    }
    acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
      acceptor_.close(ec);
      return;
    }
    const uint16_t p = acceptor_.local_endpoint(ec).port();
    ok = !ec;
    if (ok) {
      bound_port_.store(p, std::memory_order_release);
      stopped_.store(false, std::memory_order_release);
      DoAccept();
    } else {
      acceptor_.close(ec);
    }
  });
  if (ok) {
    RTC_LOG(kInfo) << "P2pWsSignalingServer listening on ws://" << bind_ip_
                   << ":" << port();
  }
  return ok;
}

void P2pWsSignalingServer::Stop() {
  bool expected = false;
  if (!stopped_.compare_exchange_strong(expected, true,
                                        std::memory_order_acq_rel)) {
    return;
  }
  bound_port_.store(0, std::memory_order_release);
  queue_.Invoke([this]() {
    RTC_DCHECK_RUN_ON(&checker_);
    safety_.flag()->SetNotAlive();
    boost::system::error_code ec;
    acceptor_.close(ec);
    for (auto& [id, conn] : clients_) {
      (void)id;
      conn->ForceClose();
    }
    clients_.clear();
  });
  queue_.Shutdown();
}

void P2pWsSignalingServer::DoAccept() {
  RTC_DCHECK_RUN_ON(&checker_);
  acceptor_.async_accept(SafeTask(
      safety_.flag(),
      [this](boost::system::error_code ec, boost::asio::ip::tcp::socket sock) {
        RTC_DCHECK_RUN_ON(&checker_);
        if (ec) {
          return;
        }
        constexpr size_t kMaxSignalingClients = 4096;
        if (clients_.size() >= kMaxSignalingClients) {
          boost::system::error_code close_ec;
          sock.close(close_ec);
          DoAccept();
          return;
        }
        const uint64_t cid = next_conn_id_++;
        auto conn = std::make_shared<ClientConn>(cid, this, std::move(sock));
        clients_.emplace(cid, conn);
        conn->Start();
        DoAccept();
      }));
}

void P2pWsSignalingServer::OnClientMessage(
    const std::shared_ptr<ClientConn>& sender,
    const std::string& raw_json) {
  RTC_DCHECK_RUN_ON(&checker_);
  if (!sender || sender->closed || sender->closing_after_write) {
    return;
  }
  const auto msg = JsonObject::Parse(raw_json);
  if (!msg.has_value()) {
    sender->SendText(MakeErrorJson("invalid_json", "malformed JSON payload"));
    return;
  }
  const std::string type = msg->GetString("type");
  if (type == "join") {
    const std::string required_token = GetRequiredAuthTokenCopy();
    if (!required_token.empty()) {
      std::string client_token = msg->GetString("token");
      if (client_token.empty()) {
        client_token = msg->GetString("auth_token");
      }
      if (!ConstantTimeWsTokenEquals(client_token, required_token)) {
        RTC_LOG(kWarning) << "P2P WS rejected unauthorized join on conn="
                          << sender->id;
        RejectClientWithError(sender, "unauthorized",
                              "invalid or missing auth token");
        return;
      }
    }

    const std::string new_room = msg->GetString("room_id");
    const std::string new_peer = msg->GetString("peer_id");
    if (new_room.empty() || new_room.size() > 256 || new_peer.empty() ||
        new_peer.size() > 256) {
      RejectClientWithError(sender, "bad_request",
                            "invalid room_id or peer_id");
      return;
    }

    if (sender->room_id == new_room && sender->peer_id == new_peer) {
      return;
    }

    // 校验目标房间内是否已存在相同 peer_id 或已达到 1v1 房间 2 人上限（严禁破坏活跃 1v1 配对）。
    std::vector<std::shared_ptr<ClientConn>> room_peers;
    for (const auto& [other_id, other] : clients_) {
      if (other_id == sender->id || other->closed ||
          other->closing_after_write || other->room_id != new_room ||
          other->peer_id.empty()) {
        continue;
      }
      if (other->peer_id == new_peer) {
        RTC_LOG(kWarning) << "P2P WS rejected duplicate peer_id='" << new_peer
                          << "' in room='" << new_room << "'";
        RejectClientWithError(sender, "duplicate_peer_id",
                              "peer_id already exists in room");
        return;
      }
      room_peers.push_back(other);
    }
    if (room_peers.size() >= kMaxPeersPerP2pRoom) {
      RTC_LOG(kWarning) << "P2P WS rejected 3rd peer='" << new_peer
                        << "' for full 1v1 room='" << new_room << "'";
      RejectClientWithError(sender, "room_full",
                            "1v1 signaling room already has 2 active peers");
      return;
    }

    if (!sender->room_id.empty() &&
        (sender->room_id != new_room || sender->peer_id != new_peer)) {
      JsonObject left_old;
      left_old.SetString("type", "peer_left");
      left_old.SetString("room_id", sender->room_id);
      left_old.SetString("peer_id", sender->peer_id);
      const std::string left_wire = left_old.Serialize();
      std::vector<std::shared_ptr<ClientConn>> old_peers;
      for (const auto& [other_id, other] : clients_) {
        if (other_id != sender->id && !other->closed &&
            !other->closing_after_write &&
            other->room_id == sender->room_id) {
          old_peers.push_back(other);
        }
      }
      for (const auto& p : old_peers) {
        p->SendText(left_wire);
      }
    }
    sender->room_id = new_room;
    sender->peer_id = new_peer;
    sender->left_notified = false;
    RTC_LOG(kInfo) << "P2P WS peer=" << sender->peer_id
                   << " joined room=" << sender->room_id;

    for (const auto& other : room_peers) {
      JsonObject notify_existing;
      notify_existing.SetString("type", "peer_joined");
      notify_existing.SetString("peer_id", sender->peer_id);
      notify_existing.SetUint32("initiator", 1);
      other->SendText(notify_existing.Serialize());

      JsonObject notify_new;
      notify_new.SetString("type", "peer_joined");
      notify_new.SetString("peer_id", other->peer_id);
      notify_new.SetUint32("initiator", 0);
      sender->SendText(notify_new.Serialize());
    }
    return;
  }

  if (type == "leave") {
    OnClientDisconnected(sender->id);
    return;
  }

  if (sender->room_id.empty() || sender->peer_id.empty()) {
    sender->SendText(
        MakeErrorJson("not_joined", "client must join a room first"));
    return;
  }

  // 严格白名单过滤客户端可转发信令类型，禁止伪造 peer_joined / peer_left 等服务端控制事件。
  if (type != "offer" && type != "answer" && type != "candidate") {
    sender->SendText(
        MakeErrorJson("unsupported_type", "unsupported signaling message type"));
    return;
  }

  // 校验客户端声明的 peer_id 与服务端会话身份一致，并在转发前由服务端强制覆写盖章。
  const std::string claimed_peer = msg->GetString("peer_id");
  if (!claimed_peer.empty() && claimed_peer != sender->peer_id) {
    sender->SendText(MakeErrorJson(
        "peer_id_mismatch", "claimed peer_id does not match joined identity"));
    return;
  }

  JsonObject stamped = *msg;
  stamped.SetString("peer_id", sender->peer_id);
  stamped.SetString("room_id", sender->room_id);
  const std::string stamped_wire = stamped.Serialize();

  const std::string target_peer = msg->GetString("target_peer_id");
  std::vector<std::shared_ptr<ClientConn>> targets;
  for (const auto& [other_id, other] : clients_) {
    if (other_id == sender->id || other->closed ||
        other->closing_after_write || other->room_id != sender->room_id ||
        other->peer_id.empty()) {
      continue;
    }
    if (!target_peer.empty() && other->peer_id != target_peer) {
      continue;
    }
    targets.push_back(other);
  }
  for (const auto& t : targets) {
    t->SendText(stamped_wire);
  }
}

void P2pWsSignalingServer::OnClientDisconnected(uint64_t conn_id) {
  RTC_DCHECK_RUN_ON(&checker_);
  const auto it = clients_.find(conn_id);
  if (it == clients_.end()) {
    return;
  }
  auto conn = it->second;
  const std::string room = conn->room_id;
  const std::string peer = conn->peer_id;
  const bool should_notify =
      !conn->left_notified && !room.empty() && !peer.empty();
  conn->left_notified = true;
  clients_.erase(it);
  conn->ForceClose();

  if (should_notify) {
    JsonObject left_msg;
    left_msg.SetString("type", "peer_left");
    left_msg.SetString("room_id", room);
    left_msg.SetString("peer_id", peer);
    const std::string wire = left_msg.Serialize();
    std::vector<std::shared_ptr<ClientConn>> targets;
    for (const auto& [other_id, other] : clients_) {
      (void)other_id;
      if (other->room_id == room) {
        targets.push_back(other);
      }
    }
    for (const auto& t : targets) {
      t->SendText(wire);
    }
  }
}

}  // namespace rtc
