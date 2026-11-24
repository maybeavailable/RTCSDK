#include "server/p2p_ws_signaling_server.h"

#include <utility>

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"

namespace rtc {

struct P2pWsSignalingServer::ClientConn
    : public std::enable_shared_from_this<P2pWsSignalingServer::ClientConn> {
  uint64_t id = 0;
  P2pWsSignalingServer* srv = nullptr;
  boost::beast::websocket::stream<boost::asio::ip::tcp::socket> ws;
  boost::beast::flat_buffer rx_buf;
  std::string room_id;
  std::string peer_id;
  bool left_notified = false;

  ClientConn(uint64_t conn_id,
             P2pWsSignalingServer* parent,
             boost::asio::ip::tcp::socket sock)
      : id(conn_id), srv(parent), ws(std::move(sock)) {}

  void Start() {
    auto self = shared_from_this();
    ws.async_accept([self](boost::system::error_code ec) {
      if (ec) {
        self->srv->OnClientDisconnected(self->id);
        return;
      }
      self->DoRead();
    });
  }

  void SendText(const std::string& text) {
    boost::system::error_code ec;
    ws.text(true);
    ws.write(boost::asio::buffer(text), ec);
  }

  void ForceClose() {
    boost::system::error_code ec;
    ws.next_layer().close(ec);
  }

  void DoRead() {
    auto self = shared_from_this();
    ws.async_read(rx_buf, [self](boost::system::error_code ec, size_t /*n*/) {
      if (ec) {
        self->srv->OnClientDisconnected(self->id);
        return;
      }
      const std::string text =
          boost::beast::buffers_to_string(self->rx_buf.data());
      self->rx_buf.consume(self->rx_buf.size());
      self->srv->OnClientMessage(self, text);
      self->DoRead();
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
    bound_port_ = acceptor_.local_endpoint(ec).port();
    ok = !ec;
    if (ok) {
      stopped_.store(false, std::memory_order_release);
      DoAccept();
    }
  });
  if (ok) {
    RTC_LOG(kInfo) << "P2pWsSignalingServer listening on ws://" << bind_ip_
                   << ":" << bound_port_;
  }
  return ok;
}

void P2pWsSignalingServer::Stop() {
  bool expected = false;
  if (!stopped_.compare_exchange_strong(expected, true,
                                        std::memory_order_acq_rel)) {
    return;
  }
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
  const auto msg = JsonObject::Parse(raw_json);
  if (!msg.has_value()) {
    return;
  }
  const std::string type = msg->GetString("type");
  if (type == "join") {
    sender->room_id = msg->GetString("room_id");
    sender->peer_id = msg->GetString("peer_id");
    RTC_LOG(kInfo) << "P2P WS peer=" << sender->peer_id
                   << " joined room=" << sender->room_id;

    for (const auto& [other_id, other] : clients_) {
      if (other_id == sender->id || other->room_id != sender->room_id ||
          other->peer_id.empty()) {
        continue;
      }
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

  const std::string target_peer = msg->GetString("target_peer_id");
  for (const auto& [other_id, other] : clients_) {
    if (other_id == sender->id || other->room_id != sender->room_id) {
      continue;
    }
    if (!target_peer.empty() && other->peer_id != target_peer) {
      continue;
    }
    other->SendText(raw_json);
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
  const bool should_notify = !conn->left_notified && !peer.empty();
  conn->left_notified = true;
  clients_.erase(it);
  conn->ForceClose();

  if (should_notify) {
    JsonObject left_msg;
    left_msg.SetString("type", "peer_left");
    left_msg.SetString("room_id", room);
    left_msg.SetString("peer_id", peer);
    const std::string wire = left_msg.Serialize();
    for (const auto& [other_id, other] : clients_) {
      (void)other_id;
      if (other->room_id == room) {
        other->SendText(wire);
      }
    }
  }
}

}  // namespace rtc