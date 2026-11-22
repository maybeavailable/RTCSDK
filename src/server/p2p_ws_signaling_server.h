#ifndef SRC_SERVER_P2P_WS_SIGNALING_SERVER_H_
#define SRC_SERVER_P2P_WS_SIGNALING_SERVER_H_

// 面向一对一 WebRTC P2P 会话配对的轻量级、零媒体面 WebSocket JSON 信令服务器
// （同时兼容嵌入式 RTCSDK 终端与 Web 浏览器），支持 `join`、`leave`、`offer`、
// `answer` 与 `candidate` 信令消息交换。

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include <boost/asio/ip/tcp.hpp>

#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"

namespace rtc {

class P2pWsSignalingServer {
 public:
  explicit P2pWsSignalingServer(std::string bind_ip = "0.0.0.0");
  ~P2pWsSignalingServer();

  P2pWsSignalingServer(const P2pWsSignalingServer&) = delete;
  P2pWsSignalingServer& operator=(const P2pWsSignalingServer&) = delete;

  bool Start(uint16_t tcp_port = 0);
  void Stop();

  uint16_t port() const { return bound_port_; }

 private:
  struct ClientConn;

  void DoAccept();
  void OnClientMessage(const std::shared_ptr<ClientConn>& sender,
                       const std::string& raw_json);
  void OnClientDisconnected(uint64_t conn_id);

  std::string bind_ip_;
  TaskQueueBoost queue_;
  SequenceChecker checker_;
  boost::asio::ip::tcp::acceptor acceptor_;
  uint16_t bound_port_ = 0;
  uint64_t next_conn_id_ = 1;
  std::map<uint64_t, std::shared_ptr<ClientConn>> clients_;
  std::atomic<bool> stopped_{true};
  ScopedTaskSafety safety_;
};

}  // namespace rtc

#endif  // SRC_SERVER_P2P_WS_SIGNALING_SERVER_H_