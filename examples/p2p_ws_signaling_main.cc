#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"
#include "server/p2p_ws_signaling_server.h"
#include "server/stun_turn_relay_server.h"

namespace {

std::atomic<bool> g_stop{false};

void SignalHandler(int /*sig*/) { g_stop.store(true); }

bool WritePortFile(const std::string& path, uint16_t port) {
  if (path.empty()) {
    return true;
  }
  FILE* fp = std::fopen(path.c_str(), "w");
  if (fp == nullptr) {
    return false;
  }
  std::fprintf(fp, "%u\n", static_cast<unsigned>(port));
  std::fclose(fp);
  return true;
}

void PrintUsage(const char* prog_name) {
  std::fprintf(
      stdout,
      "用法: %s [bind_ip] [ws_port] [选项]\n"
      "\n"
      "说明:\n"
      "  默认仅启动零媒体纯 JSON WebSocket 1v1 P2P 信令服务；\n"
      "  传入 --enable-turn 时，在同一进程内同步开启对标 coturn 的\n"
      "  RFC 5389 STUN + RFC 5766 TURN UDP 穿透与中继转发服务。\n"
      "\n"
      "信令服务选项:\n"
      "  --bind-ip <ip>             WebSocket 信令监听地址（默认 0.0.0.0）\n"
      "  --ws-port <port>           WebSocket 信令监听端口（默认 9002，0 为随机端口）\n"
      "  --port-file <path>         将实际绑定的信令端口写入指定文件\n"
      "\n"
      "可选内置 STUN / TURN 中继服务选项（默认关闭）:\n"
      "  --enable-turn              开启内置 STUN / TURN UDP 中继转发服务\n"
      "  --enable-stun-turn         等同于 --enable-turn\n"
      "  --turn-bind-ip <ip>        STUN/TURN 监听与中继套接字绑定地址（默认同 bind_ip）\n"
      "  --turn-port <port>         STUN/TURN 控制端口（默认 3478，0 为随机端口）\n"
      "  --turn-port-file <path>    将实际绑定的 STUN/TURN 端口写入指定文件\n"
      "  --external-ip <ip>         云主机弹性公网 IPv4（写入 XOR-RELAYED-ADDRESS 并启用发卡弯直通）\n"
      "  --realm <realm>            TURN 鉴权域（默认 rtc.local）\n"
      "  --turn-user <user:pass>    添加静态长期凭证账号（可重复指定多次）\n"
      "  --turn-rest-secret <sec>   开启兼容 coturn 的 TURN REST API 动态时效 HMAC-SHA1 鉴权密钥\n"
      "  --min-port <port>          TURN 中继 UDP 端口池下界（默认 49152）\n"
      "  --max-port <port>          TURN 中继 UDP 端口池上界（默认 65535）\n"
      "  --default-lifetime <sec>   TURN 分配默认续期时长（默认 600 秒）\n"
      "  --max-lifetime <sec>       TURN 分配最大续期时长（默认 3600 秒）\n"
      "  --max-allocations <num>    最大并发 TURN 中继会话数（默认 2048）\n"
      "  --no-loopback-peers        禁止向 127.0.0.0/8 环回地址转发（公网生产防 SSRF 推荐开启）\n"
      "  -h, --help                 打印本帮助说明\n",
      prog_name != nullptr ? prog_name : "rtc_p2p_ws_signaling_server");
}

}  // namespace

int main(int argc, char** argv) {
  std::string bind_ip = "0.0.0.0";
  uint16_t ws_port = 9002;
  std::string port_file;

  bool enable_turn = false;
  bool has_custom_turn_bind_ip = false;
  std::string turn_port_file;
  rtc::StunTurnServerConfig turn_cfg;

  int positional_idx = 0;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "-h" || arg == "--help") {
      PrintUsage(argv[0]);
      return 0;
    } else if (arg == "--bind-ip" && i + 1 < argc) {
      bind_ip = argv[++i];
    } else if (arg == "--ws-port" && i + 1 < argc) {
      if (!rtc::ParseUint16(argv[++i], &ws_port)) {
        std::fprintf(stderr, "无效的 --ws-port 参数: %s\n", argv[i]);
        return 1;
      }
    } else if (arg == "--port-file" && i + 1 < argc) {
      port_file = argv[++i];
    } else if (arg == "--enable-turn" || arg == "--enable-stun-turn") {
      enable_turn = true;
    } else if (arg == "--turn-bind-ip" && i + 1 < argc) {
      turn_cfg.bind_ip = argv[++i];
      turn_cfg.relay_bind_ip = turn_cfg.bind_ip;
      has_custom_turn_bind_ip = true;
    } else if (arg == "--turn-port" && i + 1 < argc) {
      if (!rtc::ParseUint16(argv[++i], &turn_cfg.port)) {
        std::fprintf(stderr, "无效的 --turn-port 参数: %s\n", argv[i]);
        return 1;
      }
    } else if (arg == "--turn-port-file" && i + 1 < argc) {
      turn_port_file = argv[++i];
    } else if (arg == "--external-ip" && i + 1 < argc) {
      turn_cfg.external_ip = argv[++i];
    } else if (arg == "--realm" && i + 1 < argc) {
      turn_cfg.realm = argv[++i];
    } else if (arg == "--turn-user" && i + 1 < argc) {
      const std::string_view user_spec(argv[++i]);
      const size_t colon = user_spec.find(':');
      if (colon == std::string_view::npos || colon == 0 ||
          colon + 1 >= user_spec.size()) {
        std::fprintf(stderr,
                     "无效的 --turn-user 格式（应为 username:password）: %s\n",
                     argv[i]);
        return 1;
      }
      turn_cfg.static_users[std::string(user_spec.substr(0, colon))] =
          std::string(user_spec.substr(colon + 1));
    } else if (arg == "--turn-rest-secret" && i + 1 < argc) {
      turn_cfg.rest_api_secret = argv[++i];
    } else if (arg == "--min-port" && i + 1 < argc) {
      if (!rtc::ParseUint16(argv[++i], &turn_cfg.min_relay_port)) {
        std::fprintf(stderr, "无效的 --min-port 参数: %s\n", argv[i]);
        return 1;
      }
    } else if (arg == "--max-port" && i + 1 < argc) {
      if (!rtc::ParseUint16(argv[++i], &turn_cfg.max_relay_port)) {
        std::fprintf(stderr, "无效的 --max-port 参数: %s\n", argv[i]);
        return 1;
      }
    } else if (arg == "--default-lifetime" && i + 1 < argc) {
      if (!rtc::ParseUint32(argv[++i], &turn_cfg.default_lifetime_sec) ||
          turn_cfg.default_lifetime_sec == 0) {
        std::fprintf(stderr, "无效的 --default-lifetime 参数: %s\n", argv[i]);
        return 1;
      }
    } else if (arg == "--max-lifetime" && i + 1 < argc) {
      if (!rtc::ParseUint32(argv[++i], &turn_cfg.max_lifetime_sec) ||
          turn_cfg.max_lifetime_sec == 0) {
        std::fprintf(stderr, "无效的 --max-lifetime 参数: %s\n", argv[i]);
        return 1;
      }
    } else if (arg == "--max-allocations" && i + 1 < argc) {
      if (!rtc::ParseUint32(argv[++i], &turn_cfg.max_allocations) ||
          turn_cfg.max_allocations == 0) {
        std::fprintf(stderr, "无效的 --max-allocations 参数: %s\n", argv[i]);
        return 1;
      }
    } else if (arg == "--no-loopback-peers") {
      turn_cfg.allow_loopback_peers = false;
    } else if (!arg.empty() && arg.front() == '-') {
      std::fprintf(stderr, "未知命令行选项: %.*s\n",
                   static_cast<int>(arg.size()), arg.data());
      PrintUsage(argv[0]);
      return 1;
    } else {
      // 保持与历史位置参数调用方式 `[bind_ip] [ws_port]` 100% 向后兼容。
      if (positional_idx == 0) {
        bind_ip = std::string(arg);
      } else if (positional_idx == 1) {
        if (!rtc::ParseUint16(arg, &ws_port)) {
          std::fprintf(stderr, "无效的信令端口位置参数: %.*s\n",
                       static_cast<int>(arg.size()), arg.data());
          return 1;
        }
      }
      ++positional_idx;
    }
  }

  std::signal(SIGINT, &SignalHandler);
  std::signal(SIGTERM, &SignalHandler);

  rtc::LogMessage::SetMinLogSeverity(rtc::LoggingSeverity::kInfo);

  // 1. 启动 WebSocket P2P JSON 信令配对服务。
  rtc::P2pWsSignalingServer sig_server(bind_ip);
  if (!sig_server.Start(ws_port)) {
    return 1;
  }

  // 2. 按需选择性开启内置 STUN / TURN UDP 穿透与中继转发服务。
  std::unique_ptr<rtc::StunTurnRelayServer> turn_server;
  if (enable_turn) {
    if (!has_custom_turn_bind_ip) {
      turn_cfg.bind_ip = bind_ip;
      turn_cfg.relay_bind_ip = bind_ip;
    }
    if (turn_cfg.static_users.empty() && turn_cfg.rest_api_secret.empty()) {
      turn_cfg.static_users["rtc"] = "rtcpass";
      RTC_LOG(kWarning)
          << "已启用 --enable-turn 但未指定鉴权参数，默认注入测试账号 "
             "rtc:rtcpass；公网生产部署请传入 --turn-user <user:pass> 或 "
             "--turn-rest-secret <secret>";
    }
    turn_server = std::make_unique<rtc::StunTurnRelayServer>(turn_cfg);
    if (!turn_server->Start()) {
      RTC_LOG(kError) << "内置 STUN/TURN 中继服务启动失败，正在回滚停止信令服务";
      sig_server.Stop();
      return 1;
    }
    if (!WritePortFile(turn_port_file, turn_server->port())) {
      RTC_LOG(kWarning) << "写入 --turn-port-file 失败: " << turn_port_file;
    }

    const std::string display_host =
        !turn_cfg.external_ip.empty()
            ? turn_cfg.external_ip
            : (turn_cfg.bind_ip == "0.0.0.0" ? "127.0.0.1" : turn_cfg.bind_ip);
    RTC_LOG(kInfo) << "协同 STUN/TURN 服务已就绪: stun:" << display_host << ":"
                   << turn_server->port() << " | turn:" << display_host << ":"
                   << turn_server->port() << "?transport=udp (realm="
                   << turn_cfg.realm << ")";
  }

  if (!WritePortFile(port_file, sig_server.port())) {
    RTC_LOG(kWarning) << "写入 --port-file 失败: " << port_file;
  }

  while (!g_stop.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  if (turn_server != nullptr) {
    const rtc::StunTurnStatsSnapshot stats = turn_server->GetStatsSnapshot();
    RTC_LOG(kInfo) << "正在停止内置 STUN/TURN 服务: binding_reqs="
                   << stats.stun_binding_requests
                   << " total_allocs=" << stats.total_allocations
                   << " relayed_pkts=" << stats.relayed_packets
                   << " relayed_bytes=" << stats.relayed_bytes;
    turn_server->Stop();
  }
  sig_server.Stop();
  return 0;
}
