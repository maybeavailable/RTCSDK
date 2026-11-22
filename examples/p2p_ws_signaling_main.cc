#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"
#include "server/p2p_ws_signaling_server.h"

namespace {
std::atomic<bool> g_stop{false};
void SignalHandler(int /*sig*/) { g_stop.store(true); }
}  // namespace

int main(int argc, char** argv) {
  std::string bind_ip = "0.0.0.0";
  uint16_t ws_port = 9002;
  std::string port_file;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--port-file" && i + 1 < argc) {
      port_file = argv[++i];
    } else if (i == 1) {
      bind_ip = argv[i];
    } else if (i == 2) {
      rtc::ParseUint16(arg, &ws_port);
    }
  }

  std::signal(SIGINT, &SignalHandler);
  std::signal(SIGTERM, &SignalHandler);

  rtc::LogMessage::SetMinLogSeverity(rtc::LoggingSeverity::kInfo);

  rtc::P2pWsSignalingServer sig_server(bind_ip);
  if (!sig_server.Start(ws_port)) {
    return 1;
  }

  if (!port_file.empty()) {
    FILE* fp = std::fopen(port_file.c_str(), "w");
    if (fp != nullptr) {
      std::fprintf(fp, "%u\n", static_cast<unsigned>(sig_server.port()));
      std::fclose(fp);
    }
  }

  while (!g_stop.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  sig_server.Stop();
  return 0;
}
