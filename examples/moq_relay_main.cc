#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <thread>

#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"
#include "server/embedded_moq_relay.h"

namespace {
std::atomic<bool> g_stop{false};

void SignalHandler(int /*sig*/) { g_stop.store(true); }
}  // namespace

int main(int argc, char** argv) {
  std::string bind_ip = "0.0.0.0";
  uint16_t moq_udp_port = 4433;
  std::string port_file;
  std::string auth_token;
  rtc_quic_cc_algo_e cc_algo = RTC_QUIC_CC_BBR;
  int pos_idx = 0;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--port-file" && i + 1 < argc) {
      port_file = argv[++i];
    } else if (arg == "--auth-token" && i + 1 < argc) {
      auth_token = argv[++i];
    } else if (arg == "--cc" && i + 1 < argc) {
      const std::string_view cc_str(argv[++i]);
      if (cc_str == "bbr2" || cc_str == "BBR2") {
        cc_algo = RTC_QUIC_CC_BBR2;
      } else if (cc_str == "cubic" || cc_str == "CUBIC") {
        cc_algo = RTC_QUIC_CC_CUBIC;
      } else if (cc_str == "copa" || cc_str == "Copa") {
        cc_algo = RTC_QUIC_CC_COPA;
      } else if (cc_str == "newreno" || cc_str == "NewReno") {
        cc_algo = RTC_QUIC_CC_NEWRENO;
      } else {
        cc_algo = RTC_QUIC_CC_BBR;
      }
    } else if (!arg.empty() && arg[0] != '-') {
      if (pos_idx == 0) {
        bind_ip = argv[i];
      } else if (pos_idx == 1) {
        rtc::ParseUint16(arg, &moq_udp_port);
      }
      ++pos_idx;
    }
  }

  std::signal(SIGINT, &SignalHandler);
  std::signal(SIGTERM, &SignalHandler);

  rtc::LogMessage::SetMinLogSeverity(rtc::LoggingSeverity::kInfo);

  rtc::EmbeddedMoqRelayServer moq_relay(bind_ip);
  moq_relay.SetQuicCongestionControl(cc_algo);
  if (!auth_token.empty()) {
    moq_relay.SetRequiredAuthToken(auth_token);
  }
  if (!moq_relay.Start(moq_udp_port)) {
    RTC_LOG(kError) << "Failed to start EmbeddedMoqRelayServer on " << bind_ip
                    << ":" << moq_udp_port;
    return 1;
  }

  if (!port_file.empty()) {
    FILE* fp = std::fopen(port_file.c_str(), "w");
    if (fp != nullptr) {
      std::fprintf(fp, "%u\n", static_cast<unsigned>(moq_relay.udp_port()));
      std::fclose(fp);
    }
  }

  RTC_LOG(kInfo) << "IETF MoQ (draft-17) Relay ready on moqt://" << bind_ip
                 << ":" << moq_relay.udp_port() << "/moq and WebTransport https://"
                 << bind_ip << ":" << moq_relay.udp_port()
                 << "/moq (W3C serverCertificateHashes sha-256="
                 << moq_relay.certificate_sha256_hex() << ")";

  while (!g_stop.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  moq_relay.Stop();
  return 0;
}
