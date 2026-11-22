# Embedded Pure-Video Dual-Mode RTC SDK (`WebRTC P2P` + `IETF MoQ`)

面向嵌入式 Linux（如瑞芯微 RK3588/RK356x、海思、NVIDIA Jetson、地平线等）设计的**零音频纯视频、硬件码流直通、双模架构（1v1 浏览器兼容 `WebRTC P2P` + 1对多/多路并发 `IETF MoQ`）**实时视频通信 SDK。

## 架构分工与核心特性

1. **职责清晰的双模传输架构（移除繁重的嵌入式 WebRTC SFU 耦合）**：
   - **`RTC_TRANSPORT_MODE_WEBRTC_P2P`（点对点低延迟直连，100% 兼容主流浏览器）**：
     - 完整实现 Full-ICE（Host / STUN `srflx` / TURN `relay` / `prflx` 对等反射学习、Controlling/Controlled 角色自动协商与 487 Role Conflict 自愈）+ Ephemeral ECDSA P-256 `DTLS-SRTP`（`actpass` / `active` / `passive` 双向协商）。
     - **完整兼容 Chrome / Edge / Firefox / Safari `RTCPeerConnection`**：支持多编码器 SDP Offer 动态 Payload Type 选择（自动匹配 H.264 `42e01f;packetization-mode=1`、RTX `apt=`、`flexfec-03`）、动态 `a=extmap:` 扩展头 ID 映射（同时兼容 RFC 8285 One-Byte `0xBEDE` 与 Two-Byte `0x1000` 扩展头）、`.local` mDNS 候选容错以及无 `a=ssrc:`（Unsignaled SSRC / `mid`）浏览器媒体流自动解复用。
     - 同时支持 **WebSocket 自动信令配对** 与 **无信令服务的直连 SDP/Trickle-ICE API**（`CreateLocalOffer` / `SetRemoteDescription` / `AddRemoteIceCandidate`）。
   - **`RTC_TRANSPORT_MODE_MOQ`（一对多分发与多路并发拉流）**：
     - 基于 `Boost.Asio` UDP 与 OpenSSL 3.0 EVP 原语从零实现的 **RFC 9000 / 9001 / 9002 QUIC v1 传输层**（`AsioQuicClientEngine` / `AsioQuicServer`）。
     - **可热插拔 QUIC 拥塞控制模组（`include/rtc_quic_congestion_control.hpp`）**：内置 **5 种主流 QUIC 拥塞控制算法**——**`BBRv1`**（默认）、**`BBRv2`**（丢包阈值与 `inflight_hi` 头空间感知）、**`CUBIC`**（RFC 9438 + RFC 9406 HyStart++）、**`Copa`**（MIT/Meta `mvfst` 低延迟目标速率控制）与 **`NewReno`**（RFC 9002 标准 AIMD），支持在不断连、不掉帧的前提下**推拉流运行期实时热切换**（自动迁移 `cwnd / BtlBw / min_rtt / ssthresh` 状态），同时支持 C++17 注入外部自定义 `IQuicCongestionControllerFactory` 插件及中继服 `--cc bbr|bbr2|cubic|copa|newreno` 参数。
     - 原生支持 `moq-transport` 控制协议、`LOC` 低开销容器封装、Simulcast 高低双流零转码分发、GOP 边界无花屏动态切流（`SUBSCRIBE_UPDATE`）、`(publisher_priority, send_order)` 抢占式调度以及超时 `RESET_STREAM` 队头阻塞消除。

2. **严格遵循 Google C++ Style Guide 与统一分级日志（`RTC_LOG`）**：
   - 内置 `.clang-format`（`BasedOnStyle: Google`），全仓库零 C++ 异常（`JsonObject` + `<charconv>` `std::from_chars`）、`rtc::ArrayView<const uint8_t>` 零拷贝视图、显式指针输出参数，开启 `-Wall -Wextra -Wshadow -Wnon-virtual-dtor` 零告警构建。
   - 统一日志子系统 `rtc::LogMessage` 自动识别 `TaskQueue` 执行域标签（`[rtc-sig]`、`[rtc-work]`、`[rtc-pacer]`、`[rtc-net]`、`[moq-relay]`），内置 `RingBufferLogSink` 与 C/C++ 自定义日志回调。

## 全覆盖 SDK 使用示例矩阵（`examples/`，C99 与 C++17 对称全覆盖）

- **纯 C99 完整用例（基于 `rtc_video_sdk.h` + `librtc_video_sdk.so`）**：
  - **[examples/c99_webrtc_p2p_full_demo.c](examples/c99_webrtc_p2p_full_demo.c)**（`./build/rtc_example_c99_p2p`）：完整覆盖 C99 下无信令直连 SDP/Trickle-ICE 双向互推互拉（H.264）+ WebSocket 自动信令 P2P 推拉流（H.265）+ 全 8 个回调与日志/异常边界校验。
  - **[examples/c99_moq_multipull_full_demo.c](examples/c99_moq_multipull_full_demo.c)**（`./build/rtc_example_c99_moq`）：完整覆盖 C99 下双机位 Simulcast 推流 + 单 QUIC 连接多路并发拉流、动态高低流互切、请求 IDR、取消订阅与远端下线通知。
- **现代 C++17 完整用例（基于 `rtc_video_engine.hpp`）**：
  - **[examples/cpp17_webrtc_p2p_full_demo.cc](examples/cpp17_webrtc_p2p_full_demo.cc)**（`./build/rtc_example_cpp17_p2p`）：完整覆盖 C++17 下无信令直连 SDP 双向 P2P（H.264）+ WebSocket 自动信令 P2P（H.265）+ 自定义 `LogSink` / `RingBufferLogSink` 与全回调校验。
  - **[examples/cpp17_moq_multipull_full_demo.cc](examples/cpp17_moq_multipull_full_demo.cc)**（`./build/rtc_example_cpp17_moq`）：完整覆盖 C++17 下弱网双机位 Simulcast 推流 + 单 QUIC 连接多路并发拉流、动态切流、请求 IDR、取消订阅与远端下线通知。
  - **[examples/browser_webrtc_p2p_gateway_demo.cc](examples/browser_webrtc_p2p_gateway_demo.cc)**（交互模式 `./build/rtc_example_browser_p2p 8080`；自检 `./build/rtc_example_browser_p2p --self-test`）：内置 HTML5 `<video>` 页面与 HTTP `/api/offer` W3C 浏览器实时视频网关。
- **配套轻量服务端**：
  - **[examples/p2p_ws_signaling_main.cc](examples/p2p_ws_signaling_main.cc)**（`./build/rtc_p2p_ws_signaling_server`）：零媒体纯 JSON WebSocket 1v1 P2P 信令配对服务。
  - **[examples/moq_relay_main.cc](examples/moq_relay_main.cc)**（`./build/rtc_moq_relay_server`）：多路分发 `IETF MoQ` QUIC v1 中继服务。
- **全维度单元测试与业内标准弱网评测套件（`tests/`）**：
  - **[tests/rtc_core_unit_tests.cc](tests/rtc_core_unit_tests.cc)**：核心模块、协议编解码、高精度 Pacer、GoogCC 与 5 种 QUIC 拥塞控制单元测试。
  - **[tests/rtc_e2e_integration_tests.cc](tests/rtc_e2e_integration_tests.cc)**：端到端集成与纯 C99 ABI 验证测试。
  - **[tests/rtc_real_cc_benchmark_test.cc](tests/rtc_real_cc_benchmark_test.cc)**：真实操作系统 UDP 瓶颈链路三阶段拥塞控制与可插拔 QUIC 拥塞控制实测。
  - **[tests/rtc_industry_weaknet_suite_test.cc](tests/rtc_industry_weaknet_suite_test.cc)**：遵循 IETF RFC 8868 / ITU-T G.1050 / RFC 3550 / W3C WebRTC 标准的 12 大常规与极限弱网场景 × 18 项全维度指标评测套件。
  - **[docs/TEST_REPORT.md](docs/TEST_REPORT.md)** 与 **[docs/test_logs/](docs/test_logs/)**：完整实测报告、亚秒级阶跃追踪曲线、常规与极限弱网 18 项指标对比矩阵及原始控制台日志归档。
  - **[docs/CONGESTION_CONTROL_TUNING_GUIDE.md](docs/CONGESTION_CONTROL_TUNING_GUIDE.md)**：面向嵌入式场景的拥塞控制参数调优工程指南（业务不可能三角选型、弱网症状归因、WebRTC/MoQ 核心旋钮源码映射与硬件编码器联调规范）。

## 编译与测试

### 1. 本机编译与运行全部测试

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure -V
```

### 2. 嵌入式 ARM64 交叉编译

```bash
export CROSS_COMPILE_PREFIX=aarch64-linux-gnu-
export TARGET_SYSROOT=/path/to/board/sysroot
cmake -S . -B build-arm64 \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
    -DRTC_BUILD_TESTS=OFF \
    -DRTC_BUILD_SERVERS=OFF \
    -DRTC_BUILD_EXAMPLES=OFF
cmake --build build-arm64 -j$(nproc)
```
