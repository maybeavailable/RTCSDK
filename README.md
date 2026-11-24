# Embedded Pure-Video Dual-Mode RTC SDK (`WebRTC P2P` + `IETF MoQ`)

面向嵌入式 Linux（如瑞芯微 RK3588/RK356x、海思、NVIDIA Jetson、地平线等）设计的**零音频纯视频、硬件码流直通、双模架构（1v1 浏览器兼容 `WebRTC P2P` + 1对多/多路并发 `IETF MoQ`）**实时视频通信 SDK。

## 架构分工与核心特性

1. **职责清晰的双模传输架构（移除繁重的嵌入式 WebRTC SFU 耦合）**：
   - **`RTC_TRANSPORT_MODE_WEBRTC_P2P`（点对点低延迟直连，100% 兼容主流浏览器）**：
     - 完整实现 Full-ICE（Host / STUN `srflx` / TURN `relay` / `prflx` 对等反射学习、异步非阻塞 DNS 域名解析与 RFC 5389 超时重传，支持 `stun:stun.l.google.com:19302` 等公网域名及 IPv4/IPv6 字面量、Controlling/Controlled 角色自动协商与 487 Role Conflict 自愈）+ Ephemeral ECDSA P-256 `DTLS-SRTP`（`actpass` / `active` / `passive` 双向协商）。
     - **完整兼容 Chrome / Edge / Firefox / Safari `RTCPeerConnection`**：支持多编码器 SDP Offer 动态 Payload Type 选择（自动匹配 H.264 `42e01f;packetization-mode=1`、RTX `apt=`、标准 **RFC 8627 `flexfec`** 及兼容 `flexfec-03`）、动态 `a=extmap:` 扩展头 ID 映射（同时兼容 RFC 8285 One-Byte `0xBEDE` 与 Two-Byte `0x1000` 扩展头）、`.local` mDNS 候选容错以及无 `a=ssrc:`（Unsignaled SSRC / `mid`）浏览器媒体流自动解复用。
     - **完整支持标准 WebRTC DataChannel（`src/pc/sctp_data_channel.h/.cc`）**：从零自研无外部重依赖的 RFC 4960 / RFC 3309（Castagnoli CRC-32c）SCTP over DTLS（RFC 8261）协议栈，完整支持四次握手、大报文自动分片重组、SACK 选择性确认、HEARTBEAT 保活、RFC 3758 PR-SCTP（`FORWARD-TSN` 限次重传与报文生存期超时跳过）、RFC 6525 `RE-CONFIG` 流关闭、RFC 8832 DCEP 带内通道协商及 RFC 8831 二进制/UTF-8 字符串传输，与浏览器 `RTCPeerConnection.createDataChannel()` / `ondatachannel` 原生互通。
     - 同时支持 **WebSocket 自动信令配对** 与 **无信令服务的直连 SDP/Trickle-ICE API**（`CreateLocalOffer` / `SetRemoteDescription` / `AddRemoteIceCandidate`）。
   - **`RTC_TRANSPORT_MODE_MOQ` / `RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT`（一对多分发、多路并发拉流与浏览器原生播放，严格遵循最新 `draft-ietf-moq-transport-17`）**：
     - 基于 `Boost.Asio` UDP 与 OpenSSL 3.0 EVP 原语从零实现的 **RFC 9000 / 9001 / 9002 QUIC v1 + 标准 RFC 8446 TLS 1.3 握手（含符合 W3C `serverCertificateHashes` 规范的 10 天有效期 ECDSA P-256 X.509v3 证书与 `CertificateVerify`）+ RFC 9221 不可靠数据报扩展（`DATAGRAM 0x30/0x31`）+ 可变长度 CID（0..20B）与多 ALPN 协商传输层**（`AsioQuicClientEngine` / `AsioQuicServer`）。
     - **完整内置 HTTP/3 与 WebTransport over HTTP/3 协议栈（`src/moq/http3_webtransport.h/.cc`）**：完整实现 **RFC 9114 HTTP/3**（控制流 `0x00`、`SETTINGS`、`HEADERS`、`DATA`、`GOAWAY`）、**RFC 9204 QPACK 静态表 + RFC 7541 Huffman 头部压缩**、**RFC 9220 Extended `CONNECT`**、**RFC 9297 HTTP Datagrams（Quarter-Stream-ID）与 Capsule 协议**（`WT_CLOSE_SESSION 0x2843` 等）以及 **`draft-ietf-webtrans-http3-14`**（`SETTINGS_WT_MAX_SESSIONS 0x14e9cd29`、`WT-Available-Protocols` / `WT-Protocol: "moqt-17"`、`0x41` 双向流、`0x54` 单向流、图 4 错误码空间映射）。中继服单 UDP 端口同时支持原生 QUIC（`moqt://host:port/moq`，ALPN `"moqt-17"`）与 WebTransport over HTTP/3（`https://host:port/moq`，ALPN `"h3"`）跨协议混联互通，并支持同连接并发处理标准 HTTP/3 `GET`/`POST` 请求。
     - **严格实现 IETF `draft-ietf-moq-transport-17` 控制与数据平面（`src/moq/moq_transport.h/.cc`）**：前导 1 比特计数 `vi64` 变长整数（拒绝非法编码点 `0xFC/0xFD`）、双端独立单向控制流（`SETUP 0x2F00` / `GOAWAY 0x10`）、奇偶 `Request ID` 双向请求流（`PUBLISH_NAMESPACE 0x06`、`SUBSCRIBE_NAMESPACE 0x11`、`NAMESPACE 0x08` / `NAMESPACE_DONE 0x0E`、`SUBSCRIBE 0x03` -> `SUBSCRIBE_OK 0x04`、`REQUEST_UPDATE 0x02` 携带 `FORWARD 0x10` 与 `NEW_GROUP_REQUEST 0x32`、`STOP_SENDING` 退订）、`SUBGROUP_HEADER (0x10..0x3D)` 差分 `Object ID Delta` 子组流与 `OBJECT_DATAGRAM`、`LOC` 低开销媒体封装、GOP 边界无花屏 Simulcast 动态切层与超时 `RESET_STREAM` 队头阻塞消除。
     - **可热插拔 QUIC 拥塞控制模组（`include/rtc_quic_congestion_control.hpp`）**：内置 **5 种主流 QUIC 拥塞控制算法**——**`BBRv1`**（默认）、**`BBRv2`**（丢包阈值与 `inflight_hi` 头空间感知）、**`CUBIC`**（RFC 9438 + RFC 9406 HyStart++）、**`Copa`**（MIT/Meta `mvfst` 低延迟目标速率控制）与 **`NewReno`**（RFC 9002 标准 AIMD），支持在不断连、不掉帧的前提下**推拉流运行期实时热切换**（自动迁移 `cwnd / BtlBw / min_rtt / ssthresh` 状态），同时支持 C++17 注入外部自定义 `IQuicCongestionControllerFactory` 插件及中继服 `--cc bbr|bbr2|cubic|copa|newreno` 参数。
     - **原生 IETF MoQ 通用数据传输通道（`MoqDataPackager` + 子组流 / `OBJECT_DATAGRAM`）**：与 WebRTC DataChannel 共享完全一致的现代 C++17 API（`CreateDataChannel` / `SendData` / `SendTextData` / `CloseDataChannel`），支持高优先级有序可靠长流、零重传低延迟 `OBJECT_DATAGRAM` 不可靠数据报、限时生存期独立对象流以及 MoQ Relay 零拷贝一对多广播与反向控制回传。

2. **纯现代 C++17 SDK 接口、严格遵循 Google C++ Style Guide 与统一分级日志（`RTC_LOG`）**：
   - 仅暴露零第三方依赖的纯 C++17 公共头文件（[`include/rtc_video_types.hpp`](include/rtc_video_types.hpp)、[`include/rtc_quic_congestion_control.hpp`](include/rtc_quic_congestion_control.hpp)、[`include/rtc_video_engine.hpp`](include/rtc_video_engine.hpp)），支持静态库 `librtc_video_core.a` 与符号隔离动态库 `librtc_video_sdk.so`（`-fvisibility=hidden` + `-Wl,--exclude-libs,ALL`）。
   - 内置 `.clang-format`（`BasedOnStyle: Google`），全仓库零 C++ 异常（`JsonObject` + `<charconv>` `std::from_chars`）、`rtc::ArrayView<const uint8_t>` 零拷贝视图、显式指针输出参数，开启 `-Wall -Wextra -Wshadow -Wnon-virtual-dtor` 零告警构建。
   - 统一日志子系统 `rtc::LogMessage` 自动识别 `TaskQueue` 执行域标签（`[rtc-sig]`、`[rtc-work]`、`[rtc-pacer]`、`[rtc-net]`、`[moq-relay]`），内置 `RingBufferLogSink` 与自定义 C++17 `rtc::LogSink` 日志接收器。

## 全覆盖现代 C++17 SDK 使用示例矩阵（`examples/`）

- **现代 C++17 完整用例（基于 `rtc_video_engine.hpp`）**：
  - **[examples/cpp17_webrtc_p2p_full_demo.cc](examples/cpp17_webrtc_p2p_full_demo.cc)**（`./build/rtc_example_cpp17_p2p`）：完整覆盖 C++17 下无信令直连 SDP 双向 P2P（H.264）+ WebSocket 自动信令 P2P（H.265）+ 自定义 `LogSink` / `RingBufferLogSink` 与全回调校验。
  - **[examples/cpp17_moq_multipull_full_demo.cc](examples/cpp17_moq_multipull_full_demo.cc)**（`./build/rtc_example_cpp17_moq`）：完整覆盖 C++17 下弱网双机位 Simulcast 推流 + 单 QUIC 连接多路并发拉流、动态切流、请求 IDR、取消订阅与远端下线通知。
  - **[examples/browser_webrtc_p2p_gateway_demo.cc](examples/browser_webrtc_p2p_gateway_demo.cc)**（交互模式 `./build/rtc_example_browser_p2p 8080`；自检 `./build/rtc_example_browser_p2p --self-test`）：内置 HTML5 `<video>` 页面与 HTTP `/api/offer` W3C 浏览器实时视频网关。
  - **[examples/browser_moq_player_demo.cc](examples/browser_moq_player_demo.cc)**（交互模式 `./build/rtc_example_browser_moq 8081`；自检 `./build/rtc_example_browser_moq --self-test`）：内置 HTML5 `<canvas>` 实时播放器，通过 W3C `WebTransport` over HTTP/3（`serverCertificateHashes`）+ 前端原生 `MOQT draft-17` 状态机 + `WebCodecs` H.264 解码器（含 `/ws-moq` 自动回退桥接）实现浏览器 MoQ 实时播放、GOP 无花屏高低清切层与双向数据通道交互。
- **配套轻量服务端**：
  - **[examples/p2p_ws_signaling_main.cc](examples/p2p_ws_signaling_main.cc)**（`./build/rtc_p2p_ws_signaling_server`）：WebSocket 1v1 P2P 信令配对服务；默认保持零媒体转发，支持通过 `--enable-turn`（配合 `--turn-port`、`--external-ip`、`--turn-user`、`--turn-rest-secret`、`--min-port`/`--max-port`、`--no-loopback-peers`）在同一进程内按需开启对标 `coturn` 的 RFC 5389 STUN + RFC 5766 TURN（含 4 字节 `ChannelData` 与同机双对称型 NAT 内存级发卡弯直通）UDP 中继转发服务。
  - **[examples/moq_relay_main.cc](examples/moq_relay_main.cc)**（`./build/rtc_moq_relay_server`）：多路分发 `IETF MoQ` QUIC v1 / HTTP/3 WebTransport 中继服务。
- **全维度单元测试与业内标准弱网评测套件（`tests/`）**：
  - **[tests/rtc_core_unit_tests.cc](tests/rtc_core_unit_tests.cc)**：核心模块、协议编解码、RFC 8627 FlexFEC、高精度 Pacer、GoogCC 与 5 种 QUIC 拥塞控制单元测试。
  - **[tests/rtc_cpp17_shared_sdk_test.cc](tests/rtc_cpp17_shared_sdk_test.cc)**：仅依赖 `include/` 公共头文件与 `librtc_video_sdk.so` 的纯 C++17 动态库隔离集成测试。
  - **[tests/rtc_e2e_integration_tests.cc](tests/rtc_e2e_integration_tests.cc)**：端到端 WebRTC P2P、STUN/TURN 中继、IETF MoQ draft-17、HTTP/3 WebTransport 及双模数据通道集成测试。
  - **[tests/rtc_real_cc_benchmark_test.cc](tests/rtc_real_cc_benchmark_test.cc)**：真实操作系统 UDP 瓶颈链路三阶段拥塞控制与可插拔 QUIC 拥塞控制实测。
  - **[tests/rtc_industry_weaknet_suite_test.cc](tests/rtc_industry_weaknet_suite_test.cc)**：遵循 IETF RFC 8868 / ITU-T G.1050 / RFC 3550 / W3C WebRTC 标准的 12 大常规与极限弱网场景 × 18 项全维度指标评测套件。
  - **[docs/TEST_REPORT.md](docs/TEST_REPORT.md)** 与 **[docs/test_logs/](docs/test_logs/)**：完整实测报告、亚秒级阶跃追踪曲线、常规与极限弱网 18 项指标对比矩阵及原始控制台日志归档。
  - **[docs/CONGESTION_CONTROL_TUNING_GUIDE.md](docs/CONGESTION_CONTROL_TUNING_GUIDE.md)**：面向嵌入式场景的拥塞控制参数调优工程指南（业务不可能三角选型、弱网症状归因、WebRTC/MoQ 核心旋钮源码映射与硬件编码器联调规范）。

## 编译与测试

### 1. 本机编译、测试与导出头文件/库文件到指定目录

```bash
# 方式 A：编译完成后自动将 include/*.hpp 与 lib/* 导出到指定目录（不传则默认导出至 build/sdk_out）
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DRTC_SDK_OUTPUT_DIR=/path/to/sdk_export
cmake --build build -j$(nproc)

# 方式 B：使用标准 CMake install 导出 SDK 头文件、动/静态库、CMake Config 及配套服务端二进制到任意指定目录
cmake --install build --prefix /path/to/sdk_export

# 运行测试套件
ctest --test-dir build --output-on-failure -V
```

导出目录结构如下：
- `include/`：`rtc_video_types.hpp`、`rtc_quic_congestion_control.hpp`、`rtc_video_engine.hpp`
- `lib/`：`librtc_video_sdk.so`（符号隔离动态库）、`librtc_video_core.a`、`libsrtp2.a` 及 `cmake/rtc_video_sdk/` 包配置
- `bin/`（执行 `cmake --install` 且开启 `RTC_BUILD_SERVERS` 时）：`rtc_p2p_ws_signaling_server`、`rtc_moq_relay_server`

下游 C++17 业务工程可直接通过 `find_package` 接入导出目录：

```cmake
find_package(rtc_video_sdk REQUIRED PATHS /path/to/sdk_export)
add_executable(my_rtc_app main.cc)
target_link_libraries(my_rtc_app PRIVATE rtc::rtc_video_sdk)
```

### 2. 嵌入式 ARM64 交叉编译与导出

```bash
export CROSS_COMPILE_PREFIX=aarch64-linux-gnu-
export TARGET_SYSROOT=/path/to/board/sysroot
cmake -S . -B build-arm64 \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
    -DRTC_SDK_OUTPUT_DIR=/path/to/arm64_sdk_export \
    -DRTC_BUILD_TESTS=OFF \
    -DRTC_BUILD_SERVERS=OFF \
    -DRTC_BUILD_EXAMPLES=OFF
cmake --build build-arm64 -j$(nproc)
```
