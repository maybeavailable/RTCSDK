# RTCSDK 拥塞控制参数调优工程指南

本文档针对 `RTCSDK` 的双模传输架构（`WebRTC P2P GoogCC` + `IETF MoQ 可插拔 QUIC CC`）与全维度弱网评测基准（[`tests/rtc_industry_weaknet_suite_test.cc`](../tests/rtc_industry_weaknet_suite_test.cc)），提供系统化的 **“定业务三角 -> 看指标找病灶 -> 对号拧参数 -> 联调硬件编码器”** 四步工程调优方法论。

---

## 一、第一步：确定业务场景的“不可能三角”优先级

实时视频传输的拥塞控制本质是在以下三个互斥目标之间寻找帕累托最优，调参前必须明确当前产品的第一优先级：

```text
低排队延迟 (Low Latency)  <--->  高带宽利用率 (High Utilization)  <--->  抗随机丢包与画质平稳 (Smoothness)
```

| 典型嵌入式业务场景 | 第一优先级 | 可让渡指标 | 推荐传输与拥塞控制选型 |
| :--- | :--- | :--- | :--- |
| **遥控驾驶 / 机械臂远控** | **极致低尾延迟**（端到端 `P99 < 80ms`） | 让渡 `10%~15%` 带宽利用率 | WebRTC `GoogCC`（收紧阈值）或 MoQ `Copa` |
| **无人机图传 / 户外移动巡检** | **抗高随机丢包与不断流** | 容忍 `150~250ms` 延迟 | MoQ `BBRv1` / `BBRv2` 或 WebRTC 高配 `FlexFEC` |
| **多路安防监控 / NVR 集中拉流** | **高吞吐画质 + 多流公平性** | 容忍 `200~300ms` 延迟 | MoQ `BBRv2` / `CUBIC` + Simulcast 高低双层 |

---

## 二、第二步：根据弱网评测指标“看症状、断病根”

运行 [`./build/rtc_industry_weaknet_suite_test`](TEST_REPORT.md) 获取 18 项核心指标后，对照以下 4 类典型症状精准定位需要调整的子模块：

1. **症状 A：`SelfDrop% = 0%`，但 `QueueP95` 与 `E2ELat_P95` 显著偏高（如深缓冲场景 > 200ms）**
   - **根因**：延迟梯度过载检测器过于迟钝，或拥塞窗口增益 `cwnd_gain` 偏大导致路由器常驻排队（Bufferbloat）。
   - **调优方向**：收紧过载检测阈值 `threshold_` / 降低 BBR `cwnd_gain_` 或上调 Copa 延迟权重 `delta_`。
2. **症状 B：无丢包且排队极低，但 `LinkUtil% < 75%` 或出电梯/隧道后画质恢复过慢**
   - **根因**：周期恢复探测间隔太保守、AIMD 乘性增幅小，或无线空口微抖动误触发了早退（Overuse）。
   - **调优方向**：缩短恢复探测周期 / 略微放宽过载确认时间 `overusing_time_threshold_ms_`。
3. **症状 C：`WireLoss` 在 `5%~15%`（无线随机丢包），`QueueP50` 很低，但编码码率暴跌成马赛克**
   - **根因**：算法将**无线信道随机丢包**误判为**路由器满载拥塞丢包**。
   - **调优方向**：上调丢包退避触发门限（WebRTC `SendSideBWE` / BBRv2 `kLossThresh`），避免在无线信道使用基于丢包的 `CUBIC` / `NewReno`。
4. **症状 D：带宽骤降瞬间 `SelfDrop%` 飙升、最大卡顿 `MaxFreeze_ms > 800ms`**
   - **根因**：过载退避幅度不够果断、Pacer 突发上限偏大，或旧高码率 GOP 长时间阻塞发送队列。
   - **调优方向**：调小乘性退避因子 `beta_` / 合理收紧 `moq_delivery_timeout_ms` 及时触发 `RESET_STREAM` 淘汰旧 GOP。

---

## 三、第三步：SDK 核心可调参数速查表（精确对应源码位置）

### 3.1 WebRTC P2P（`GoogCC + Pacer + FlexFEC/RTX`）核心旋钮

| 参数名称 | 源码位置与当前默认值 | 调小效果 | 调大效果 | 实战调优建议 |
| :--- | :--- | :--- | :--- | :--- |
| **`threshold_` & `overusing_time_threshold_ms_`** | [`src/modules/congestion_controller/goog_cc/goog_cc_controller.h#L102-L103`](../src/modules/congestion_controller/goog_cc/goog_cc_controller.h#L102-L103)（默认 `12.5` / `10.0 ms`） | 对排队极敏感，端到端延迟更低，但 Wi-Fi 空口抖动易误触发降码率 | 抗无线抖动更稳、带宽利用率更高，但带宽骤降时多排 `10~20ms` 队 | 远控场景调至 `9.0 / 8ms`；4G/Wi-Fi 移动网调至 `14.0 / 15ms` |
| **`window_size`**（Trendline 包组窗口） | [`src/modules/congestion_controller/goog_cc/goog_cc_controller.h#L63`](../src/modules/congestion_controller/goog_cc/goog_cc_controller.h#L63)（默认 `20`） | 拥塞阶跃响应更快 | 线性回归斜率滤波更平滑，抗突发噪声 | 推荐保持在 `15 ~ 25` 区间 |
| **`beta_`**（AIMD 过载乘性退避系数） | [`src/modules/congestion_controller/goog_cc/goog_cc_controller.h#L192`](../src/modules/congestion_controller/goog_cc/goog_cc_controller.h#L192)（默认 `0.85`） | 单次过载降幅更大，排空路由器积压极快，但画质跳变明显 | 码率下降更平滑，但浅队列路由器易发生二次尾丢包 | 浅缓冲交换机改 `0.78`；常规网络保持 `0.85` |
| **丢包退避门限 `26 / 256`**（约 `10%`） | [`src/modules/congestion_controller/goog_cc/goog_cc_controller.cc#L611`](../src/modules/congestion_controller/goog_cc/goog_cc_controller.cc#L611)（默认 `26`） | 轻微丢包即下调目标码率（偏保守） | **容忍更高比例随机无线丢包而不砍总目标码率** | 户外远距无线图传可放宽至 `38`（约 `15%` 丢包内由 FlexFEC+RTX 兜底） |
| **拥塞后恢复探测间隔 `2500 ms`** | [`src/modules/congestion_controller/goog_cc/goog_cc_controller.cc#L815`](../src/modules/congestion_controller/goog_cc/goog_cc_controller.cc#L815)（默认 `2500ms`, `1.8x`） | 带宽恢复后画质回升极快，窄带稳态略增约 `2%` 探测开销 | 稳态零额外开销，但出隧道后爬升较慢 | 车载/巡检频繁进出遮挡区可缩至 `1200 ~ 1500 ms` |
| **`pacing_factor`**（Pacer 平滑发送倍率） | [`src/modules/congestion_controller/goog_cc/goog_cc_controller.h#L334`](../src/modules/congestion_controller/goog_cc/goog_cc_controller.h#L334)（默认 `1.1`） | 发包间隔极均匀，保护极浅缓冲路由器 | 大关键帧（IDR）排空更快，降低首帧/I帧延迟 | 大 I 帧场景设为 `1.25 ~ 1.35`；超窄带设为 `1.05` |
| **FlexFEC / RTX 冗余配比系数** | [`src/modules/rtp_rtcp/flexfec_codec.cc#L27-L40`](../src/modules/rtp_rtcp/flexfec_codec.cc#L27-L40) | 节省冗余带宽留给编码器提升清晰度 | 免等 `1 RTT` 重传即可异或恢复丢包 | `RTT < 50ms` 降 FEC 靠 RTX；`RTT > 80ms` 提高 `rtt_factor` 重用 FEC |

---

### 3.2 IETF MoQ（`可插拔 QUIC CC + MoqBweAdapter + Simulcast`）核心旋钮

| 参数名称 | 源码位置与当前默认值 | 作用机理与实战调优建议 |
| :--- | :--- | :--- |
| **拥塞控制算法模组选型** | [`include/rtc_video_types.hpp`](../include/rtc_video_types.hpp)（`rtc_quic_cc_algo_e`） | **选对模组优先于微调常数**：高丢包无线网（`5%~50%`）选 `BBRv1` / `BBRv2`；深队列低延迟选 `Copa`；常规有线共享瓶颈选 `CUBIC`。支持通过 `SetQuicCongestionControl` 根据实时丢包率/RTT 动态热切换。 |
| **`cwnd_gain_`**（BBRv1/v2 窗口增益） | [`src/moq/quic_congestion_control.cc#L296`](../src/moq/quic_congestion_control.cc#L296)（默认 `2.0`） | Wi-Fi 帧聚合（A-MPDU）和蜂窝网 ACK 压缩需保持 `2.0` 以跑满物理带宽；若工业内网极浅缓冲交换机出现尾丢包，可下调至 `1.5`。 |
| **BBRv2 单轮丢包阈值 `2%`** | [`src/moq/quic_congestion_control.cc#L429`](../src/moq/quic_congestion_control.cc#L429) | 单轮丢包超过阈值会收缩 `inflight_hi/lo`。在 `5%~15%` 无线底噪环境若使用 `BBRv2`，建议放宽至 **`5% ~ 8%`**（或直接使用无视随机丢包的 `BBRv1`）。 |
| **Copa 延迟权重 `delta_`** | [`src/moq/quic_congestion_control.cc#L1011-L1016`](../src/moq/quic_congestion_control.cc#L1011-L1016)（默认 `0.5`） | 目标速率与 `1 / (delta * queueing_delay)` 成正比。独占管道追求极致低延迟设为 `0.5 ~ 0.8`；需与后台大流量 TCP 流竞争带宽时调小至 `0.125 ~ 0.2`。 |
| **RACK 自适应乱序容忍度 `rttvar / 5`** | [`src/moq/asio_quic_transport.cc#L1949-L1951`](../src/moq/asio_quic_transport.cc#L1949-L1951) | 在多网卡聚合或多径无线重度乱序网络中，将除数由 `5` 调为 `3`（更快放宽包序号乱序容忍阈值），可避免伪丢包重传并显著提升吞吐率。 |
| **`moq_delivery_timeout_ms`** | [`include/rtc_video_engine.hpp#L60`](../include/rtc_video_engine.hpp#L60)（默认 `250 ms`） | **经验公式**：设为 `max(300ms, 4 * 基础RTT)`。过小会导致高时延链路（如卫星网）误重置正常 GOP；过大则拥塞骤降时旧流阻塞时间变长。 |
| **`high_hysteresis_bps`**（Simulcast 迟滞带） | [`src/modules/video_coding/video_coding_module.h#L238`](../src/modules/video_coding/video_coding_module.h#L238)（默认 `80 kbps`） | 若网络长期处于 `850 ~ 930 kbps` 临界带宽导致高低清层频繁切换，将迟滞带扩大至 `150 ~ 200 kbps` 即可彻底消除乒乓震荡。 |

---

## 四、第四步：嵌入式真机硬件编码器（VENC）联调与回归纪律

1. **硬件编码器码控模式必须与软件 BWE 严密对齐**：
   - 在 RK3588、海思、Jetson 等嵌入式 SoC 上，若硬件 VENC 设为长窗口 `VBR`，当画面剧烈运动时实际输出码率可能瞬间达到 `target_bitrate_bps` 的 `2 ~ 3 倍`，直接击穿发送端 Pacer 预算并引发路由器尾部丢包。
   - **真机推荐配置**：
     - 码控模式设为 **`CBR`** 或短统计窗口（`<= 500ms`）的紧约束 **`AVBR`**；
     - 约束 **I/P 帧体积比（IP Ratio <= 4~6 倍）**，窄带弱网优先启用 **Intra Refresh（帧内宏块渐进刷新）** 或多 Slice 切分；
     - 常规 GOP 间隔设为 **`1s ~ 2s`（30 ~ 60 帧）**，同时在 `OnEncoderForceIdr` 回调触发时立即插入关键帧。
2. **单变量 A/B 回归铁律（防止“按下葫芦浮起瓢”）**：
   - 每次仅修改 **1 组物理含义明确的参数**，完整运行 `./build/rtc_industry_weaknet_suite_test` 同时验证正向指标与反向红线：
     - 调**激进/快爬升**参数后，必须验收 **`P5-600ms深队列`**（排队 P95 不恶化）与 **`X3-150k超窄带`**（自致尾丢包仍保持 `0.0%`）；
     - 调**低延迟/敏感退避**参数后，必须验收 **`P1-基准网络`**（带宽利用率 `> 85%`）与 **`P3/X5-抖动乱序`**（不因空口抖动误砍码率）。
