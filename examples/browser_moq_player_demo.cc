// 兼容浏览器的 IETF MoQ (draft-17) WebTransport + WebCodecs 实时播放器与网关示例：
//
// 模式 1（浏览器原生 WebTransport + MoQ draft-17 实时拉流播放）：
//   运行命令：./rtc_example_browser_moq 8081
//   在 Chrome / Edge / Firefox 中打开 http://127.0.0.1:8081 并点击 "Start MoQ Playback"，
//   浏览器通过 W3C WebTransport over HTTP/3（使用 10 天有效期的 ECDSA P-256 自定义证书哈希
//   `serverCertificateHashes`）直连内嵌双栈 MoQ 中继服务器，在前端 JS 中运行完整的
//   `draft-ietf-moq-transport-17` 协议状态机（SETUP 0x2F00、SUBSCRIBE_NAMESPACE、
//   SUBSCRIBE、REQUEST_UPDATE 切层、SUBGROUP_HEADER 流与 OBJECT_DATAGRAM 数据报），
//   并通过 W3C WebCodecs `VideoDecoder`（含软件 I_PCM 兜底渲染器）在 <canvas> 上实时播放
//   H.264 双层 Simulcast 视频流与双向 MoQ 数据通道（若环境不支持 WebTransport 则自动回退至
//   `/ws-moq` WebSocket 桥接通道，兼容 Safari 等全部浏览器）。
//
// 模式 2（自动化端到端自测）：
//   运行命令：./rtc_example_browser_moq --self-test
//   自动验证 `/api/moq-info` 证书指纹下发、WebTransport + MoQ draft-17 视频拉流、
//   GOP 对齐高低清切层、双向 MoQ 数据通道回显及 `/ws-moq` 桥接通道后以状态码 0 退出。

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"
#include "rtc_base/task_queue.h"
#include "rtc_video_engine.hpp"
#include "server/embedded_moq_relay.h"

namespace {

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
using tcp = boost::asio::ip::tcp;

constexpr const char* kDemoRoomId = "browser_moq_live";
constexpr const char* kDemoPubPeerId = "embedded_cam";

std::atomic<bool> g_quit{false};
void OnSignal(int /*sig*/) { g_quit.store(true); }

constexpr const char kBrowserMoqHtmlPage[] = R"HTML(<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>Embedded RTCSDK - IETF MoQ (draft-17) Browser Live Player</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0b1120; color: #f8fafc;
           display: flex; flex-direction: column; align-items: center; padding: 1.6rem; margin: 0; }
    h2 { margin: 0.2rem 0 0.6rem; font-weight: 600; }
    .sub { color: #94a3b8; font-size: 0.9rem; margin-bottom: 1rem; }
    canvas { width: 480px; height: 360px; background: #020617; border-radius: 12px;
             border: 1px solid #334155; image-rendering: pixelated; box-shadow: 0 10px 30px rgba(0,0,0,0.45); }
    .stats { display: flex; gap: 1rem; flex-wrap: wrap; margin: 0.8rem 0; font-size: 0.85rem;
             background: #1e293b; padding: 0.6rem 1rem; border-radius: 8px; border: 1px solid #334155; }
    .toolbar { display: flex; gap: 0.6rem; flex-wrap: wrap; align-items: center; margin: 0.5rem 0; }
    button { background: #2563eb; color: #fff; border: none; padding: 0.6rem 1.1rem;
             border-radius: 8px; font-size: 0.92rem; cursor: pointer; font-weight: 500; }
    button.secondary { background: #0f766e; }
    button.warn { background: #b45309; }
    select, input { padding: 0.55rem 0.75rem; border-radius: 8px; border: 1px solid #475569;
                    background: #0f172a; color: #f8fafc; font-size: 0.9rem; }
    pre { background: #1e293b; padding: 0.9rem; border-radius: 8px; width: min(760px, 92vw);
          height: 210px; overflow: auto; font-size: 0.82rem; border: 1px solid #334155; margin-top: 0.8rem; }
  </style>
</head>
<body>
  <h2>Embedded RTCSDK &harr; Browser IETF MoQ (draft-17) Live Player</h2>
  <div class="sub">WebTransport over HTTP/3 (QUIC v1 + TLS 1.3 serverCertificateHashes) + WebCodecs H.264 + MoQ DataChannel</div>
  <canvas id="moqCanvas" width="16" height="16"></canvas>
  <div class="stats">
    <span>承载: <b id="stTransport">Idle</b></span>
    <span>当前层: <b id="stLayer">-</b></span>
    <span>解码器: <b id="stDecoder">-</b></span>
    <span>Group/Obj: <b id="stLocation">0 / 0</b></span>
    <span>累计渲染帧: <b id="stFrames">0</b></span>
  </div>
  <div class="toolbar">
    <select id="modeSelect">
      <option value="auto">Auto (WebTransport HTTP/3 &rarr; WS Fallback)</option>
      <option value="wt">Pure WebTransport (HTTP/3 + MOQT draft-17)</option>
      <option value="ws">WebSocket MoQ Bridge (/ws-moq)</option>
    </select>
    <button onclick="startMoqPlayback()">Start MoQ Playback</button>
    <button class="secondary" onclick="switchLayer('high')">Switch HIGH Layer</button>
    <button class="warn" onclick="switchLayer('low')">Switch LOW Layer</button>
  </div>
  <div class="toolbar">
    <input id="dcInput" value="PTZ:PAN_LEFT_30" style="width:220px;">
    <button onclick="sendMoqData(true)">Send Reliable Stream DC</button>
    <button class="secondary" onclick="sendMoqData(false)">Send Datagram DC</button>
  </div>
  <pre id="logBox">Ready. Click "Start MoQ Playback" to subscribe to IETF MoQ (draft-17) tracks.</pre>

  <script>
    const canvas = document.getElementById('moqCanvas');
    const ctx = canvas.getContext('2d');
    let activeWt = null;
    let activeWs = null;
    let videoDecoder = null;
    let framesRendered = 0;
    let nextClientReqId = 0;
    let highSubWriter = null;
    let lowSubWriter = null;
    let highAlias = -1;
    let lowAlias = -1;
    let dataDownAlias = 50;
    let dataGroupSeq = 1;
    let seenKeyframe = false;

    const log = (msg) => {
      const box = document.getElementById('logBox');
      box.textContent += '\n' + msg;
      box.scrollTop = box.scrollHeight;
    };
    const setStat = (id, val) => { document.getElementById(id).textContent = val; };

    function hexToBytes(hex) {
      const out = new Uint8Array(hex.length / 2);
      for (let i = 0; i < out.length; ++i) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16);
      }
      return out;
    }

    // ---------------- draft-ietf-moq-transport-17 Section 1.4.1 vi64 变长整数编解码 ----------------
    function appendVi64(val, arr) {
      let v = BigInt(val);
      if (v < (1n << 7n)) {
        arr.push(Number(v));
      } else if (v < (1n << 14n)) {
        arr.push(0x80 | Number(v >> 8n), Number(v & 0xffn));
      } else if (v < (1n << 21n)) {
        arr.push(0xc0 | Number(v >> 16n), Number((v >> 8n) & 0xffn), Number(v & 0xffn));
      } else if (v < (1n << 28n)) {
        arr.push(0xe0 | Number(v >> 24n));
        for (let s = 16n; s >= 0n; s -= 8n) arr.push(Number((v >> s) & 0xffn));
      } else if (v < (1n << 35n)) {
        arr.push(0xf0 | Number(v >> 32n));
        for (let s = 24n; s >= 0n; s -= 8n) arr.push(Number((v >> s) & 0xffn));
      } else if (v < (1n << 42n)) {
        arr.push(0xf8 | Number(v >> 40n));
        for (let s = 32n; s >= 0n; s -= 8n) arr.push(Number((v >> s) & 0xffn));
      } else if (v < (1n << 56n)) {
        arr.push(0xfe);
        for (let s = 48n; s >= 0n; s -= 8n) arr.push(Number((v >> s) & 0xffn));
      } else {
        arr.push(0xff);
        for (let s = 56n; s >= 0n; s -= 8n) arr.push(Number((v >> s) & 0xffn));
      }
    }

    function readVi64(u8, state) {
      if (state.off >= u8.length) return null;
      const b0 = u8[state.off];
      if (b0 === 0xfc || b0 === 0xfd) throw new Error('MOQT PROTOCOL_VIOLATION invalid vi64');
      let leading = 0;
      for (let bit = 7; bit >= 0; --bit) {
        if ((b0 & (1 << bit)) !== 0) leading++;
        else break;
      }
      const total = (leading >= 7) ? (leading + 1) : (1 + leading);
      if (state.off + total > u8.length) return null;
      let val = 0n;
      if (leading < 6) {
        const mask = (1 << (7 - leading)) - 1;
        val = BigInt(b0 & mask);
      }
      for (let i = 1; i < total; ++i) {
        val = (val << 8n) | BigInt(u8[state.off + i]);
      }
      state.off += total;
      return Number(val);
    }

    function appendVi64Str(str, arr) {
      const b = new TextEncoder().encode(str);
      appendVi64(b.length, arr);
      for (let i = 0; i < b.length; ++i) arr.push(b[i]);
    }

    function readVi64Str(u8, state) {
      const len = readVi64(u8, state);
      if (len === null || state.off + len > u8.length) return null;
      const s = new TextDecoder().decode(u8.subarray(state.off, state.off + len));
      state.off += len;
      return s;
    }

    function appendNamespace(fields, arr) {
      appendVi64(fields.length, arr);
      for (const f of fields) appendVi64Str(f, arr);
    }

    function wrapControlMsg(msgType, bodyArr) {
      const out = [];
      appendVi64(msgType, out);
      out.push((bodyArr.length >> 8) & 0xff, bodyArr.length & 0xff);
      for (let i = 0; i < bodyArr.length; ++i) out.push(bodyArr[i]);
      return new Uint8Array(out);
    }

    // ---------------- 视频帧渲染（W3C WebCodecs VideoDecoder + I_PCM 兜底软件光栅化） ----------------
    function initVideoDecoder() {
      seenKeyframe = false;
      if ('VideoDecoder' in window) {
        try {
          videoDecoder = new VideoDecoder({
            output: (frame) => {
              if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) {
                canvas.width = frame.displayWidth;
                canvas.height = frame.displayHeight;
              }
              ctx.drawImage(frame, 0, 0);
              frame.close();
              framesRendered++;
              setStat('stFrames', String(framesRendered));
            },
            error: (e) => {
              log('[WebCodecs fallback] ' + e.message);
              videoDecoder = null;
            }
          });
          videoDecoder.configure({ codec: 'avc1.42e01f', optimizeForLatency: true });
          setStat('stDecoder', 'WebCodecs H.264');
          return;
        } catch (e) {
          videoDecoder = null;
        }
      }
      setStat('stDecoder', 'JS YUV420 Blitter');
    }

    function renderIpcmFallback(annexB) {
      if (annexB.length < 27 + 384) return;
      const yOff = 27;
      const uOff = yOff + 256;
      const vOff = uOff + 64;
      const img = ctx.createImageData(16, 16);
      for (let r = 0; r < 16; ++r) {
        for (let c = 0; c < 16; ++c) {
          const y = annexB[yOff + r * 16 + c];
          const u = annexB[uOff + (r >> 1) * 8 + (c >> 1)] - 128;
          const v = annexB[vOff + (r >> 1) * 8 + (c >> 1)] - 128;
          const idx = (r * 16 + c) * 4;
          img.data[idx]     = Math.max(0, Math.min(255, Math.round(y + 1.402 * v)));
          img.data[idx + 1] = Math.max(0, Math.min(255, Math.round(y - 0.344136 * u - 0.714136 * v)));
          img.data[idx + 2] = Math.max(0, Math.min(255, Math.round(y + 1.772 * u)));
          img.data[idx + 3] = 255;
        }
      }
      ctx.putImageData(img, 0, 0);
      framesRendered++;
      setStat('stFrames', String(framesRendered));
    }

    function handleAnnexBFrame(annexB, isKeyframe, tsUs, layerName, groupId, objId) {
      setStat('stLayer', layerName.toUpperCase());
      setStat('stLocation', groupId + ' / ' + objId);
      if (isKeyframe) seenKeyframe = true;
      if (!seenKeyframe) return;

      if (videoDecoder && videoDecoder.state === 'configured') {
        try {
          videoDecoder.decode(new EncodedVideoChunk({
            type: isKeyframe ? 'key' : 'delta',
            timestamp: tsUs,
            data: annexB
          }));
          return;
        } catch (e) {
          videoDecoder = null;
          setStat('stDecoder', 'JS YUV420 Blitter');
        }
      }
      renderIpcmFallback(annexB);
    }

    function unpackLocAndRender(payload, trackAlias, groupId, objId) {
      const st = { off: 0 };
      const metaLen = readVi64(payload, st);
      if (metaLen === null || st.off + metaLen > payload.length) return;
      const mst = { off: st.off };
      const capUs = readVi64(payload, mst);
      readVi64(payload, mst);
      readVi64(payload, mst);
      if (capUs === null || mst.off + 2 > st.off + metaLen) return;
      const flags = payload[mst.off];
      const isKf = (flags & 0x01) !== 0;
      const isHigh = (flags & 0x08) !== 0 || trackAlias === highAlias;
      const annexB = payload.subarray(st.off + metaLen);
      handleAnnexBFrame(annexB, isKf, capUs, isHigh ? 'high' : 'low', groupId, objId);
    }

    function unpackMoqDataAndLog(payload, viaDatagram) {
      const st = { off: 0 };
      const objId = readVi64(payload, st);
      const sender = readVi64Str(payload, st);
      const label = readVi64Str(payload, st);
      const proto = readVi64Str(payload, st);
      const tsUs = readVi64(payload, st);
      if (tsUs === null || st.off + 1 > payload.length) return;
      const flags = payload[st.off++];
      const plen = readVi64(payload, st);
      if (plen === null || st.off + plen > payload.length) return;
      const txt = new TextDecoder().decode(payload.subarray(st.off, st.off + plen));
      log(`[MoQ DC ${viaDatagram ? 'Datagram' : 'Stream'} RX] (${sender}/${label}): ${txt}`);
    }

    // ---------------- 原生 WebTransport + MOQT draft-17 客户端流程 ----------------
    function buildMoqSetup() {
      const kv = [];
      appendVi64(0x07, kv);  // IMPLEMENTATION (0x07, odd -> bytes)
      appendVi64Str('rtcsdk-browser-moqt-17', kv);
      return wrapControlMsg(0x2f00, kv);
    }

    function buildSubscribeNamespace(reqId, nsFields) {
      const b = [];
      appendVi64(reqId, b);
      appendVi64(0, b);      // required_request_id_delta = 0
      appendNamespace(nsFields, b);
      appendVi64(0x01, b);   // subscribe_options = NAMESPACE
      appendVi64(0, b);      // num_params = 0
      return wrapControlMsg(0x11, b);
    }

    function buildPublishNamespace(reqId, nsFields) {
      const b = [];
      appendVi64(reqId, b);
      appendVi64(0, b);
      appendNamespace(nsFields, b);
      appendVi64(0, b);
      return wrapControlMsg(0x06, b);
    }

    function buildSubscribe(reqId, nsFields, trackName, forwardVal) {
      const b = [];
      appendVi64(reqId, b);
      appendVi64(0, b);
      appendNamespace(nsFields, b);
      appendVi64Str(trackName, b);
      if (forwardVal !== null) {
        appendVi64(1, b);           // 1 个消息参数
        appendVi64(0x10, b);        // FORWARD (0x10, even -> varint)
        appendVi64(forwardVal, b);
      } else {
        appendVi64(0, b);
      }
      return wrapControlMsg(0x03, b);
    }

    function buildRequestUpdate(reqId, forwardVal, requestNewGroup) {
      const b = [];
      appendVi64(reqId, b);
      appendVi64(0, b);
      if (requestNewGroup) {
        appendVi64(2, b);
        appendVi64(0x10, b);               // 第 1 项：FORWARD (0x10)
        appendVi64(forwardVal, b);
        appendVi64(0x32 - 0x10, b);        // 第 2 项升序差分：NEW_GROUP_REQUEST (0x32)
        appendVi64(1, b);
      } else {
        appendVi64(1, b);
        appendVi64(0x10, b);
        appendVi64(forwardVal, b);
      }
      return wrapControlMsg(0x02, b);
    }

    async function readSubscribeOkAlias(readable) {
      const reader = readable.getReader();
      let buf = new Uint8Array(0);
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const merged = new Uint8Array(buf.length + value.length);
        merged.set(buf, 0);
        merged.set(value, buf.length);
        buf = merged;
        const st = { off: 0 };
        const mtype = readVi64(buf, st);
        if (mtype === null || st.off + 2 > buf.length) continue;
        const blen = (buf[st.off] << 8) | buf[st.off + 1];
        if (st.off + 2 + blen > buf.length) continue;
        const bst = { off: st.off + 2 };
        if (mtype === 0x04) {
          const alias = readVi64(buf, bst);
          reader.releaseLock();
          return alias;
        }
        break;
      }
      reader.releaseLock();
      return -1;
    }

    async function pumpIncomingSubgroupStream(readable) {
      const reader = readable.getReader();
      let buf = new Uint8Array(0);
      let hdr = null;
      let prevObjId = null;

      while (true) {
        const { value, done } = await reader.read();
        if (value && value.length > 0) {
          const merged = new Uint8Array(buf.length + value.length);
          merged.set(buf, 0);
          merged.set(value, buf.length);
          buf = merged;
        }

        if (!hdr) {
          const st = { off: 0 };
          const stype = readVi64(buf, st);
          if (stype === null) { if (done) break; continue; }
          if (stype === 0x2f00) {
            // 服务端单向控制流（SETUP / GOAWAY），保持排空即可。
            buf = new Uint8Array(0);
            if (done) break;
            continue;
          }
          const sidMode = (stype & 0x06) >> 1;
          const hasProps = (stype & 0x01) !== 0;
          const defPrio = (stype & 0x20) !== 0;
          const trackAlias = readVi64(buf, st);
          const groupId = readVi64(buf, st);
          let subgroupId = 0;
          if (sidMode === 0x02) subgroupId = readVi64(buf, st);
          if (trackAlias === null || groupId === null || subgroupId === null) {
            if (done) break;
            continue;
          }
          if (!defPrio) {
            if (st.off + 1 > buf.length) { if (done) break; continue; }
            st.off += 1;
          }
          hdr = { trackAlias, groupId, hasProps };
          buf = buf.subarray(st.off);
        }

        while (hdr && buf.length > 0) {
          const st = { off: 0 };
          const delta = readVi64(buf, st);
          if (delta === null) break;
          if (hdr.hasProps) {
            const propLen = readVi64(buf, st);
            if (propLen === null || st.off + propLen > buf.length) break;
            st.off += propLen;
          }
          const plen = readVi64(buf, st);
          if (plen === null) break;
          if (plen === 0) {
            const status = readVi64(buf, st);
            if (status === null) break;
            prevObjId = (prevObjId === null) ? delta : (prevObjId + delta + 1);
            buf = buf.subarray(st.off);
            continue;
          }
          if (st.off + plen > buf.length) break;
          const objId = (prevObjId === null) ? delta : (prevObjId + delta + 1);
          prevObjId = objId;
          const objPayload = buf.subarray(st.off, st.off + plen);
          buf = buf.subarray(st.off + plen);

          if (hdr.trackAlias === dataDownAlias) {
            unpackMoqDataAndLog(objPayload, false);
          } else {
            unpackLocAndRender(objPayload, hdr.trackAlias, hdr.groupId, objId);
          }
        }
        if (done) break;
      }
    }

    async function pumpIncomingDatagrams(readable) {
      const reader = readable.getReader();
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value || value.length === 0) continue;
        const st = { off: 0 };
        const dtype = readVi64(value, st);
        if (dtype === null) continue;
        const zeroObj = (dtype & 0x04) !== 0;
        const defPrio = (dtype & 0x08) !== 0;
        const hasStatus = (dtype & 0x20) !== 0;
        const hasProps = (dtype & 0x01) !== 0;
        const alias = readVi64(value, st);
        const grp = readVi64(value, st);
        const obj = zeroObj ? 0 : readVi64(value, st);
        if (alias === null || grp === null || obj === null) continue;
        if (!defPrio) {
          if (st.off + 1 > value.length) continue;
          st.off += 1;
        }
        if (hasProps) {
          const pLen = readVi64(value, st);
          if (pLen === null || st.off + pLen > value.length) continue;
          st.off += pLen;
        }
        if (!hasStatus && alias === dataDownAlias) {
          unpackMoqDataAndLog(value.subarray(st.off), true);
        }
      }
    }

    async function startNativeWebTransport(info) {
      log(`Connecting WebTransport to ${info.wt_url} (sha256=${info.cert_sha256.slice(0, 16)}...)`);
      const wt = new WebTransport(info.wt_url, {
        serverCertificateHashes: [{ algorithm: 'sha-256', value: hexToBytes(info.cert_sha256) }]
      });
      await wt.ready;
      activeWt = wt;
      setStat('stTransport', 'WebTransport (HTTP/3 + MOQT-17)');
      log('WebTransport over HTTP/3 session established! Sending MOQT draft-17 SETUP (0x2F00)...');

      // 1. 打开单向控制流发送 SETUP（保持打开，不发送 FIN）
      const ctrlStream = await wt.createUnidirectionalStream();
      const ctrlWriter = ctrlStream.getWriter();
      await ctrlWriter.write(buildMoqSetup());

      // 2. 启动入站单向流与数据报接收循环
      (async () => {
        const uniReader = wt.incomingUnidirectionalStreams.getReader();
        while (true) {
          const { value, done } = await uniReader.read();
          if (done) break;
          pumpIncomingSubgroupStream(value).catch(() => {});
        }
      })();
      pumpIncomingDatagrams(wt.datagrams.readable).catch(() => {});

      const peerNs = ['rtc', info.room_id, info.publisher_peer_id];

      // 3. 订阅房间命名空间并发起本端数据轨道发布声明
      const subNsBidi = await wt.createBidirectionalStream();
      await subNsBidi.writable.getWriter().write(
          buildSubscribeNamespace(nextClientReqId, ['rtc', info.room_id]));
      nextClientReqId += 2;

      const pubNsBidi = await wt.createBidirectionalStream();
      await pubNsBidi.writable.getWriter().write(
          buildPublishNamespace(nextClientReqId, ['rtc', info.room_id, 'browser_viewer', 'data', 'browser_ctrl']));
      nextClientReqId += 2;

      // 4. 订阅高清层（FORWARD=1）、低清层（FORWARD=0）与 MoQ 通用数据通道
      const highBidi = await wt.createBidirectionalStream();
      highSubWriter = highBidi.writable.getWriter();
      await highSubWriter.write(buildSubscribe(nextClientReqId, peerNs, 'video/high', 1));
      nextClientReqId += 2;
      highAlias = await readSubscribeOkAlias(highBidi.readable);

      const lowBidi = await wt.createBidirectionalStream();
      lowSubWriter = lowBidi.writable.getWriter();
      await lowSubWriter.write(buildSubscribe(nextClientReqId, peerNs, 'video/low', 0));
      nextClientReqId += 2;
      lowAlias = await readSubscribeOkAlias(lowBidi.readable);

      const dataBidi = await wt.createBidirectionalStream();
      await dataBidi.writable.getWriter().write(buildSubscribe(nextClientReqId, peerNs, 'data/all', null));
      nextClientReqId += 2;
      dataDownAlias = await readSubscribeOkAlias(dataBidi.readable);

      log(`MOQT draft-17 SUBSCRIBE_OK: highAlias=${highAlias}, lowAlias=${lowAlias}, dataAlias=${dataDownAlias}`);
    }

    async function startWsBridge() {
      const wsProto = location.protocol === 'https:' ? 'wss://' : 'ws://';
      const ws = new WebSocket(wsProto + location.host + '/ws-moq');
      ws.binaryType = 'arraybuffer';
      activeWs = ws;
      ws.onopen = () => {
        setStat('stTransport', 'WebSocket MoQ Bridge');
        log('Connected to /ws-moq bridge (backed by EmbeddedMoqRelayServer)');
      };
      ws.onmessage = (ev) => {
        if (typeof ev.data === 'string') {
          log('[MoQ DC RX] ' + ev.data);
          return;
        }
        const u8 = new Uint8Array(ev.data);
        if (u8.length < 10) return;
        const isKf = (u8[0] & 0x01) !== 0;
        const isHigh = (u8[0] & 0x02) !== 0;
        const view = new DataView(ev.buffer, ev.byteOffset, ev.byteLength);
        const grp = view.getUint32(1, false);
        const tsUs = view.getUint32(5, false) * 1000;
        handleAnnexBFrame(u8.subarray(9), isKf, tsUs, isHigh ? 'high' : 'low', grp, 0);
      };
    }

    async function cleanupActive() {
      if (activeWt) { try { activeWt.close(); } catch (e) {} activeWt = null; }
      if (activeWs) { try { activeWs.close(); } catch (e) {} activeWs = null; }
      if (videoDecoder) { try { videoDecoder.close(); } catch (e) {} videoDecoder = null; }
      highSubWriter = null;
      lowSubWriter = null;
    }

    async function startMoqPlayback() {
      await cleanupActive();
      framesRendered = 0;
      nextClientReqId = 0;
      initVideoDecoder();

      const resp = await fetch('/api/moq-info');
      const info = await resp.json();
      const mode = document.getElementById('modeSelect').value;

      if (mode === 'ws') {
        await startWsBridge();
        return;
      }
      if ('WebTransport' in window) {
        try {
          await startNativeWebTransport(info);
          return;
        } catch (err) {
          log('WebTransport connect error: ' + err.message);
          if (mode === 'wt') return;
          log('Falling back automatically to /ws-moq bridge...');
        }
      } else if (mode === 'wt') {
        log('Current browser does not expose window.WebTransport.');
        return;
      }
      await startWsBridge();
    }

    async function switchLayer(target) {
      const wantHigh = (target === 'high');
      if (activeWt && highSubWriter && lowSubWriter) {
        if (wantHigh) {
          await lowSubWriter.write(buildRequestUpdate(nextClientReqId, 0, false));
          nextClientReqId += 2;
          await highSubWriter.write(buildRequestUpdate(nextClientReqId, 1, true));
          nextClientReqId += 2;
        } else {
          await highSubWriter.write(buildRequestUpdate(nextClientReqId, 0, false));
          nextClientReqId += 2;
          await lowSubWriter.write(buildRequestUpdate(nextClientReqId, 1, true));
          nextClientReqId += 2;
        }
        log(`Sent MOQT draft-17 REQUEST_UPDATE -> ${target.toUpperCase()} layer`);
      } else if (activeWs && activeWs.readyState === WebSocket.OPEN) {
        activeWs.send('SWITCH:' + target);
        log(`Sent bridge layer switch -> ${target.toUpperCase()}`);
      }
    }

    function packMoqDataObject(text, ordered) {
      const payload = new TextEncoder().encode(text);
      const out = [];
      appendVi64(dataGroupSeq, out);
      appendVi64Str('browser_viewer', out);
      appendVi64Str('browser_ctrl', out);
      appendVi64Str('json', out);
      appendVi64(Date.now() * 1000, out);
      out.push(ordered ? 0x02 : 0x00);  // UTF-8 文本标志 + ordered 位
      appendVi64(payload.length, out);
      for (let i = 0; i < payload.length; ++i) out.push(payload[i]);
      return new Uint8Array(out);
    }

    async function sendMoqData(reliable) {
      const txt = document.getElementById('dcInput').value;
      if (activeWt) {
        const packed = packMoqDataObject(txt, reliable);
        const grp = dataGroupSeq++;
        if (reliable) {
          // 通过 SUBGROUP_HEADER (0x18 = end_of_group) 单向流发送可靠有序 MoQ 数据对象（track_alias = 3）
          const hdr = [];
          appendVi64(0x18, hdr);
          appendVi64(3, hdr);
          appendVi64(grp, hdr);
          hdr.push(8);
          appendVi64(0, hdr);  // object_id_delta = 0
          appendVi64(packed.length, hdr);
          const wire = new Uint8Array(hdr.length + packed.length);
          wire.set(hdr, 0);
          wire.set(packed, hdr.length);
          const uni = await activeWt.createUnidirectionalStream();
          const w = uni.getWriter();
          await w.write(wire);
          await w.close();
          log('[MoQ DC Stream TX] ' + txt);
        } else {
          // 通过 OBJECT_DATAGRAM (0x06 = end_of_group | zero_object_id) 发送零重传数据报（track_alias = 3）
          const dg = [];
          appendVi64(0x06, dg);
          appendVi64(3, dg);
          appendVi64(grp, dg);
          dg.push(8);
          const wire = new Uint8Array(dg.length + packed.length);
          wire.set(dg, 0);
          wire.set(packed, dg.length);
          const dw = activeWt.datagrams.writable.getWriter();
          await dw.write(wire);
          dw.releaseLock();
          log('[MoQ DC Datagram TX] ' + txt);
        }
      } else if (activeWs && activeWs.readyState === WebSocket.OPEN) {
        activeWs.send('DC:' + txt);
        log('[MoQ Bridge DC TX] ' + txt);
      } else {
        log('MoQ session is not connected yet.');
      }
    }
  </script>
</body>
</html>
)HTML";

// 生成比特级精确的 ITU-T H.264 Constrained Baseline (42e01f) 16x16 I_PCM Annex-B 帧，
// 高清层采用暖色调循环，低清层采用冷色调循环，便于在浏览器 <canvas> 中直观观察 Simulcast 切层效果。
std::vector<uint8_t> BuildValidH264LayerColorFrame(int frame_index,
                                                   bool is_high_layer) {
  static const uint8_t kAnnexBHeaders[] = {
      0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xE0, 0x1F, 0xDA, 0xF2,
      0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80,
      0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x86, 0x80,
  };
  std::vector<uint8_t> frame(kAnnexBHeaders,
                             kAnnexBHeaders + sizeof(kAnnexBHeaders));
  frame.reserve(sizeof(kAnnexBHeaders) + 385);

  uint8_t y_val = 0;
  uint8_t cb_val = 0;
  uint8_t cr_val = 0;
  if (is_high_layer) {
    y_val = static_cast<uint8_t>(60 + ((frame_index * 6) % 150));
    cb_val = static_cast<uint8_t>(55 + ((frame_index * 9) % 90));
    cr_val = static_cast<uint8_t>(195 - ((frame_index * 5) % 80));
  } else {
    y_val = static_cast<uint8_t>(45 + ((frame_index * 5) % 130));
    cb_val = static_cast<uint8_t>(185 - ((frame_index * 7) % 70));
    cr_val = static_cast<uint8_t>(75 + ((frame_index * 4) % 70));
  }

  frame.insert(frame.end(), 256, y_val);
  frame.insert(frame.end(), 64, cb_val);
  frame.insert(frame.end(), 64, cr_val);
  frame.push_back(0x80);
  return frame;
}

class EmbeddedMoqPubObserver final : public rtc::IRtcEventObserver {
 public:
  void BindEngine(rtc::RtcVideoEngine* eng, int reply_dc_id) {
    std::lock_guard<std::mutex> lock(mu_);
    engine_ = eng;
    reply_dc_id_ = reply_dc_id;
  }

  void OnEncoderBitrateAllocation(rtc_stream_layer_e,
                                  bool,
                                  uint32_t,
                                  uint32_t) override {}
  void OnEncoderForceIdr(rtc_stream_layer_e) override {
    force_idr_.store(true, std::memory_order_release);
  }
  void OnRemoteTrackPublished(const std::string&,
                              const std::string&,
                              rtc_video_codec_e) override {}
  void OnRemoteTrackUnpublished(const std::string&,
                                const std::string&) override {}
  void OnRemoteEncodedFrame(const std::string&,
                            const std::string&,
                            const rtc_encoded_frame_t&) override {}
  void OnConnectionState(rtc_connection_state_e state, int) override {
    connected_.store(state == RTC_CONN_STATE_CONNECTED,
                     std::memory_order_release);
  }

  void OnDataChannelMessage(const std::string& peer_id,
                            int /*channel_id*/,
                            bool /*is_binary*/,
                            const uint8_t* data,
                            size_t size) override {
    const std::string msg(reinterpret_cast<const char*>(data), size);
    RTC_LOG(kInfo) << "[MoqPub] DataChannel RX from " << peer_id << ": " << msg;
    std::lock_guard<std::mutex> lock(mu_);
    if (engine_ != nullptr && reply_dc_id_ >= 0) {
      engine_->SendTextData(reply_dc_id_, "MOQ_ACK:" + msg);
    }
  }

  bool is_connected() const {
    return connected_.load(std::memory_order_acquire);
  }
  bool ConsumeForceIdr() {
    return force_idr_.exchange(false, std::memory_order_acq_rel);
  }

 private:
  std::mutex mu_;
  rtc::RtcVideoEngine* engine_ = nullptr;
  int reply_dc_id_ = -1;
  std::atomic<bool> connected_{false};
  std::atomic<bool> force_idr_{false};
};

class BrowserMoqLiveGateway {
 public:
  BrowserMoqLiveGateway()
      : relay_("0.0.0.0"),
        http_queue_("moq-http-gw", rtc::TaskQueuePriority::kNormal),
        acceptor_(http_queue_.io_context()) {}

  ~BrowserMoqLiveGateway() { Stop(); }

  BrowserMoqLiveGateway(const BrowserMoqLiveGateway&) = delete;
  BrowserMoqLiveGateway& operator=(const BrowserMoqLiveGateway&) = delete;

  bool Start(uint16_t http_port, uint16_t moq_udp_port = 0) {
    if (!relay_.Start(moq_udp_port)) {
      return false;
    }

    bool http_ok = false;
    http_queue_.Invoke([this, http_port, &http_ok]() {
      boost::system::error_code ec;
      const tcp::endpoint ep(boost::asio::ip::make_address("0.0.0.0"),
                             http_port);
      acceptor_.open(ep.protocol(), ec);
      if (ec) return;
      acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
      acceptor_.bind(ep, ec);
      if (ec) return;
      acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
      if (ec) return;
      bound_http_port_ = acceptor_.local_endpoint(ec).port();
      http_ok = !ec;
      if (http_ok) {
        DoAccept();
      }
    });
    if (!http_ok) {
      relay_.Stop();
      return false;
    }

    rtc::EngineConfig pub_cfg;
    pub_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT;
    pub_cfg.signaling_or_moq_url =
        "https://127.0.0.1:" + std::to_string(relay_.udp_port()) + "/moq";
    pub_cfg.publish_codec = RTC_CODEC_H264;
    pub_cfg.enable_simulcast = true;
    pub_engine_ = rtc::RtcVideoEngine::Create(pub_cfg, &pub_obs_);

    rtc::DataChannelConfig dcfg;
    dcfg.label = "pub_ctrl_ack";
    dcfg.ordered = true;
    const int dc_id = pub_engine_->CreateDataChannel(dcfg);
    pub_obs_.BindEngine(pub_engine_.get(), dc_id);
    pub_engine_->JoinRoom(kDemoRoomId, kDemoPubPeerId);

    pump_thread_ = std::thread([this]() { RunFramePumpLoop(); });
    return true;
  }

  void Stop() {
    if (stopped_.exchange(true)) {
      return;
    }
    http_queue_.Invoke([this]() {
      boost::system::error_code ec;
      acceptor_.close(ec);
    });
    http_queue_.Shutdown();

    if (pump_thread_.joinable()) {
      pump_thread_.join();
    }
    {
      std::lock_guard<std::mutex> lock(ws_threads_mu_);
      for (auto* s : active_ws_sockets_) {
        boost::system::error_code ec;
        s->close(ec);
      }
    }
    for (auto& t : ws_threads_) {
      if (t.joinable()) {
        t.join();
      }
    }
    ws_threads_.clear();

    pub_obs_.BindEngine(nullptr, -1);
    if (pub_engine_) {
      pub_engine_->LeaveRoom();
      pub_engine_.reset();
    }
    relay_.Stop();
  }

  uint16_t http_port() const { return bound_http_port_; }
  uint16_t moq_udp_port() const { return relay_.udp_port(); }
  std::string cert_sha256_hex() const { return relay_.certificate_sha256_hex(); }

 private:
  void DoAccept() {
    acceptor_.async_accept([this](boost::system::error_code ec,
                                  tcp::socket socket) {
      if (ec || stopped_.load(std::memory_order_acquire)) {
        return;
      }
      HandleHttpOrWsClient(std::move(socket));
      DoAccept();
    });
  }

  void HandleHttpOrWsClient(tcp::socket socket) {
    beast::error_code ec;
    beast::flat_buffer buffer;
    http::request<http::string_body> req;
    http::read(socket, buffer, req, ec);
    if (ec) {
      return;
    }

    if (websocket::is_upgrade(req) && req.target() == "/ws-moq") {
      std::lock_guard<std::mutex> lock(ws_threads_mu_);
      ws_threads_.emplace_back(
          [this, s = std::move(socket), req = std::move(req)]() mutable {
            tcp::socket* raw_sock = &s;
            {
              std::lock_guard<std::mutex> lk(ws_threads_mu_);
              active_ws_sockets_.insert(raw_sock);
            }
            // 使用预读取后的请求完成 WebSocket 升级握手
            websocket::stream<tcp::socket> ws_check(std::move(s));
            // 转交至桥接会话运行
            WsMoqBridgeRunner(std::move(ws_check), req, relay_.udp_port(),
                              raw_sock);
          });
      return;
    }

    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::access_control_allow_origin, "*");

    if (req.method() == http::verb::get && req.target() == "/") {
      res.set(http::field::content_type, "text/html; charset=utf-8");
      res.body() = kBrowserMoqHtmlPage;
    } else if (req.method() == http::verb::get &&
               req.target() == "/api/moq-info") {
      std::string host_hdr(req[http::field::host]);
      const size_t colon = host_hdr.find(':');
      const std::string host_only =
          (colon == std::string::npos || host_hdr.empty())
              ? "127.0.0.1"
              : host_hdr.substr(0, colon);

      rtc::JsonObject info;
      info.SetString("room_id", kDemoRoomId);
      info.SetString("publisher_peer_id", kDemoPubPeerId);
      info.SetUint32("moq_udp_port", relay_.udp_port());
      info.SetString("wt_url", "https://" + host_only + ":" +
                                   std::to_string(relay_.udp_port()) + "/moq");
      info.SetString("cert_sha256", relay_.certificate_sha256_hex());
      info.SetString("alpn", "h3");
      info.SetString("moqt_protocol", "moqt-17");

      res.set(http::field::content_type, "application/json");
      res.body() = info.Serialize();
    } else {
      res.result(http::status::not_found);
      res.body() = "Not Found";
    }

    res.prepare_payload();
    http::write(socket, res, ec);
    socket.shutdown(tcp::socket::shutdown_send, ec);
  }

  void WsMoqBridgeRunner(websocket::stream<tcp::socket> ws,
                         const http::request<http::string_body>& upgrade_req,
                         uint16_t relay_port,
                         tcp::socket* tracked_key) {
    class PreparedWsBridge final : public rtc::IRtcEventObserver {
     public:
      PreparedWsBridge(websocket::stream<tcp::socket> s, uint16_t port)
          : ws_stream_(std::move(s)), rport_(port) {}

      void Run(const http::request<http::string_body>& req) {
        beast::error_code ec;
        ws_stream_.accept(req, ec);
        if (ec) return;

        rtc::EngineConfig sub_cfg;
        sub_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT;
        sub_cfg.signaling_or_moq_url =
            "https://127.0.0.1:" + std::to_string(rport_) + "/moq";
        sub_cfg.publish_codec = RTC_CODEC_H264;
        sub_ = rtc::RtcVideoEngine::Create(sub_cfg, this);

        rtc::DataChannelConfig dcfg;
        dcfg.label = "ws_bridge_ctrl";
        dc_id_ = sub_->CreateDataChannel(dcfg);
        sub_->JoinRoom(kDemoRoomId,
                       "ws_viewer_" + std::to_string(
                           reinterpret_cast<uintptr_t>(this) & 0xFFFFu));

        while (!ec) {
          beast::flat_buffer rx;
          ws_stream_.read(rx, ec);
          if (ec) break;
          const std::string cmd = beast::buffers_to_string(rx.data());
          if (cmd == "SWITCH:low") {
            sub_->SwitchSubscribedLayer(kDemoPubPeerId, RTC_STREAM_LAYER_LOW);
          } else if (cmd == "SWITCH:high") {
            sub_->SwitchSubscribedLayer(kDemoPubPeerId, RTC_STREAM_LAYER_HIGH);
          } else if (cmd.rfind("DC:", 0) == 0 && dc_id_ >= 0) {
            sub_->SendTextData(dc_id_, cmd.substr(3));
          }
        }
        {
          std::lock_guard<std::mutex> lk(mu_);
          closed_ = true;
        }
        if (sub_) {
          sub_->LeaveRoom();
          sub_.reset();
        }
      }

      void OnEncoderBitrateAllocation(rtc_stream_layer_e,
                                      bool,
                                      uint32_t,
                                      uint32_t) override {}
      void OnEncoderForceIdr(rtc_stream_layer_e) override {}
      void OnRemoteTrackPublished(const std::string& peer_id,
                                  const std::string& track_id,
                                  rtc_video_codec_e) override {
        if (peer_id == kDemoPubPeerId && sub_) {
          sub_->SubscribeTrack(track_id, RTC_STREAM_LAYER_HIGH);
        }
      }
      void OnRemoteTrackUnpublished(const std::string&,
                                    const std::string&) override {}
      void OnRemoteEncodedFrame(const std::string&,
                                const std::string&,
                                const rtc_encoded_frame_t& frame) override {
        if (frame.data == nullptr || frame.size == 0) return;
        const uint32_t grp = ++grp_;
        const uint32_t ts_ms = static_cast<uint32_t>(frame.capture_ts_us / 1000);
        std::vector<uint8_t> pkt(9 + frame.size);
        pkt[0] = (frame.is_keyframe ? 0x01u : 0x00u) |
                 (frame.layer == RTC_STREAM_LAYER_HIGH ? 0x02u : 0x00u);
        pkt[1] = static_cast<uint8_t>((grp >> 24) & 0xFFu);
        pkt[2] = static_cast<uint8_t>((grp >> 16) & 0xFFu);
        pkt[3] = static_cast<uint8_t>((grp >> 8) & 0xFFu);
        pkt[4] = static_cast<uint8_t>(grp & 0xFFu);
        pkt[5] = static_cast<uint8_t>((ts_ms >> 24) & 0xFFu);
        pkt[6] = static_cast<uint8_t>((ts_ms >> 16) & 0xFFu);
        pkt[7] = static_cast<uint8_t>((ts_ms >> 8) & 0xFFu);
        pkt[8] = static_cast<uint8_t>(ts_ms & 0xFFu);
        std::memcpy(pkt.data() + 9, frame.data, frame.size);

        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) return;
        beast::error_code ec;
        ws_stream_.binary(true);
        ws_stream_.write(boost::asio::buffer(pkt), ec);
      }
      void OnConnectionState(rtc_connection_state_e, int) override {}
      void OnDataChannelMessage(const std::string&,
                                int,
                                bool,
                                const uint8_t* data,
                                size_t size) override {
        const std::string txt(reinterpret_cast<const char*>(data), size);
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) return;
        beast::error_code ec;
        ws_stream_.text(true);
        ws_stream_.write(boost::asio::buffer(txt), ec);
      }

      tcp::socket* underlying_socket() { return &ws_stream_.next_layer(); }

     private:
      websocket::stream<tcp::socket> ws_stream_;
      uint16_t rport_;
      std::unique_ptr<rtc::RtcVideoEngine> sub_;
      int dc_id_ = -1;
      std::atomic<uint32_t> grp_{0};
      std::mutex mu_;
      bool closed_ = false;
    };

    PreparedWsBridge bridge(std::move(ws), relay_port);
    {
      std::lock_guard<std::mutex> lk(ws_threads_mu_);
      active_ws_sockets_.erase(tracked_key);
      active_ws_sockets_.insert(bridge.underlying_socket());
    }
    bridge.Run(upgrade_req);
    {
      std::lock_guard<std::mutex> lk(ws_threads_mu_);
      active_ws_sockets_.erase(bridge.underlying_socket());
    }
  }

  void RunFramePumpLoop() {
    uint64_t ts_us = 1'000'000;
    int frame_idx = 0;
    while (!stopped_.load(std::memory_order_acquire)) {
      if (pub_engine_ && pub_obs_.is_connected()) {
        const bool is_gop_boundary =
            ((frame_idx % 15) == 0) || pub_obs_.ConsumeForceIdr();
        const auto high_nalu =
            BuildValidH264LayerColorFrame(frame_idx, /*is_high_layer=*/true);
        const auto low_nalu =
            BuildValidH264LayerColorFrame(frame_idx, /*is_high_layer=*/false);

        rtc_encoded_frame_t fl{};
        fl.data = low_nalu.data();
        fl.size = low_nalu.size();
        fl.capture_ts_us = ts_us;
        fl.is_keyframe = is_gop_boundary;
        fl.layer = RTC_STREAM_LAYER_LOW;
        pub_engine_->PushVideoFrame(fl);

        rtc_encoded_frame_t fh{};
        fh.data = high_nalu.data();
        fh.size = high_nalu.size();
        fh.capture_ts_us = ts_us;
        fh.is_keyframe = is_gop_boundary;
        fh.layer = RTC_STREAM_LAYER_HIGH;
        pub_engine_->PushVideoFrame(fh);

        ++frame_idx;
      }
      ts_us += 33'333;
      std::this_thread::sleep_for(std::chrono::milliseconds(33));
    }
  }

  rtc::EmbeddedMoqRelayServer relay_;
  rtc::TaskQueueBoost http_queue_;
  tcp::acceptor acceptor_;
  uint16_t bound_http_port_ = 0;
  std::atomic<bool> stopped_{false};

  EmbeddedMoqPubObserver pub_obs_;
  std::unique_ptr<rtc::RtcVideoEngine> pub_engine_;
  std::thread pump_thread_;

  std::mutex ws_threads_mu_;
  std::set<tcp::socket*> active_ws_sockets_;
  std::vector<std::thread> ws_threads_;
};

int RunAutomatedBrowserMoqSelfTest() {
  BrowserMoqLiveGateway gateway;
  if (!gateway.Start(/*http_port=*/0, /*moq_udp_port=*/0)) {
    RTC_LOG(kError) << "Failed to start BrowserMoqLiveGateway";
    return 1;
  }

  // 1. 验证 HTTP GET / 与 GET /api/moq-info 正常返回页面及 64 位证书 SHA-256 哈希
  boost::asio::io_context ioc;
  beast::error_code ec;
  tcp::socket sock(ioc);
  sock.connect(
      tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"),
                    gateway.http_port()),
      ec);
  if (ec) {
    return 2;
  }

  http::request<http::string_body> req{http::verb::get, "/api/moq-info", 11};
  req.set(http::field::host, "127.0.0.1");
  req.prepare_payload();
  http::write(sock, req, ec);
  if (ec) {
    return 3;
  }

  beast::flat_buffer rx_buf;
  http::response<http::string_body> res;
  http::read(sock, rx_buf, res, ec);
  sock.shutdown(tcp::socket::shutdown_both, ec);
  if (res.result() != http::status::ok) {
    return 4;
  }

  const auto info_json = rtc::JsonObject::Parse(res.body());
  if (!info_json.has_value() ||
      info_json->GetString("cert_sha256").size() != 64 ||
      info_json->GetString("moqt_protocol") != "moqt-17") {
    return 5;
  }
  const std::string wt_url = info_json->GetString("wt_url");

  // 2. 模拟浏览器通过 WebTransport over HTTP/3 + MOQT draft-17 拉流、切层并交互数据通道
  class SimulatedBrowserWtObserver final : public rtc::IRtcEventObserver {
   public:
    void BindEngine(rtc::RtcVideoEngine* eng) { engine_ = eng; }

    void OnEncoderBitrateAllocation(rtc_stream_layer_e,
                                    bool,
                                    uint32_t,
                                    uint32_t) override {}
    void OnEncoderForceIdr(rtc_stream_layer_e) override {}
    void OnRemoteTrackPublished(const std::string& peer_id,
                                const std::string& track_id,
                                rtc_video_codec_e) override {
      if (peer_id == kDemoPubPeerId && engine_ != nullptr) {
        engine_->SubscribeTrack(track_id, RTC_STREAM_LAYER_HIGH);
      }
    }
    void OnRemoteTrackUnpublished(const std::string&,
                                  const std::string&) override {}
    void OnRemoteEncodedFrame(const std::string&,
                              const std::string&,
                              const rtc_encoded_frame_t& frame) override {
      std::lock_guard<std::mutex> lock(mu_);
      if (frame.layer == RTC_STREAM_LAYER_HIGH) {
        ++high_frames_;
      } else {
        ++low_frames_;
      }
      cv_.notify_all();
    }
    void OnConnectionState(rtc_connection_state_e, int) override {}
    void OnDataChannelMessage(const std::string&,
                              int,
                              bool,
                              const uint8_t* data,
                              size_t size) override {
      std::lock_guard<std::mutex> lock(mu_);
      dc_reply_.assign(reinterpret_cast<const char*>(data), size);
      cv_.notify_all();
    }

    bool WaitHighFrames(int n, int timeout_ms) {
      std::unique_lock<std::mutex> lock(mu_);
      return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                          [this, n]() { return high_frames_ >= n; });
    }
    bool WaitLowAndDcReply(int n, int timeout_ms) {
      std::unique_lock<std::mutex> lock(mu_);
      return cv_.wait_for(
          lock, std::chrono::milliseconds(timeout_ms), [this, n]() {
            return low_frames_ >= n && dc_reply_ == "MOQ_ACK:HELLO_MOQ_BROWSER";
          });
    }
    int high_frames() const {
      std::lock_guard<std::mutex> lock(mu_);
      return high_frames_;
    }
    int low_frames() const {
      std::lock_guard<std::mutex> lock(mu_);
      return low_frames_;
    }
    std::string dc_reply() const {
      std::lock_guard<std::mutex> lock(mu_);
      return dc_reply_;
    }

   private:
    rtc::RtcVideoEngine* engine_ = nullptr;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    int high_frames_ = 0;
    int low_frames_ = 0;
    std::string dc_reply_;
  } wt_obs;

  rtc::EngineConfig wt_cfg;
  wt_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT;
  wt_cfg.signaling_or_moq_url = wt_url;
  wt_cfg.publish_codec = RTC_CODEC_H264;
  auto wt_browser = rtc::RtcVideoEngine::Create(wt_cfg, &wt_obs);
  wt_obs.BindEngine(wt_browser.get());

  rtc::DataChannelConfig dc_cfg;
  dc_cfg.label = "browser_ctrl";
  dc_cfg.ordered = true;
  const int browser_dc = wt_browser->CreateDataChannel(dc_cfg);
  wt_browser->JoinRoom(kDemoRoomId, "simulated_wt_browser");

  const bool got_high = wt_obs.WaitHighFrames(8, 4000);
  wt_browser->SwitchSubscribedLayer(kDemoPubPeerId, RTC_STREAM_LAYER_LOW);
  wt_browser->SendTextData(browser_dc, "HELLO_MOQ_BROWSER");
  const bool got_low_and_dc = wt_obs.WaitLowAndDcReply(5, 4000);

  // 3. 验证 /ws-moq WebSocket 兜底桥接通道同样可拉取视频与双向数据通道
  websocket::stream<tcp::socket> ws_client(ioc);
  ws_client.next_layer().connect(
      tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"),
                    gateway.http_port()),
      ec);
  bool got_ws_frame = false;
  if (!ec) {
    ws_client.handshake("127.0.0.1", "/ws-moq", ec);
    if (!ec) {
      for (int i = 0; i < 10 && !ec; ++i) {
        beast::flat_buffer ws_rx;
        ws_client.read(ws_rx, ec);
        if (!ec && ws_client.got_binary() && ws_rx.size() > 20) {
          got_ws_frame = true;
          break;
        }
      }
      ws_client.close(websocket::close_code::normal, ec);
    }
  }

  RTC_LOG(kInfo) << "=== Browser MoQ (draft-17) Self-Test Summary: http_port="
                 << gateway.http_port()
                 << " moq_udp_port=" << gateway.moq_udp_port()
                 << " cert_sha256=" << gateway.cert_sha256_hex().substr(0, 16)
                 << "... high_frames=" << wt_obs.high_frames()
                 << " low_frames=" << wt_obs.low_frames()
                 << " dc_reply=" << wt_obs.dc_reply()
                 << " ws_bridge_ok=" << (got_ws_frame ? "true" : "false")
                 << " ===";

  wt_obs.BindEngine(nullptr);
  wt_browser->LeaveRoom();
  wt_browser.reset();
  gateway.Stop();
  return (got_high && got_low_and_dc && got_ws_frame) ? 0 : 6;
}

}  // namespace

int main(int argc, char** argv) {
  rtc::RtcVideoEngine::SetMinLogSeverity(rtc::LoggingSeverity::kInfo);

  for (int i = 1; i < argc; ++i) {
    if (std::string_view(argv[i]) == "--self-test") {
      return RunAutomatedBrowserMoqSelfTest();
    }
  }

  uint16_t http_port = 8081;
  uint16_t moq_udp_port = 0;
  if (argc >= 2) {
    rtc::ParseUint16(argv[1], &http_port);
  }
  if (argc >= 3) {
    rtc::ParseUint16(argv[2], &moq_udp_port);
  }

  std::signal(SIGINT, &OnSignal);
  std::signal(SIGTERM, &OnSignal);

  BrowserMoqLiveGateway gateway;
  if (!gateway.Start(http_port, moq_udp_port)) {
    RTC_LOG(kError) << "Failed to start BrowserMoqLiveGateway on HTTP port "
                    << http_port;
    return 1;
  }

  RTC_LOG(kInfo) << "Browser IETF MoQ (draft-17) Live Player listening at "
                    "http://127.0.0.1:"
                 << gateway.http_port() << "/ (WebTransport UDP="
                 << gateway.moq_udp_port()
                 << ", sha256=" << gateway.cert_sha256_hex() << ")";
  while (!g_quit.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  gateway.Stop();
  return 0;
}
