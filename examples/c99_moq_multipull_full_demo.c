// 纯 C99 IETF MoQ 多路拉流 SDK 完整使用示例（`c99_moq_multipull_full_demo.c`）
//
// 基于 Boost.Asio QUIC v1 对接独立 `rtc_moq_relay_server` 进程，100% 覆盖测试
// `rtc_video_sdk.h` 中的纯 C99 IETF MoQ API 接口：
//   - 2 路 Simulcast 摄像头推流端（`c99_cam_h265` 与 `c99_cam_h264`，同时推送
//     LOW + HIGH 空间层及 SVC `temporal_id` / `discardable` 标记）
//   - 1 个多路拉流控制台（`c99_nvr_console`），在单条 QUIC 连接上并发订阅两路
//     媒体轨道（`rtc_client_subscribe_track`）
//   - 动态 GOP 对齐的 Simulcast 空间层切换（`rtc_client_switch_subscribed_layer`）
//   - 上行关键帧请求（`rtc_client_request_remote_idr`）、周期性网络遥测回调
//     （`on_network_stats`）、显式取消轨道订阅（`rtc_client_unsubscribe_track`）
//     以及远端离线取消发布通知（`on_remote_track_unpublished`）

#define _POSIX_C_SOURCE 200809L

#include "rtc_video_sdk.h"

#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

typedef struct {
  const char* name;
  pthread_mutex_t lock;
  bool connected;
  bool force_idr[2];
  uint32_t bwe_cbs;
  uint32_t stats_cbs;

  bool saw_cam_h265;
  bool saw_cam_h264;
  uint32_t unpub_events;
  uint32_t h265_frames;
  uint32_t h264_frames;
  rtc_stream_layer_e h265_last_layer;
  rtc_stream_layer_e h264_last_layer;
  uint32_t dc_messages_rx;
} c99_moq_peer_t;

static void sleep_ms(int ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (long)(ms % 1000) * 1000000L;
  nanosleep(&ts, NULL);
}

static void init_moq_peer(c99_moq_peer_t* p, const char* name) {
  memset(p, 0, sizeof(*p));
  p->name = name;
  pthread_mutex_init(&p->lock, NULL);
}

static void destroy_moq_peer(c99_moq_peer_t* p) {
  pthread_mutex_destroy(&p->lock);
}

static void on_moq_bwe(void* ud,
                       rtc_stream_layer_e layer,
                       bool active,
                       uint32_t bps,
                       uint32_t fps) {
  (void)layer;
  (void)active;
  (void)bps;
  (void)fps;
  c99_moq_peer_t* p = (c99_moq_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->bwe_cbs++;
  pthread_mutex_unlock(&p->lock);
}

static void on_moq_force_idr(void* ud, rtc_stream_layer_e layer) {
  c99_moq_peer_t* p = (c99_moq_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->force_idr[layer == RTC_STREAM_LAYER_HIGH ? 1 : 0] = true;
  pthread_mutex_unlock(&p->lock);
}

static void on_moq_track_pub(void* ud,
                             const char* peer_id,
                             const char* track_id,
                             rtc_video_codec_e codec) {
  c99_moq_peer_t* p = (c99_moq_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  if (strcmp(track_id, "c99_cam_h265") == 0) {
    p->saw_cam_h265 = true;
  } else if (strcmp(track_id, "c99_cam_h264") == 0) {
    p->saw_cam_h264 = true;
  }
  pthread_mutex_unlock(&p->lock);
  printf("[%s] MoQ track discovered: peer=%s track=%s codec=%s\n", p->name,
         peer_id, track_id, codec == RTC_CODEC_H265 ? "H265" : "H264");
}

static void on_moq_track_unpub(void* ud,
                               const char* peer_id,
                               const char* track_id) {
  c99_moq_peer_t* p = (c99_moq_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->unpub_events++;
  pthread_mutex_unlock(&p->lock);
  printf("[%s] MoQ track unpublished: peer=%s track=%s\n", p->name, peer_id,
         track_id);
}

static void on_moq_frame(void* ud,
                         const char* peer_id,
                         const char* track_id,
                         const rtc_encoded_frame_t* frame) {
  (void)peer_id;
  c99_moq_peer_t* p = (c99_moq_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  if (strcmp(track_id, "c99_cam_h265") == 0) {
    p->h265_frames++;
    p->h265_last_layer = frame->layer;
  } else if (strcmp(track_id, "c99_cam_h264") == 0) {
    p->h264_frames++;
    p->h264_last_layer = frame->layer;
  }
  pthread_mutex_unlock(&p->lock);
}

static void on_moq_conn_state(void* ud, rtc_connection_state_e st, int reason) {
  (void)reason;
  c99_moq_peer_t* p = (c99_moq_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  if (st == RTC_CONN_STATE_CONNECTED) {
    p->connected = true;
  }
  pthread_mutex_unlock(&p->lock);
}

static void on_moq_stats(void* ud, const rtc_network_stats_t* stats) {
  (void)stats;
  c99_moq_peer_t* p = (c99_moq_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->stats_cbs++;
  pthread_mutex_unlock(&p->lock);
}

static void on_moq_dc_msg(void* ud,
                          const char* peer_id,
                          int channel_id,
                          bool is_binary,
                          const uint8_t* data,
                          size_t size) {
  (void)channel_id;
  (void)is_binary;
  c99_moq_peer_t* p = (c99_moq_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->dc_messages_rx++;
  pthread_mutex_unlock(&p->lock);
  printf("[%s] MoQ DataChannel RX from %s: %.*s\n", p->name, peer_id,
         (int)size, (const char*)data);
}

static bool wait_moq_connected(c99_moq_peer_t* p, int timeout_ms) {
  int waited = 0;
  while (waited < timeout_ms) {
    pthread_mutex_lock(&p->lock);
    const bool ok = p->connected;
    pthread_mutex_unlock(&p->lock);
    if (ok) {
      return true;
    }
    sleep_ms(10);
    waited += 10;
  }
  return false;
}

static size_t build_moq_test_frame(uint8_t* buf,
                                   size_t cap,
                                   rtc_video_codec_e codec,
                                   bool is_idr,
                                   size_t payload_len) {
  static const uint8_t kH265Idr[] = {
      0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01,
      0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x60,
      0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xC1, 0x73,
      0x00, 0x00, 0x00, 0x01, 0x26, 0x01,
  };
  static const uint8_t kH265P[] = {0x00, 0x00, 0x00, 0x01, 0x02, 0x01};
  static const uint8_t kH264Idr[] = {
      0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xE0, 0x1F,
      0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80,
      0x00, 0x00, 0x00, 0x01, 0x65, 0x88,
  };
  static const uint8_t kH264P[] = {0x00, 0x00, 0x00, 0x01, 0x41, 0x9A};

  const uint8_t* hdr = NULL;
  size_t hdr_len = 0;
  if (codec == RTC_CODEC_H265) {
    hdr = is_idr ? kH265Idr : kH265P;
    hdr_len = is_idr ? sizeof(kH265Idr) : sizeof(kH265P);
  } else {
    hdr = is_idr ? kH264Idr : kH264P;
    hdr_len = is_idr ? sizeof(kH264Idr) : sizeof(kH264P);
  }
  if (hdr_len + payload_len > cap) {
    return 0;
  }
  memcpy(buf, hdr, hdr_len);
  memset(buf + hdr_len, 0x6B, payload_len);
  return hdr_len + payload_len;
}

int main(int argc, char** argv) {
  const char* relay_bin = "./rtc_moq_relay_server";
  for (int i = 1; i + 1 < argc; ++i) {
    if (strcmp(argv[i], "--relay-bin") == 0) {
      relay_bin = argv[i + 1];
    }
  }

  rtc_enable_stderr_logging(true);
  rtc_set_log_level(RTC_LOG_INFO);

  char port_file[128];
  snprintf(port_file, sizeof(port_file), "/tmp/rtc_c99_moq_%d.port",
           (int)getpid());
  unlink(port_file);

  const pid_t relay_pid = fork();
  if (relay_pid < 0) {
    return 1;
  }
  if (relay_pid == 0) {
#ifdef __linux__
    (void)prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
    execl(relay_bin, relay_bin, "127.0.0.1", "0", "--port-file", port_file,
          (char*)NULL);
    _exit(127);
  }

  unsigned moq_port = 0;
  for (int i = 0; i < 100 && moq_port == 0; ++i) {
    FILE* fp = fopen(port_file, "r");
    if (fp != NULL) {
      if (fscanf(fp, "%u", &moq_port) != 1) {
        moq_port = 0;
      }
      fclose(fp);
    }
    if (moq_port == 0) {
      sleep_ms(20);
    }
  }
  unlink(port_file);
  if (moq_port == 0) {
    kill(relay_pid, SIGTERM);
    waitpid(relay_pid, NULL, 0);
    fprintf(stderr, "Failed to start rtc_moq_relay_server\n");
    return 2;
  }

  char moq_url[128];
  snprintf(moq_url, sizeof(moq_url), "moq://127.0.0.1:%u", moq_port);

  c99_moq_peer_t nvr_ctx;
  c99_moq_peer_t cam1_ctx;
  c99_moq_peer_t cam2_ctx;
  init_moq_peer(&nvr_ctx, "C99-NVR");
  init_moq_peer(&cam1_ctx, "C99-CamH265");
  init_moq_peer(&cam2_ctx, "C99-CamH264");

  rtc_callbacks_t cbs;
  memset(&cbs, 0, sizeof(cbs));
  cbs.on_encoder_bitrate_allocation = &on_moq_bwe;
  cbs.on_encoder_force_idr = &on_moq_force_idr;
  cbs.on_remote_track_published = &on_moq_track_pub;
  cbs.on_remote_track_unpublished = &on_moq_track_unpub;
  cbs.on_remote_encoded_frame = &on_moq_frame;
  cbs.on_connection_state = &on_moq_conn_state;
  cbs.on_network_stats = &on_moq_stats;
  cbs.on_data_channel_message = &on_moq_dc_msg;

  rtc_config_t pull_cfg;
  memset(&pull_cfg, 0, sizeof(pull_cfg));
  pull_cfg.transport_mode = RTC_TRANSPORT_MODE_MOQ;
  pull_cfg.signaling_or_moq_url = moq_url;
  pull_cfg.publish_codec = RTC_CODEC_H264;
  pull_cfg.zero_playout_delay = true;

  rtc_config_t cam1_cfg = pull_cfg;
  cam1_cfg.publish_codec = RTC_CODEC_H265;
  cam1_cfg.enable_simulcast = true;
  cam1_cfg.low_layer_max_bps = 450000;
  cam1_cfg.moq_delivery_timeout_ms = 400;
  cam1_cfg.quic_cc_algo = RTC_QUIC_CC_BBR;

  rtc_config_t cam2_cfg = cam1_cfg;
  cam2_cfg.publish_codec = RTC_CODEC_H264;
  cam2_cfg.quic_cc_algo = RTC_QUIC_CC_CUBIC;

  printf("[C99-MoQ] Initial QUIC CC modules: cam1=%s, cam2=%s\n",
         rtc_quic_cc_algo_name(cam1_cfg.quic_cc_algo),
         rtc_quic_cc_algo_name(cam2_cfg.quic_cc_algo));

  rtc_client_t* nvr = rtc_client_create(&pull_cfg, &cbs, &nvr_ctx);
  rtc_client_t* cam1 = rtc_client_create(&cam1_cfg, &cbs, &cam1_ctx);
  rtc_client_t* cam2 = rtc_client_create(&cam2_cfg, &cbs, &cam2_ctx);

  rtc_client_join_room(nvr, "c99_moq_fleet", "c99_nvr_console");
  // 验证重复加入房间会返回 RTC_ERR_ALREADY_CONNECTED
  if (rtc_client_join_room(nvr, "c99_moq_fleet", "c99_nvr_console") !=
      RTC_ERR_ALREADY_CONNECTED) {
    return 3;
  }
  wait_moq_connected(&nvr_ctx, 5000);

  rtc_client_join_room(cam1, "c99_moq_fleet", "c99_cam_h265");
  rtc_client_join_room(cam2, "c99_moq_fleet", "c99_cam_h264");
  wait_moq_connected(&cam1_ctx, 5000);
  wait_moq_connected(&cam2_ctx, 5000);

  // 等待 NVR 通过 `on_remote_track_published` 发现两路摄像头
  for (int w = 0; w < 100; ++w) {
    pthread_mutex_lock(&nvr_ctx.lock);
    const bool ready = nvr_ctx.saw_cam_h265 && nvr_ctx.saw_cam_h264;
    pthread_mutex_unlock(&nvr_ctx.lock);
    if (ready) {
      break;
    }
    sleep_ms(20);
  }

  // 在单条 QUIC v1 连接上并发订阅两路媒体轨道，并由摄像头 1 广播 MoQ 数据轨道报文
  rtc_client_subscribe_track(nvr, "c99_cam_h265", RTC_STREAM_LAYER_HIGH);
  rtc_client_subscribe_track(nvr, "c99_cam_h264", RTC_STREAM_LAYER_LOW);
  sleep_ms(40);
  {
    rtc_data_channel_init_t dc_init;
    rtc_data_channel_init_default(&dc_init, "cam_gps");
    const int gps_dc = rtc_client_create_data_channel(cam1, &dc_init);
    const char* kGps = "{\"lat\":31.2304,\"lon\":121.4737}";
    rtc_client_send_data(cam1, gps_dc, (const uint8_t*)kGps, strlen(kGps),
                         false);
  }

  uint8_t low_buf[4096];
  uint8_t high_buf[8192];
  uint64_t ts_us = 1000000ULL;
  for (int f = 0; f < 28; ++f) {
    const bool is_gop = (f % 8) == 0;
    const uint8_t tid = (f % 2 == 0) ? 0u : 1u;

    const size_t low1 = build_moq_test_frame(
        low_buf, sizeof(low_buf), RTC_CODEC_H265, is_gop, is_gop ? 1300u : 450u);
    const size_t high1 =
        build_moq_test_frame(high_buf, sizeof(high_buf), RTC_CODEC_H265, is_gop,
                             is_gop ? 4200u : 1400u);

    rtc_encoded_frame_t f_low;
    memset(&f_low, 0, sizeof(f_low));
    f_low.data = low_buf;
    f_low.size = low1;
    f_low.capture_ts_us = ts_us;
    f_low.is_keyframe = is_gop;
    f_low.layer = RTC_STREAM_LAYER_LOW;
    f_low.temporal_id = is_gop ? 0u : tid;
    f_low.discardable = (tid > 0u);
    rtc_client_push_video_frame(cam1, &f_low);

    rtc_encoded_frame_t f_high = f_low;
    f_high.data = high_buf;
    f_high.size = high1;
    f_high.layer = RTC_STREAM_LAYER_HIGH;
    rtc_client_push_video_frame(cam1, &f_high);

    const size_t low2 = build_moq_test_frame(
        low_buf, sizeof(low_buf), RTC_CODEC_H264, is_gop, is_gop ? 1200u : 420u);
    const size_t high2 =
        build_moq_test_frame(high_buf, sizeof(high_buf), RTC_CODEC_H264, is_gop,
                             is_gop ? 3900u : 1300u);
    f_low.size = low2;
    rtc_client_push_video_frame(cam2, &f_low);
    f_high.size = high2;
    rtc_client_push_video_frame(cam2, &f_high);

    if (f == 6) {
      // 在推流过程中无需重连即可运行时热切换 QUIC 拥塞控制模块：
      // cam1 从 BBRv1 切换至 BBRv2，cam2 从 CUBIC 切换至 Copa。
      if (rtc_client_set_quic_cc_algo(cam1, RTC_QUIC_CC_BBR2) != RTC_OK ||
          rtc_client_set_quic_cc_algo(cam2, RTC_QUIC_CC_COPA) != RTC_OK) {
        return 5;
      }
    }
    if (f == 9) {
      // 动态切换 Simulcast 空间层并请求上行 IDR 关键帧
      rtc_client_switch_subscribed_layer(nvr, "c99_cam_h265",
                                         RTC_STREAM_LAYER_LOW);
      rtc_client_switch_subscribed_layer(nvr, "c99_cam_h264",
                                         RTC_STREAM_LAYER_HIGH);
      rtc_client_request_remote_idr(nvr, "c99_cam_h265");
    }
    if (f == 18) {
      // 第二次运行时热切换：cam1 从 BBRv2 切换至 NewReno，cam2 从 Copa 切换至 BBRv1。
      if (rtc_client_set_quic_cc_algo(cam1, RTC_QUIC_CC_NEWRENO) != RTC_OK ||
          rtc_client_set_quic_cc_algo(cam2, RTC_QUIC_CC_BBR) != RTC_OK) {
        return 6;
      }
    }

    ts_us += 33333ULL;
    sleep_ms(22);
  }

  sleep_ms(120);
  // 取消订阅 cam2 并让 cam1 离开房间，以验证 UNANNOUNCE 取消发布回调
  rtc_client_unsubscribe_track(nvr, "c99_cam_h264");
  rtc_client_leave_room(cam1);
  for (int w = 0; w < 50; ++w) {
    pthread_mutex_lock(&nvr_ctx.lock);
    const uint32_t unpub = nvr_ctx.unpub_events;
    pthread_mutex_unlock(&nvr_ctx.lock);
    if (unpub > 0u) {
      break;
    }
    sleep_ms(20);
  }

  pthread_mutex_lock(&nvr_ctx.lock);
  const uint32_t f265 = nvr_ctx.h265_frames;
  const uint32_t f264 = nvr_ctx.h264_frames;
  const rtc_stream_layer_e l265 = nvr_ctx.h265_last_layer;
  const rtc_stream_layer_e l264 = nvr_ctx.h264_last_layer;
  const uint32_t unpub = nvr_ctx.unpub_events;
  const uint32_t stats_cnt = nvr_ctx.stats_cbs;
  const uint32_t dc_rx = nvr_ctx.dc_messages_rx;
  pthread_mutex_unlock(&nvr_ctx.lock);

  printf("=== C99 MoQ Multi-Pull Demo Summary: h265=%u (layer=%s), "
         "h264=%u (layer=%s), dc_rx=%u, unpub=%u, stats=%u ===\n",
         f265, l265 == RTC_STREAM_LAYER_LOW ? "LOW" : "HIGH", f264,
         l264 == RTC_STREAM_LAYER_LOW ? "LOW" : "HIGH", dc_rx, unpub,
         stats_cnt);

  rtc_client_leave_room(cam2);
  rtc_client_leave_room(nvr);
  rtc_client_destroy(cam2);
  rtc_client_destroy(cam1);
  rtc_client_destroy(nvr);
  destroy_moq_peer(&cam2_ctx);
  destroy_moq_peer(&cam1_ctx);
  destroy_moq_peer(&nvr_ctx);

  kill(relay_pid, SIGTERM);
  waitpid(relay_pid, NULL, 0);

  const bool passed = (f265 >= 18u) && (f264 >= 18u) &&
                      (l265 == RTC_STREAM_LAYER_LOW) &&
                      (l264 == RTC_STREAM_LAYER_HIGH) && (dc_rx > 0u) &&
                      (unpub > 0u) && (stats_cnt > 0u);
  return passed ? 0 : 4;
}
