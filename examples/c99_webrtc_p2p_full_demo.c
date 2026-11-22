// 纯 C99 WebRTC P2P SDK 完整使用示例（`c99_webrtc_p2p_full_demo.c`）
//
// 100% 覆盖测试 `rtc_video_sdk.h` 中的纯 C99 WebRTC P2P API 接口：
//   - 统一日志系统（`rtc_set_log_level`、`rtc_enable_stderr_logging`、
//     `rtc_set_log_callback`）以及防御性错误码校验
//   - 场景 A：无信令服务器直连 W3C SDP 与 Trickle-ICE 双向 P2P 传输
//     （H.264 编码，涵盖 `rtc_client_create_offer`、`rtc_client_set_remote_description`、
//     `rtc_client_add_remote_ice_candidate` 与 `rtc_client_request_remote_idr`）
//   - 场景 B：基于 WebSocket（`ws://`）自动房间信令的 1 对 1 P2P 传输
//     （H.265 编码，涵盖 `ice_servers` 配置、`rtc_client_join_room`、`rtc_client_leave_room`、
//     `on_remote_track_published`、`on_remote_track_unpublished` 以及 `on_network_stats`）

#define _POSIX_C_SOURCE 200809L

#include "rtc_video_sdk.h"

#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

typedef struct {
  const char* label;
  pthread_mutex_t lock;
  bool connected;
  bool force_idr_pending;
  uint32_t bitrate_cbs;
  uint32_t target_bps;
  uint32_t target_fps;
  uint32_t tracks_published;
  uint32_t tracks_unpublished;
  uint32_t frames_pulled;
  size_t bytes_pulled;
  uint32_t stats_cbs;
  uint32_t local_candidates_cbs;
  rtc_client_t* trickle_target;
} c99_p2p_peer_t;

static void sleep_ms(int ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (long)(ms % 1000) * 1000000L;
  nanosleep(&ts, NULL);
}

static void init_peer_ctx(c99_p2p_peer_t* p, const char* label) {
  memset(p, 0, sizeof(*p));
  p->label = label;
  pthread_mutex_init(&p->lock, NULL);
}

static void destroy_peer_ctx(c99_p2p_peer_t* p) {
  pthread_mutex_destroy(&p->lock);
}

static void on_c99_log(void* user_data,
                       rtc_log_severity_e severity,
                       const char* queue_name,
                       const char* file_name,
                       int line,
                       const char* message) {
  int* counter = (int*)user_data;
  if (counter != NULL) {
    (*counter)++;
  }
  const char* sev = "INFO";
  if (severity == RTC_LOG_WARNING) {
    sev = "WARN";
  } else if (severity == RTC_LOG_ERROR) {
    sev = "ERR ";
  }
  printf("[C99-P2P-LOG][%s][%s][%s:%d] %s\n", sev, queue_name, file_name, line,
         message);
}

static void cb_bitrate(void* ud,
                       rtc_stream_layer_e layer,
                       bool active,
                       uint32_t bps,
                       uint32_t fps) {
  (void)layer;
  c99_p2p_peer_t* p = (c99_p2p_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->bitrate_cbs++;
  p->target_bps = active ? bps : 0u;
  p->target_fps = fps;
  pthread_mutex_unlock(&p->lock);
}

static void cb_force_idr(void* ud, rtc_stream_layer_e layer) {
  (void)layer;
  c99_p2p_peer_t* p = (c99_p2p_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->force_idr_pending = true;
  pthread_mutex_unlock(&p->lock);
}

static void cb_track_pub(void* ud,
                         const char* peer_id,
                         const char* track_id,
                         rtc_video_codec_e codec) {
  c99_p2p_peer_t* p = (c99_p2p_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->tracks_published++;
  pthread_mutex_unlock(&p->lock);
  printf("[%s] Remote track published: peer=%s track=%s codec=%s\n", p->label,
         peer_id, track_id, codec == RTC_CODEC_H265 ? "H265" : "H264");
}

static void cb_track_unpub(void* ud,
                           const char* peer_id,
                           const char* track_id) {
  c99_p2p_peer_t* p = (c99_p2p_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->tracks_unpublished++;
  pthread_mutex_unlock(&p->lock);
  printf("[%s] Remote track unpublished: peer=%s track=%s\n", p->label, peer_id,
         track_id);
}

static void cb_encoded_frame(void* ud,
                             const char* peer_id,
                             const char* track_id,
                             const rtc_encoded_frame_t* frame) {
  (void)peer_id;
  (void)track_id;
  c99_p2p_peer_t* p = (c99_p2p_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->frames_pulled++;
  p->bytes_pulled += frame->size;
  pthread_mutex_unlock(&p->lock);
}

static void cb_conn_state(void* ud, rtc_connection_state_e st, int reason) {
  (void)reason;
  c99_p2p_peer_t* p = (c99_p2p_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  if (st == RTC_CONN_STATE_CONNECTED) {
    p->connected = true;
  }
  pthread_mutex_unlock(&p->lock);
}

static void cb_stats(void* ud, const rtc_network_stats_t* stats) {
  (void)stats;
  c99_p2p_peer_t* p = (c99_p2p_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->stats_cbs++;
  pthread_mutex_unlock(&p->lock);
}

static void cb_ice_candidate(void* ud,
                             const char* sdp_mid,
                             int sdp_mline_index,
                             const char* candidate_sdp) {
  (void)sdp_mid;
  (void)sdp_mline_index;
  c99_p2p_peer_t* p = (c99_p2p_peer_t*)ud;
  pthread_mutex_lock(&p->lock);
  p->local_candidates_cbs++;
  rtc_client_t* target = p->trickle_target;
  pthread_mutex_unlock(&p->lock);
  if (target != NULL) {
    rtc_client_add_remote_ice_candidate(target, candidate_sdp);
  }
}

static rtc_callbacks_t make_full_callbacks(void) {
  rtc_callbacks_t cbs;
  memset(&cbs, 0, sizeof(cbs));
  cbs.on_encoder_bitrate_allocation = &cb_bitrate;
  cbs.on_encoder_force_idr = &cb_force_idr;
  cbs.on_remote_track_published = &cb_track_pub;
  cbs.on_remote_track_unpublished = &cb_track_unpub;
  cbs.on_remote_encoded_frame = &cb_encoded_frame;
  cbs.on_connection_state = &cb_conn_state;
  cbs.on_network_stats = &cb_stats;
  cbs.on_local_ice_candidate = &cb_ice_candidate;
  return cbs;
}

static bool wait_peer_connected(c99_p2p_peer_t* p, int timeout_ms) {
  int elapsed = 0;
  while (elapsed < timeout_ms) {
    pthread_mutex_lock(&p->lock);
    const bool ok = p->connected;
    pthread_mutex_unlock(&p->lock);
    if (ok) {
      return true;
    }
    sleep_ms(10);
    elapsed += 10;
  }
  return false;
}

static size_t fill_annexb_frame(uint8_t* dst,
                                size_t cap,
                                rtc_video_codec_e codec,
                                bool is_idr,
                                uint8_t fill_byte) {
  static const uint8_t kH264Idr[] = {
      0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xE0, 0x1F,
      0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80,
      0x00, 0x00, 0x00, 0x01, 0x65, 0x88,
  };
  static const uint8_t kH264P[] = {0x00, 0x00, 0x00, 0x01, 0x41, 0x9A};
  static const uint8_t kH265Idr[] = {
      0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01,
      0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x60,
      0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xC1, 0x73,
      0x00, 0x00, 0x00, 0x01, 0x26, 0x01,
  };
  static const uint8_t kH265P[] = {0x00, 0x00, 0x00, 0x01, 0x02, 0x01};

  const uint8_t* hdr = NULL;
  size_t hdr_len = 0;
  if (codec == RTC_CODEC_H265) {
    hdr = is_idr ? kH265Idr : kH265P;
    hdr_len = is_idr ? sizeof(kH265Idr) : sizeof(kH265P);
  } else {
    hdr = is_idr ? kH264Idr : kH264P;
    hdr_len = is_idr ? sizeof(kH264Idr) : sizeof(kH264P);
  }
  const size_t body_len = is_idr ? 3200u : 1000u;
  if (hdr_len + body_len > cap) {
    return 0;
  }
  memcpy(dst, hdr, hdr_len);
  memset(dst + hdr_len, fill_byte, body_len);
  return hdr_len + body_len;
}

// 第 0 部分：验证 C99 API 的防御性参数校验
static bool run_defensive_api_checks(void) {
  if (rtc_client_create(NULL, NULL, NULL) != NULL) {
    return false;
  }
  rtc_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  cfg.publish_codec = RTC_CODEC_H264;

  rtc_client_t* c = rtc_client_create(&cfg, NULL, NULL);
  if (c == NULL) {
    return false;
  }

  uint8_t dummy[8] = {0, 0, 0, 1, 0x65, 1, 2, 3};
  rtc_encoded_frame_t f;
  memset(&f, 0, sizeof(f));
  f.data = dummy;
  f.size = sizeof(dummy);

  const bool checks_ok =
      (rtc_client_join_room(c, "", "peer") == RTC_ERR_INVALID_ARG) &&
      (rtc_client_push_video_frame(c, &f) == RTC_ERR_NOT_CONNECTED) &&
      (rtc_client_push_video_frame(c, NULL) == RTC_ERR_INVALID_ARG);

  char tiny_sdp[16];
  const bool oom_check_ok =
      (rtc_client_create_offer(c, tiny_sdp, sizeof(tiny_sdp)) ==
       RTC_ERR_NO_MEMORY);

  rtc_client_destroy(c);
  return checks_ok && oom_check_ok;
}

// 第 1 部分：无信令服务器直连 W3C SDP 与 Trickle-ICE 双向 P2P（H.264）
static bool run_direct_sdp_bidirectional_p2p(void) {
  printf("\n--- [C99 Part 1] Serverless Direct W3C SDP Bidirectional P2P ---\n");
  c99_p2p_peer_t peer_a;
  c99_p2p_peer_t peer_b;
  init_peer_ctx(&peer_a, "C99-CamA");
  init_peer_ctx(&peer_b, "C99-ViewerB");

  rtc_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  cfg.publish_codec = RTC_CODEC_H264;
  cfg.enable_flexfec = true;
  cfg.zero_playout_delay = true;
  cfg.min_bitrate_bps = 150000;
  cfg.start_bitrate_bps = 1500000;
  cfg.max_bitrate_bps = 4000000;

  const rtc_callbacks_t cbs = make_full_callbacks();
  rtc_client_t* ca = rtc_client_create(&cfg, &cbs, &peer_a);
  rtc_client_t* cb = rtc_client_create(&cfg, &cbs, &peer_b);
  peer_a.trickle_target = cb;
  peer_b.trickle_target = ca;

  rtc_client_join_room(ca, "c99_direct", "cam_a");
  rtc_client_join_room(cb, "c99_direct", "viewer_b");

  char offer_sdp[4096];
  char answer_sdp[4096];
  if (rtc_client_create_offer(cb, offer_sdp, sizeof(offer_sdp)) != RTC_OK ||
      rtc_client_set_remote_description(ca, "offer", offer_sdp, answer_sdp,
                                        sizeof(answer_sdp)) != RTC_OK ||
      rtc_client_set_remote_description(cb, "answer", answer_sdp, NULL, 0) !=
          RTC_OK) {
    return false;
  }
  // 候选地址收集结束的空字符串必须作为合法的 W3C 空操作返回成功
  if (rtc_client_add_remote_ice_candidate(ca, "") != RTC_OK) {
    return false;
  }

  if (!wait_peer_connected(&peer_a, 5000) ||
      !wait_peer_connected(&peer_b, 5000)) {
    return false;
  }

  uint8_t buf[8192];
  uint64_t ts_us = 1000000ULL;
  for (int i = 0; i < 20; ++i) {
    const bool is_idr = (i % 7) == 0;
    const size_t nbytes = fill_annexb_frame(buf, sizeof(buf), RTC_CODEC_H264,
                                            is_idr, (uint8_t)(i + 1));
    rtc_encoded_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.data = buf;
    frame.size = nbytes;
    frame.capture_ts_us = ts_us;
    frame.is_keyframe = is_idr;
    frame.layer = RTC_STREAM_LAYER_HIGH;

    rtc_client_push_video_frame(ca, &frame);
    rtc_client_push_video_frame(cb, &frame);

    if (i == 6) {
      rtc_client_request_remote_idr(cb, "cam_a_video0");
    }
    ts_us += 33333ULL;
    sleep_ms(20);
  }

  sleep_ms(150);
  pthread_mutex_lock(&peer_a.lock);
  const uint32_t a_frames = peer_a.frames_pulled;
  const uint32_t a_stats = peer_a.stats_cbs;
  pthread_mutex_unlock(&peer_a.lock);

  pthread_mutex_lock(&peer_b.lock);
  const uint32_t b_frames = peer_b.frames_pulled;
  const uint32_t b_bwe = peer_b.bitrate_cbs;
  pthread_mutex_unlock(&peer_b.lock);

  printf("[C99 Part 1 Result] a_pulled=%u, b_pulled=%u, stats_cbs=%u, bwe=%u\n",
         a_frames, b_frames, a_stats, b_bwe);

  pthread_mutex_lock(&peer_a.lock);
  peer_a.trickle_target = NULL;
  pthread_mutex_unlock(&peer_a.lock);
  pthread_mutex_lock(&peer_b.lock);
  peer_b.trickle_target = NULL;
  pthread_mutex_unlock(&peer_b.lock);

  rtc_client_leave_room(ca);
  rtc_client_leave_room(cb);
  rtc_client_destroy(ca);
  rtc_client_destroy(cb);
  destroy_peer_ctx(&peer_a);
  destroy_peer_ctx(&peer_b);

  return (a_frames >= 12u) && (b_frames >= 12u) && (a_stats > 0u) &&
         (b_bwe > 0u);
}

// 第 2 部分：WebSocket（`ws://`）自动信令 1v1 P2P（H.265 + 轨道取消发布）
static bool run_ws_signaling_h265_p2p(const char* sig_server_bin) {
  printf("\n--- [C99 Part 2] WebSocket Auto-Signaling H.265 P2P ---\n");
  char port_file[128];
  snprintf(port_file, sizeof(port_file), "/tmp/rtc_c99_sig_%d.port",
           (int)getpid());
  unlink(port_file);

  const pid_t srv_pid = fork();
  if (srv_pid < 0) {
    return false;
  }
  if (srv_pid == 0) {
#ifdef __linux__
    (void)prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
    execl(sig_server_bin, sig_server_bin, "127.0.0.1", "0", "--port-file",
          port_file, (char*)NULL);
    _exit(127);
  }

  unsigned ws_port = 0;
  for (int i = 0; i < 100 && ws_port == 0; ++i) {
    FILE* fp = fopen(port_file, "r");
    if (fp != NULL) {
      if (fscanf(fp, "%u", &ws_port) != 1) {
        ws_port = 0;
      }
      fclose(fp);
    }
    if (ws_port == 0) {
      sleep_ms(20);
    }
  }
  unlink(port_file);
  if (ws_port == 0) {
    kill(srv_pid, SIGTERM);
    waitpid(srv_pid, NULL, 0);
    return false;
  }

  char ws_url[128];
  snprintf(ws_url, sizeof(ws_url), "ws://127.0.0.1:%u", ws_port);

  c99_p2p_peer_t pub_ctx;
  c99_p2p_peer_t sub_ctx;
  init_peer_ctx(&pub_ctx, "C99-WS-PubH265");
  init_peer_ctx(&sub_ctx, "C99-WS-SubH265");

  rtc_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.transport_mode = RTC_TRANSPORT_MODE_WEBRTC_P2P;
  cfg.signaling_or_moq_url = ws_url;
  cfg.auth_token = "c99_demo_token";
  cfg.ice_servers[0].uri = "stun:127.0.0.1:3478";
  cfg.ice_server_count = 1;
  cfg.publish_codec = RTC_CODEC_H265;
  cfg.enable_flexfec = true;
  cfg.zero_playout_delay = true;

  const rtc_callbacks_t cbs = make_full_callbacks();
  rtc_client_t* pub = rtc_client_create(&cfg, &cbs, &pub_ctx);
  rtc_client_t* sub = rtc_client_create(&cfg, &cbs, &sub_ctx);

  rtc_client_join_room(pub, "c99_ws_room", "uav_h265");
  rtc_client_join_room(sub, "c99_ws_room", "ground_ctrl");

  bool ok = wait_peer_connected(&pub_ctx, 5000) &&
            wait_peer_connected(&sub_ctx, 5000);
  if (ok) {
    uint8_t buf[8192];
    uint64_t ts_us = 2000000ULL;
    for (int i = 0; i < 16; ++i) {
      const bool is_idr = (i % 6) == 0;
      const size_t nbytes = fill_annexb_frame(buf, sizeof(buf), RTC_CODEC_H265,
                                              is_idr, (uint8_t)(0x40 + i));
      rtc_encoded_frame_t frame;
      memset(&frame, 0, sizeof(frame));
      frame.data = buf;
      frame.size = nbytes;
      frame.capture_ts_us = ts_us;
      frame.is_keyframe = is_idr;
      frame.layer = RTC_STREAM_LAYER_HIGH;
      rtc_client_push_video_frame(pub, &frame);
      ts_us += 33333ULL;
      sleep_ms(20);
    }

    sleep_ms(120);
    // 推流端离开房间 -> 订阅端必须收到 `on_remote_track_unpublished` 回调
    rtc_client_leave_room(pub);
    for (int w = 0; w < 50; ++w) {
      pthread_mutex_lock(&sub_ctx.lock);
      const uint32_t unpub = sub_ctx.tracks_unpublished;
      pthread_mutex_unlock(&sub_ctx.lock);
      if (unpub > 0u) {
        break;
      }
      sleep_ms(20);
    }

    pthread_mutex_lock(&sub_ctx.lock);
    printf("[C99 Part 2 Result] h265_pulled=%u, pub_events=%u, unpub_events=%u\n",
           sub_ctx.frames_pulled, sub_ctx.tracks_published,
           sub_ctx.tracks_unpublished);
    ok = (sub_ctx.frames_pulled >= 10u) && (sub_ctx.tracks_published > 0u) &&
         (sub_ctx.tracks_unpublished > 0u);
    pthread_mutex_unlock(&sub_ctx.lock);
  }

  rtc_client_leave_room(sub);
  rtc_client_destroy(sub);
  rtc_client_destroy(pub);
  destroy_peer_ctx(&sub_ctx);
  destroy_peer_ctx(&pub_ctx);

  kill(srv_pid, SIGTERM);
  waitpid(srv_pid, NULL, 0);
  return ok;
}

int main(int argc, char** argv) {
  const char* sig_bin = "./rtc_p2p_ws_signaling_server";
  for (int i = 1; i + 1 < argc; ++i) {
    if (strcmp(argv[i], "--sig-bin") == 0) {
      sig_bin = argv[i + 1];
    }
  }

  int total_logs = 0;
  rtc_enable_stderr_logging(false);
  rtc_set_log_level(RTC_LOG_INFO);
  rtc_set_log_callback(&on_c99_log, &total_logs);

  if (!run_defensive_api_checks()) {
    fprintf(stderr, "C99 defensive API checks failed\n");
    return 1;
  }
  if (!run_direct_sdp_bidirectional_p2p()) {
    fprintf(stderr, "C99 Part 1 (Direct SDP P2P) failed\n");
    return 2;
  }
  if (!run_ws_signaling_h265_p2p(sig_bin)) {
    fprintf(stderr, "C99 Part 2 (WebSocket H.265 P2P) failed\n");
    return 3;
  }

  rtc_set_log_callback(NULL, NULL);
  printf("=== C99 WebRTC P2P Full Demo PASSED (logs_captured=%d) ===\n",
         total_logs);
  return (total_logs > 0) ? 0 : 4;
}
