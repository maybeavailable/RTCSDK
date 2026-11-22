#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "api/units.h"
#include "modules/congestion_controller/goog_cc/goog_cc_controller.h"
#include "modules/pacing/pacing_module.h"
#include "modules/rtp_rtcp/flexfec_codec.h"
#include "modules/rtp_rtcp/rtcp_packets.h"
#include "modules/rtp_rtcp/rtp_packet.h"
#include "modules/rtp_rtcp/rtp_packet_history.h"
#include "modules/rtp_rtcp/rtp_video_packetizer.h"
#include "modules/video_coding/video_coding_module.h"
#include "moq/asio_quic_transport.h"
#include "moq/moq_transport.h"
#include "p2p/stun_turn_ice.h"
#include "pc/dtls_srtp_transport.h"
#include "pc/sctp_data_channel.h"
#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"
#include "rtc_base/packet_slab_pool.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/task_queue.h"
#include "rtc_base/time_utils.h"
#include "rtc_base/timestamp_extrapolator.h"

namespace rtc {
namespace {

// 0. 验证统一日志类（TaskQueue 标签、RingBufferLogSink、C99 回调与级别过滤）
TEST(LoggingTest, UnifiedLoggerTaskQueueTagAndSinks) {
  LogMessage::SetLogToStderr(false);
  LogMessage::SetMinLogSeverity(LoggingSeverity::kInfo);

  RingBufferLogSink ring_sink(8);
  LogMessage::AddLogSink(&ring_sink, LoggingSeverity::kInfo);

  struct CCallbackCapture {
    int count = 0;
    std::string last_queue;
    std::string last_msg;
  } c_cap;

  rtc_set_log_callback(
      [](void* ud, rtc_log_severity_e /*sev*/, const char* queue_name,
         const char* /*file*/, int /*line*/, const char* msg) {
        auto* cap = static_cast<CCallbackCapture*>(ud);
        ++cap->count;
        cap->last_queue = queue_name;
        cap->last_msg = msg;
      },
      &c_cap);

  // 在 kInfo 阈值下，kVerbose 级别日志必须被过滤掉
  RTC_LOG(kVerbose) << "should_not_appear";
  EXPECT_EQ(ring_sink.Size(), 0u);

  SdkTaskQueues queues;
  queues.worker()->Invoke([]() {
    RTC_LOG(kInfo) << "worker_pipeline_event=" << 42;
  });

  const auto lines = ring_sink.Snapshot();
  ASSERT_GE(lines.size(), 1u);
  EXPECT_NE(lines.back().find("[rtc-work]"), std::string::npos);
  EXPECT_NE(lines.back().find("worker_pipeline_event=42"), std::string::npos);

  EXPECT_EQ(c_cap.last_queue, "rtc-work");
  EXPECT_EQ(c_cap.last_msg, "worker_pipeline_event=42");

  rtc_set_log_callback(nullptr, nullptr);
  LogMessage::RemoveLogSink(&ring_sink);
  LogMessage::SetLogToStderr(true);
}

// 1. 验证 TaskQueue 五域线程隔离、SequenceChecker 以及 ScopedTaskSafety 零释放后使用（UAF）保护
TEST(RtcBaseTest, TaskQueueIsolationAndSafetyFlag) {
  SdkTaskQueues queues;

  const auto sig_tid = queues.signaling()->Invoke([]() {
    EXPECT_NE(TaskQueueBase::Current(), nullptr);
    return std::this_thread::get_id();
  });
  const auto work_tid =
      queues.worker()->Invoke([]() { return std::this_thread::get_id(); });
  const auto pace_tid =
      queues.pacer()->Invoke([]() { return std::this_thread::get_id(); });
  const auto net_tid =
      queues.network()->Invoke([]() { return std::this_thread::get_id(); });
  const auto cb_tid =
      queues.callback()->Invoke([]() { return std::this_thread::get_id(); });

  EXPECT_NE(sig_tid, work_tid);
  EXPECT_NE(work_tid, pace_tid);
  EXPECT_NE(pace_tid, net_tid);
  EXPECT_NE(net_tid, cb_tid);

  std::atomic<int> counter{0};
  queues.worker()->Invoke([&]() {
    ScopedTaskSafety safety;
    queues.worker()->PostDelayedTask(
        SafeTask(safety.flag(), [&]() { counter.fetch_add(1); }),
        TimeDelta::Millis(30));
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(60));
  EXPECT_EQ(counter.load(), 0);
}

TEST(RtcBaseTest, PacketSlabPoolAndJsonUtilsZeroException) {
  auto pool = PacketSlabPool::Create(16);
  EXPECT_EQ(pool->FreeSlots(), 16u);
  {
    auto p1 = pool->Acquire();
    auto p2 = pool->Acquire();
    EXPECT_EQ(pool->FreeSlots(), 14u);
    const uint8_t sample[4] = {1, 2, 3, 4};
    p1->Assign(MakeArrayView(sample, 4));
    EXPECT_EQ(p1->size, 4u);
  }
  EXPECT_EQ(pool->FreeSlots(), 16u);

  JsonObject obj;
  obj.SetString("sdp", "v=0\r\nm=video 9\r\n");
  obj.SetUint32("ssrc", 0x12345678u);
  const std::string encoded = obj.Serialize();
  const auto decoded = JsonObject::Parse(encoded);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->GetString("sdp"), "v=0\r\nm=video 9\r\n");
  EXPECT_EQ(decoded->GetUint32("ssrc"), 0x12345678u);
  EXPECT_FALSE(JsonObject::Parse("{malformed_json").has_value());
}

// 2. 验证 H.264（RFC 6184）与 H.265（RFC 7798）RTP 打包器及 RTP 头部扩展
TEST(RtpRtcpTest, H264AndH265PacketizerAndExtensionsRoundTrip) {
  const std::vector<uint8_t> sps_pps = {
      0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1F, 0xAA,
      0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80};
  H264Packetizer h264_pkt(1000);
  bool is_kf = false;
  auto param_slices = h264_pkt.PacketizeAnnexB(sps_pps, &is_kf);
  ASSERT_EQ(param_slices.size(), 1u);
  EXPECT_EQ(param_slices[0].bytes[0] & 0x1F, 24);

  std::vector<uint8_t> large_idr = {0x00, 0x00, 0x00, 0x01, 0x65};
  large_idr.resize(3505, 0x5A);
  auto idr_slices = h264_pkt.PacketizeAnnexB(large_idr, &is_kf);
  EXPECT_TRUE(is_kf);
  ASSERT_GE(idr_slices.size(), 5u);

  PacketBuffer pb(VideoCodec::kH264);
  uint16_t seq = 500;
  std::vector<AssembledRtpFrame> out_frames;
  for (size_t i = 0; i < idr_slices.size(); ++i) {
    RtpPacket pkt;
    pkt.set_sequence_number(seq++);
    pkt.set_timestamp(90000);
    pkt.set_ssrc(0x11223344);
    pkt.set_marker(idr_slices[i].is_last_in_frame);
    pkt.set_transport_sequence_number(static_cast<uint16_t>(10 + i));
    pkt.SetMid("0");
    pkt.SetRid("h");
    pkt.set_playout_delay(PlayoutDelayLimits{0, 0});

    CompactDependencyExtension dep;
    dep.is_first_in_frame = idr_slices[i].is_first_in_frame;
    dep.is_last_in_frame = idr_slices[i].is_last_in_frame;
    dep.is_keyframe = true;
    dep.frame_number = 1;
    pkt.set_dependency_descriptor(dep);
    *pkt.mutable_payload() = idr_slices[i].bytes;

    const auto wire = pkt.Serialize();
    RtpPacket parsed;
    ASSERT_TRUE(parsed.Parse(wire));
    EXPECT_EQ(parsed.rid().value_or(""), "h");
    EXPECT_EQ(parsed.transport_sequence_number().value_or(0), 10 + i);

    auto f = pb.InsertPacket(parsed, Timestamp::Millis(1000));
    out_frames.insert(out_frames.end(), f.begin(), f.end());
  }
  ASSERT_EQ(out_frames.size(), 1u);
  EXPECT_TRUE(out_frames[0].is_keyframe);
  EXPECT_EQ(out_frames[0].annexb_bitstream.size(),
            sps_pps.size() + large_idr.size());

  std::vector<uint8_t> h265_irap = {
      0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0xAA, 0xBB,
      0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0xCC, 0xDD,
      0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xEE, 0xFF,
      0x00, 0x00, 0x00, 0x01, 0x26, 0x01};
  h265_irap.resize(2800, 0x77);
  H265Packetizer h265_pkt(900);
  bool h265_kf = false;
  auto h265_slices = h265_pkt.PacketizeAnnexB(h265_irap, &h265_kf);
  EXPECT_TRUE(h265_kf);
  PacketBuffer pb265(VideoCodec::kH265);
  std::vector<AssembledRtpFrame> f265;
  for (const auto& s : h265_slices) {
    RtpPacket pkt;
    pkt.set_sequence_number(seq++);
    pkt.set_timestamp(180000);
    pkt.set_marker(s.is_last_in_frame);
    *pkt.mutable_payload() = s.bytes;
    auto res = pb265.InsertPacket(pkt, Timestamp::Millis(2000));
    f265.insert(f265.end(), res.begin(), res.end());
  }
  ASSERT_EQ(f265.size(), 1u);
  EXPECT_EQ(f265[0].annexb_bitstream, h265_irap);
}

// 3. 验证 FlexFEC 擦除恢复以及 RtxCodec 与 RtpPacketHistory 的 RTT 重传门控机制
TEST(RtpRtcpTest, FlexfecAndRtxRecovery) {
  FlexfecSender fec_tx(118, 0x9999, 0x1111, "0");
  fec_tx.SetProtectionParameters(FecProtectionParams{85, 1, false});
  FlexfecReceiver fec_rx(0x9999, 0x1111);

  std::vector<RtpPacket> media;
  for (int i = 0; i < 3; ++i) {
    RtpPacket p;
    p.set_ssrc(0x1111);
    p.set_sequence_number(static_cast<uint16_t>(100 + i));
    p.set_timestamp(9000);
    std::vector<uint8_t> body(200 + i * 30, static_cast<uint8_t>(0x30 + i));
    *p.mutable_payload() = body;
    fec_tx.AddRtpPacketAndGenerateFec(p);
    media.push_back(p);
  }
  auto fec_pkts = fec_tx.GetFecPackets();
  ASSERT_EQ(fec_pkts.size(), 1u);

  EXPECT_TRUE(fec_rx.OnRtpPacket(media[0]).empty());
  EXPECT_TRUE(fec_rx.OnRtpPacket(media[2]).empty());
  auto recovered = fec_rx.OnRtpPacket(fec_pkts[0]);
  ASSERT_EQ(recovered.size(), 1u);
  EXPECT_EQ(recovered[0].sequence_number(), 101);
  EXPECT_EQ(recovered[0].payload(), media[1].payload());

  RtpPacketHistory hist(128);
  hist.SetRtt(TimeDelta::Millis(50));
  hist.PutRtpPacket(media[1], Timestamp::Millis(1000));

  auto first_rtx_hit = hist.GetPacketAndMarkAsSent(101, Timestamp::Millis(1010));
  ASSERT_TRUE(first_rtx_hit.has_value());
  EXPECT_FALSE(
      hist.GetPacketAndMarkAsSent(101, Timestamp::Millis(1015)).has_value());
  EXPECT_TRUE(
      hist.GetPacketAndMarkAsSent(101, Timestamp::Millis(1065)).has_value());

  RtpPacket rtx_pkt = RtxCodec::BuildRtxPacket(*first_rtx_hit, 0x2222, 97, 777);
  auto unwrapped = RtxCodec::ParseRtxPacket(rtx_pkt, 0x1111, 96);
  ASSERT_TRUE(unwrapped.has_value());
  EXPECT_EQ(unwrapped->sequence_number(), 101);
  EXPECT_EQ(unwrapped->payload(), media[1].payload());
}

// 4. 验证 TWCC RtcpTransportFeedback 与 RtcpNack BLP 位掩码线速编解码
TEST(RtpRtcpTest, TwccFeedbackAndNackCodec) {
  RtcpNack nack;
  nack.sender_ssrc = 1;
  nack.media_ssrc = 2;
  nack.packet_ids = {1000, 1001, 1005, 1016, 1020};
  const auto nack_wire = nack.Build();
  const auto parsed_rtcp = ParseCompoundRtcp(nack_wire);
  ASSERT_EQ(parsed_rtcp.nacks.size(), 1u);
  EXPECT_EQ(parsed_rtcp.nacks[0].packet_ids, nack.packet_ids);

  RtcpTransportFeedback fb;
  fb.sender_ssrc = 10;
  fb.media_ssrc = 20;
  const Timestamp t0 = Timestamp::Millis(1280);
  fb.SetBase(300, t0);
  fb.AddReceivedPacket(300, t0);
  fb.AddReceivedPacket(302, t0 + TimeDelta::Millis(5));
  fb.AddReceivedPacket(303, t0 + TimeDelta::Millis(120));

  const auto fb_wire = fb.Build();
  const auto parsed_fb = ParseCompoundRtcp(fb_wire);
  ASSERT_EQ(parsed_fb.transport_feedbacks.size(), 1u);
  const auto statuses = parsed_fb.transport_feedbacks[0].AllPacketStatuses();
  ASSERT_EQ(statuses.size(), 4u);
  EXPECT_TRUE(statuses[0].receive_time.IsFinite());
  EXPECT_FALSE(statuses[1].receive_time.IsFinite());
  EXPECT_EQ((statuses[2].receive_time - statuses[0].receive_time).ms(), 5);
  EXPECT_EQ((statuses[3].receive_time - statuses[0].receive_time).ms(), 120);
}

// 5. 验证 GoogCcNetworkController 闭环拥塞检测与码率退避
TEST(GoogCcTest, DetectsBottleneckQueueingAndReducesBitrate) {
  GoogCcConfig cfg;
  cfg.min_bitrate = DataRate::KilobitsPerSec(150);
  cfg.start_bitrate = DataRate::KilobitsPerSec(2000);
  cfg.max_bitrate = DataRate::KilobitsPerSec(5000);

  GoogCcNetworkController goog_cc(cfg);
  TransportFeedbackAdapter adapter;

  Timestamp now = Timestamp::Millis(10'000);
  goog_cc.OnNetworkAvailability(now, true);

  Timestamp bottleneck_free_at = now + TimeDelta::Millis(25);
  uint16_t twcc_seq = 1;

  for (int step = 0; step < 30; ++step) {
    RtcpTransportFeedback fb;
    fb.SetBase(twcc_seq, bottleneck_free_at);
    for (int p = 0; p < 10; ++p) {
      const uint16_t seq = twcc_seq++;
      adapter.AddPacket(seq, DataSize::Bytes(1200), PacedPacketInfo{}, now);
      auto sent = adapter.ProcessSentPacket(seq, now);
      ASSERT_TRUE(sent.has_value());
      goog_cc.OnSentPacket(*sent);

      const Timestamp wire_arrival =
          std::max(now + TimeDelta::Millis(25), bottleneck_free_at) +
          TimeDelta::Micros(13'714);
      bottleneck_free_at = wire_arrival;
      fb.AddReceivedPacket(seq, wire_arrival);
      now += TimeDelta::Micros(4800);
    }
    auto report = adapter.ProcessTransportFeedback(
        fb, bottleneck_free_at + TimeDelta::Millis(25));
    if (report.has_value()) {
      goog_cc.OnTransportPacketsFeedback(*report);
    }
  }

  EXPECT_LT(goog_cc.TargetRate().kbps(), 1100);
  EXPECT_GE(goog_cc.TargetRate().kbps(), 150);
}

// 6. 验证 FrameBuffer3 严格参考帧连续性门控
TEST(VideoCodingTest, FrameBuffer3BlocksBrokenReferencesAndRecoversOnIdr) {
  FrameBuffer3 fb(64);
  auto make_frame = [](int64_t fid, bool is_key, int64_t ref_id) {
    AssembledRtpFrame f;
    f.rtp_timestamp = static_cast<uint32_t>(fid * 3000);
    f.received_time = Timestamp::Millis(fid * 33);
    f.is_keyframe = is_key;
    f.dep.frame_id = fid;
    f.dep.is_keyframe = is_key;
    f.dep.num_references = is_key ? 0 : 1;
    if (!is_key) {
      f.dep.references[0] = ref_id;
    }
    f.annexb_bitstream = {0, 0, 0, 1, 0x65};
    return f;
  };

  fb.InsertFrame(make_frame(1, true, 0));
  auto d1 = fb.ExtractNextDecodableFrame();
  ASSERT_TRUE(d1.has_value());
  EXPECT_EQ(d1->dep.frame_id, 1);

  fb.InsertFrame(make_frame(3, false, 2));
  fb.InsertFrame(make_frame(4, false, 3));
  EXPECT_FALSE(fb.ExtractNextDecodableFrame().has_value());

  fb.InsertFrame(make_frame(5, true, 0));
  fb.InsertFrame(make_frame(6, false, 5));

  auto d5 = fb.ExtractNextDecodableFrame();
  ASSERT_TRUE(d5.has_value());
  EXPECT_EQ(d5->dep.frame_id, 5);

  auto d6 = fb.ExtractNextDecodableFrame();
  ASSERT_TRUE(d6.has_value());
  EXPECT_EQ(d6->dep.frame_id, 6);
}

// 7. 验证 STUN HMAC-SHA1 消息完整性 + CRC32 指纹校验及 libsrtp2 AEAD-AES-128-GCM 加解密
TEST(TransportCryptoTest, StunIntegrityAndLibsrtpGcmRoundTrip) {
  StunMessage req(StunMessageType::kBindingRequest);
  req.set_username("serverUfrag:clientUfrag");
  req.set_priority(1853824767u);
  req.set_ice_controlling(0x1122334455667788ULL);
  req.set_use_candidate(true);
  const boost::asio::ip::udp::endpoint mapped(
      boost::asio::ip::make_address_v4("192.168.10.55"), 54321);
  req.set_xor_mapped_address(mapped);

  const auto wire = req.Serialize("secret_ice_password", true);
  EXPECT_TRUE(StunMessage::IsStunPacket(wire));
  EXPECT_FALSE(StunMessage::Parse(wire, "wrong_password").has_value());

  const auto parsed = StunMessage::Parse(wire, "secret_ice_password");
  ASSERT_TRUE(parsed.has_value());
  EXPECT_TRUE(parsed->use_candidate());
  ASSERT_TRUE(parsed->xor_mapped_address().has_value());
  EXPECT_EQ(*parsed->xor_mapped_address(), mapped);

  const std::vector<uint8_t> key_a(28, 0x42);
  const std::vector<uint8_t> key_b(28, 0x99);
  SrtpSessionPair alice;
  SrtpSessionPair bob;
  ASSERT_TRUE(alice.SetupKeys(SrtpCipherProfile::kAeadAes128Gcm, key_a, key_b));
  ASSERT_TRUE(bob.SetupKeys(SrtpCipherProfile::kAeadAes128Gcm, key_b, key_a));

  RtpPacket rtp;
  rtp.set_ssrc(0xCAFEBABE);
  rtp.set_sequence_number(42);
  rtp.set_timestamp(90000);
  const uint8_t payload[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
  rtp.SetPayload(MakeArrayView(payload, sizeof(payload)));

  auto cipher_buf = rtp.Serialize();
  const auto plain_orig = cipher_buf;
  ASSERT_TRUE(alice.ProtectRtp(&cipher_buf));
  EXPECT_GT(cipher_buf.size(), plain_orig.size());

  ASSERT_TRUE(bob.UnprotectRtp(&cipher_buf));
  EXPECT_EQ(cipher_buf, plain_orig);
}

// 8. 验证 IETF MoQ 变长整数（VarInt）、控制消息编解码器及 LOC 帧封装器
TEST(MoqTransportTest, VarIntControlAndLocPackagerRoundTrip) {
  std::vector<uint8_t> varints;
  const uint64_t values[] = {0, 63, 64, 16383, 16384, 1073741823ULL,
                             9876543210123ULL};
  for (uint64_t v : values) {
    QuicVarInt::Append(v, &varints);
  }
  size_t off = 0;
  for (uint64_t expected : values) {
    uint64_t actual = 0;
    ASSERT_TRUE(QuicVarInt::Read(varints, &off, &actual));
    EXPECT_EQ(actual, expected);
  }

  MoqControlMessage sub;
  sub.type = MoqControlMessageType::kSubscribe;
  sub.subscribe_id = 42;
  sub.track_alias = 142;
  sub.track_namespace = "room1/cam_01";
  sub.track_name = "video/high";
  sub.subscriber_priority = 64;
  sub.filter_type = MoqFilterType::kLatestGroup;
  const auto sub_wire = sub.Encode();
  size_t sub_consumed = 0;
  const auto parsed_sub = MoqControlMessage::Decode(sub_wire, &sub_consumed);
  ASSERT_TRUE(parsed_sub.has_value());
  EXPECT_EQ(parsed_sub->subscribe_id, 42u);
  EXPECT_EQ(parsed_sub->track_alias, 142u);
  EXPECT_EQ(parsed_sub->track_namespace, "room1/cam_01");
  EXPECT_EQ(parsed_sub->track_name, "video/high");

  EncodedVideoFrame orig;
  orig.capture_time = Timestamp::Micros(1234567);
  orig.rtp_timestamp = 90000;
  orig.codec = VideoCodec::kH265;
  orig.layer = SpatialLayer::kHigh;
  orig.dep.frame_id = 15;
  orig.dep.is_keyframe = false;
  orig.dep.temporal_id = 1;
  orig.dep.num_references = 1;
  orig.dep.references[0] = 14;
  orig.data = {0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0xAA, 0xBB};

  const auto loc_wire = LocFramePackager::PackObject(7, orig);
  size_t loc_consumed = 0;
  uint64_t obj_id = 0;
  const auto unpacked =
      LocFramePackager::UnpackObject(loc_wire, &loc_consumed, &obj_id);
  ASSERT_TRUE(unpacked.has_value());
  EXPECT_EQ(obj_id, 7u);
  EXPECT_EQ(unpacked->codec, VideoCodec::kH265);
  EXPECT_EQ(unpacked->layer, SpatialLayer::kHigh);
  EXPECT_EQ(unpacked->dep.frame_id, 15);
  EXPECT_EQ(unpacked->dep.references[0], 14);
  EXPECT_EQ(unpacked->data, orig.data);
}

// 9. 验证 RFC 9001 附录 A.1 初始密钥测试向量、数据包/头部保护、
//    选择性确认（Selective ACK）区间编解码，以及乱序流重组与 RESET_STREAM 丢弃
TEST(QuicTransportTest, Rfc9001InitialVectorAndPacketProtectionAndReassembly) {
  // RFC 9001 附录 A.1 官方客户端初始目标连接 ID（DCID）：0x8394c8f03e515708
  const uint8_t rfc_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  QuicTrafficKeys client_keys;
  QuicTrafficKeys server_keys;
  std::array<uint8_t, 32> init_secret{};
  ASSERT_TRUE(QuicCryptoUtils::DeriveInitialKeys(
      MakeArrayView(rfc_dcid, 8), &client_keys, &server_keys, &init_secret));

  const uint8_t expected_client_key[16] = {
      0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
      0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d};
  const uint8_t expected_client_iv[12] = {0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3,
                                          0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c};
  const uint8_t expected_client_hp[16] = {
      0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
      0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2};
  const uint8_t expected_server_key[16] = {
      0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
      0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37};

  EXPECT_EQ(0, std::memcmp(client_keys.aead_key.data(), expected_client_key, 16));
  EXPECT_EQ(0, std::memcmp(client_keys.aead_iv.data(), expected_client_iv, 12));
  EXPECT_EQ(0, std::memcmp(client_keys.hp_key.data(), expected_client_hp, 16));
  EXPECT_EQ(0, std::memcmp(server_keys.aead_key.data(), expected_server_key, 16));

  // 验证长包头 Initial 包的 1200 字节最小填充及头部保护/AEAD 加密。
  std::vector<uint8_t> init_hdr = {0xC3, 0x00, 0x00, 0x00, 0x01, 0x08};
  init_hdr.insert(init_hdr.end(), rfc_dcid, rfc_dcid + 8);
  init_hdr.push_back(0x08);
  init_hdr.insert(init_hdr.end(), rfc_dcid, rfc_dcid + 8);
  init_hdr.push_back(0x00);  // Token 长度 = 0

  const uint8_t ping_frame[] = {0x01};
  auto protected_init = QuicCryptoUtils::ProtectPacket(
      client_keys, 2, init_hdr, /*is_long_header=*/true,
      MakeArrayView(ping_frame, 1), kQuicMinClientInitialSize);
  ASSERT_GE(protected_init.size(), kQuicMinClientInitialSize);

  auto unprot = QuicCryptoUtils::UnprotectPacket(protected_init, client_keys, 1);
  ASSERT_TRUE(unprot.has_value());
  EXPECT_EQ(unprot->level, QuicEncryptionLevel::kInitial);
  EXPECT_EQ(unprot->packet_number, 2u);
  EXPECT_EQ(unprot->plaintext[0], 0x01);

  // 篡改密文必须干脆地触发 GCM 认证失败。
  protected_init.back() ^= 0x55;
  EXPECT_FALSE(
      QuicCryptoUtils::UnprotectPacket(protected_init, client_keys, 1).has_value());

  // 验证选择性确认（Selective ACK）多区间空洞（Gap）的编码与解码。
  QuicAckRangeSet ack_set;
  ack_set.RecordReceived(0, true);
  ack_set.RecordReceived(1, true);
  ack_set.RecordReceived(4, true);
  ack_set.RecordReceived(7, true);
  ack_set.RecordReceived(8, true);
  std::vector<uint8_t> ack_wire;
  ack_set.EncodeAckFrame(240, &ack_wire);
  size_t ack_off = 0;
  uint64_t decoded_delay = 0;
  std::vector<QuicAckRangeSet::Range> decoded_ranges;
  ASSERT_TRUE(QuicAckRangeSet::DecodeAckFrame(ack_wire, &ack_off, &decoded_delay,
                                              &decoded_ranges));
  ASSERT_EQ(decoded_ranges.size(), 3u);
  EXPECT_EQ(decoded_ranges[0].smallest, 7u);
  EXPECT_EQ(decoded_ranges[0].largest, 8u);
  EXPECT_EQ(decoded_ranges[1].smallest, 4u);
  EXPECT_EQ(decoded_ranges[1].largest, 4u);
  EXPECT_EQ(decoded_ranges[2].smallest, 0u);
  EXPECT_EQ(decoded_ranges[2].largest, 1u);

  // 验证 QuicStreamReceiveBuffer 乱序流重组及 RESET_STREAM 数据丢弃。
  QuicStreamReceiveBuffer rx_stream;
  const uint8_t part2[] = {'W', 'o', 'r', 'l', 'd'};
  const uint8_t part1[] = {'H', 'e', 'l', 'l', 'o', ' '};
  rx_stream.InsertChunk(6, MakeArrayView(part2, 5), /*fin=*/true);
  std::vector<uint8_t> out_bytes;
  bool out_fin = false;
  EXPECT_FALSE(rx_stream.ExtractContiguous(&out_bytes, &out_fin));

  rx_stream.InsertChunk(0, MakeArrayView(part1, 6), /*fin=*/false);
  ASSERT_TRUE(rx_stream.ExtractContiguous(&out_bytes, &out_fin));
  EXPECT_TRUE(out_fin);
  const std::string assembled(out_bytes.begin(), out_bytes.end());
  EXPECT_EQ(assembled, "Hello World");

  QuicStreamReceiveBuffer reset_stream;
  reset_stream.InsertChunk(10, MakeArrayView(part2, 5), false);
  reset_stream.Reset();
  EXPECT_TRUE(reset_stream.is_reset());
  EXPECT_FALSE(reset_stream.ExtractContiguous(&out_bytes, &out_fin));
}

// 10. 验证 W3C 浏览器（Chrome/Firefox/Safari）SDP Offer 解析、动态负载类型（PT）
//     选择，以及 RFC 8285 双字节 RTP 头部扩展（扩展 ID >= 15）
TEST(BrowserCompatibilityTest,
     ChromeOfferSdpNegotiationAndTwoByteRtpExtensions) {
  const std::string chrome_offer_sdp =
      "v=0\r\n"
      "o=- 70123456789 2 IN IP4 127.0.0.1\r\n"
      "s=-\r\n"
      "t=0 0\r\n"
      "a=group:BUNDLE 0 video_mid\r\n"
      "a=extmap-allow-mixed\r\n"
      "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
      "a=mid:0\r\n"
      "a=rtpmap:111 opus/48000/2\r\n"
      "m=video 9 UDP/TLS/RTP/SAVPF 96 97 100 101 102 103 49\r\n"
      "c=IN IP4 0.0.0.0\r\n"
      "a=ice-ufrag:chromeUf\r\n"
      "a=ice-pwd:chromePassword1234567890\r\n"
      "a=fingerprint:SHA-256 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:"
      "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99\r\n"
      "a=setup:actpass\r\n"
      "a=mid:video_mid\r\n"
      "a=sendrecv\r\n"
      "a=rtcp-mux\r\n"
      "a=extmap:4/sendrecv urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
      "a=extmap:15 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
      "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
      "a=rtpmap:96 VP8/90000\r\n"
      "a=rtpmap:97 rtx/90000\r\n"
      "a=fmtp:97 apt=96\r\n"
      "a=rtpmap:100 H264/90000\r\n"
      "a=fmtp:100 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\n"
      "a=rtpmap:101 rtx/90000\r\n"
      "a=fmtp:101 apt=100\r\n"
      "a=rtpmap:102 H264/90000\r\n"
      "a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
      "a=rtpmap:103 rtx/90000\r\n"
      "a=fmtp:103 apt=102\r\n"
      "a=rtpmap:49 flexfec-03/90000\r\n"
      "a=fmtp:49 repair-window=10000000\r\n"
      "a=candidate:1 1 UDP 2122260223 192c88a1-9999.local 51234 typ host\r\n"
      "a=candidate:2 1 UDP 2122194687 192.168.1.88 51234 typ host\r\n";

  const auto parsed =
      PureVideoSdpDescription::Parse(chrome_offer_sdp, VideoCodec::kH264);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->video_m_sections.size(), 1u);
  EXPECT_EQ(parsed->candidates.size(), 1u);

  const auto& vm = parsed->video_m_sections[0];
  EXPECT_EQ(vm.mid, "video_mid");
  EXPECT_EQ(vm.codec, VideoCodec::kH264);
  EXPECT_EQ(vm.video_pt, 102);
  EXPECT_TRUE(vm.has_rtx);
  EXPECT_EQ(vm.rtx_pt, 103);
  EXPECT_TRUE(vm.has_flexfec);
  EXPECT_EQ(vm.flexfec_pt, 49);
  EXPECT_EQ(vm.ext_map.mid_id, 4);
  EXPECT_EQ(vm.ext_map.transport_sequence_number_id, 15);
  EXPECT_EQ(vm.ext_map.absolute_send_time_id, 2);
  EXPECT_EQ(vm.ext_map.dependency_descriptor_id, 0);

  // 验证当扩展 ID 为 15 时启用 RFC 8285 双字节头部扩展（0x1000）。
  RtpPacket pkt;
  pkt.set_extension_map(vm.ext_map);
  pkt.set_payload_type(vm.video_pt);
  pkt.set_ssrc(0x12345678);
  pkt.set_sequence_number(500);
  pkt.set_timestamp(90000);
  pkt.set_transport_sequence_number(888);
  pkt.SetMid("video_mid");
  const uint8_t nalu[] = {0x65, 0x88, 0x84};
  pkt.SetPayload(nalu);

  const auto wire = pkt.Serialize();
  // 偏移量 12..13 处的扩展标识字节必须为 0x1000（RFC 8285 双字节扩展格式）。
  ASSERT_GT(wire.size(), 16u);
  EXPECT_EQ(wire[12], 0x10);
  EXPECT_EQ(wire[13], 0x00);

  RtpPacket rx_pkt;
  ASSERT_TRUE(rx_pkt.Parse(wire, vm.ext_map));
  ASSERT_TRUE(rx_pkt.transport_sequence_number().has_value());
  EXPECT_EQ(*rx_pkt.transport_sequence_number(), 888);
  ASSERT_TRUE(rx_pkt.mid().has_value());
  EXPECT_EQ(*rx_pkt.mid(), "video_mid");
}

// 11. 验证亚毫秒级 PacingController 时间债务核算（200 微秒步进）
//     实现约 100% 码率利用率且无整数截断损耗。
TEST(GoogCcTest, SubMillisecondPacerPrecisionAndZeroBudgetStarvation) {
  class CountingPacketSender final : public PacingPacketSender {
   public:
    void SendPacedPacket(std::unique_ptr<RtpPacket> packet,
                         const PacedPacketInfo& /*cluster_info*/) override {
      ++packets_sent;
      bytes_sent += packet->SerializedSize();
    }

    std::vector<std::unique_ptr<RtpPacket>> GeneratePadding(
        DataSize target_size) override {
      std::vector<std::unique_ptr<RtpPacket>> out;
      auto pad = std::make_unique<RtpPacket>();
      pad->set_ssrc(0x5555);
      pad->set_padding_size(
          static_cast<size_t>(std::clamp<int64_t>(target_size.bytes() - 12, 24, 224)));
      out.push_back(std::move(pad));
      return out;
    }

    size_t packets_sent = 0;
    size_t bytes_sent = 0;
  };

  SimulatedClock sim_clock(Timestamp::Millis(50'000));
  CountingPacketSender sender;
  PacingController pacer(&sim_clock, &sender);
  // 4.0 Mbps = 500,000 字节/秒；禁用紧急队列排空，以便严格测量
  // 纯粹的令牌/时间债务平滑发送精度。
  pacer.set_queue_time_limit(TimeDelta::Seconds(10));
  pacer.SetPacingRates(DataRate::KilobitsPerSec(4000), DataRate::Zero());

  for (int i = 0; i < 550; ++i) {
    auto pkt = std::make_unique<RtpPacket>();
    pkt->set_ssrc(0x1111);
    pkt->set_sequence_number(static_cast<uint16_t>(i));
    std::vector<uint8_t> body(1000 - RtpPacket::kFixedHeaderSize, 0xAA);
    *pkt->mutable_payload() = std::move(body);
    ASSERT_EQ(pkt->SerializedSize(), 1000u);
    pacer.EnqueuePacket(std::move(pkt), RtpPacketMediaType::kVideoDelta);
  }

  // 以 200 微秒为步长推进 1.000 秒（共 5000 次亚毫秒级唤醒）。
  for (int tick = 0; tick < 5000; ++tick) {
    pacer.ProcessPackets();
    sim_clock.AdvanceTime(TimeDelta::Micros(200));
  }

  const double achieved_kbps = (static_cast<double>(sender.bytes_sent) * 8.0) / 1000.0;
  const double utilization = achieved_kbps / 4000.0;
  RTC_LOG(kInfo) << "Sub-ms Pacer benchmark: sent=" << sender.packets_sent
                 << " pkts (" << achieved_kbps
                 << " kbps, utilization=" << (utilization * 100.0) << "%)";
  EXPECT_GE(utilization, 0.995);
  EXPECT_LE(utilization, 1.005);
}

// 12. 闭环瓶颈链路仿真器：验证 GoogCC + ProbeBitrateEstimator
//     快速带宽探测爬升、不崩溃的阶跃降速退避以及物理链路利用率。
TEST(GoogCcTest, ClosedLoopProbeConvergenceBackoffAndWireUtilization) {
  struct InFlightFeedbackEvent {
    Timestamp feedback_arrival_time;
    uint16_t twcc_seq;
    Timestamp wire_arrival_time;
  };

  class ClosedLoopHarness final : public PacingPacketSender {
   public:
    ClosedLoopHarness(SimulatedClock* clk, GoogCcNetworkController* cc)
        : clock_(clk), goog_cc_(cc) {}

    void SendPacedPacket(std::unique_ptr<RtpPacket> packet,
                         const PacedPacketInfo& cluster_info) override {
      const Timestamp now = clock_->CurrentTime();
      const uint16_t seq = next_twcc_seq_++;
      const DataSize sz = DataSize::Bytes(packet->SerializedSize());
      phase_wire_bytes += packet->SerializedSize();

      adapter.AddPacket(seq, sz, cluster_info, now);
      auto sent = adapter.ProcessSentPacket(seq, now);
      if (sent.has_value()) {
        ApplyUpdate(goog_cc_->OnSentPacket(*sent));
      }

      const TimeDelta tx_time = sz / link_capacity;
      bottleneck_free_at = std::max(now, bottleneck_free_at) + tx_time;
      const Timestamp wire_arrival = bottleneck_free_at + one_way_delay;
      max_queue_delay = std::max(max_queue_delay, bottleneck_free_at - now);
      pending_rx.push_back(
          InFlightFeedbackEvent{wire_arrival + one_way_delay, seq, wire_arrival});
    }

    std::vector<std::unique_ptr<RtpPacket>> GeneratePadding(
        DataSize target_size) override {
      std::vector<std::unique_ptr<RtpPacket>> pad_pkts;
      int64_t rem = target_size.bytes();
      while (rem > 24) {
        auto p = std::make_unique<RtpPacket>();
        p->set_ssrc(0x2222);
        p->set_sequence_number(pad_seq_++);
        const size_t pad =
            static_cast<size_t>(std::clamp<int64_t>(rem - 12, 24, 224));
        p->set_padding_size(pad);
        rem -= static_cast<int64_t>(p->SerializedSize());
        pad_pkts.push_back(std::move(p));
      }
      return pad_pkts;
    }

    void ApplyUpdate(const NetworkControlUpdate& upd) {
      if (upd.congestion_window.has_value() && pacer != nullptr) {
        pacer->SetCongestionWindow(*upd.congestion_window);
      }
      if (upd.pacer_config.has_value() && pacer != nullptr) {
        pacer->SetPacingRates(upd.pacer_config->data_rate(),
                              upd.pacer_config->pad_rate());
      }
      if (!upd.probe_cluster_configs.empty() && pacer != nullptr) {
        pacer->CreateProbeClusters(upd.probe_cluster_configs);
      }
    }

    SimulatedClock* clock_;
    GoogCcNetworkController* goog_cc_;
    PacingController* pacer = nullptr;
    TransportFeedbackAdapter adapter;

    DataRate link_capacity = DataRate::KilobitsPerSec(3000);
    TimeDelta one_way_delay = TimeDelta::Millis(20);
    Timestamp bottleneck_free_at = Timestamp::MinusInfinity();
    TimeDelta max_queue_delay = TimeDelta::Zero();

    uint16_t next_twcc_seq_ = 1;
    uint16_t pad_seq_ = 1;
    size_t phase_wire_bytes = 0;
    std::vector<InFlightFeedbackEvent> pending_rx;
  };

  SimulatedClock clk(Timestamp::Millis(100'000));
  GoogCcConfig cfg;
  cfg.min_bitrate = DataRate::KilobitsPerSec(150);
  cfg.start_bitrate = DataRate::KilobitsPerSec(800);
  cfg.max_bitrate = DataRate::KilobitsPerSec(6000);

  GoogCcNetworkController goog_cc(cfg);
  ClosedLoopHarness harness(&clk, &goog_cc);
  PacingController pacer(&clk, &harness);
  harness.pacer = &pacer;

  SimulcastRateAllocator allocator(
      SimulcastAllocatorConfig{false, 150'000, 120'000, 500'000, 400'000, 80'000,
                               6'000'000});

  harness.ApplyUpdate(goog_cc.OnNetworkAvailability(clk.CurrentTime(), true));

  uint16_t media_seq = 100;
  auto run_simulation_ms = [&](int duration_ms) {
    for (int ms = 0; ms < duration_ms; ++ms) {
      const Timestamp now = clk.CurrentTime();
      // 30 fps 编码器严格按照分配的媒体码率预算生成对应大小的视频帧
      if ((ms % 33) == 0) {
        const DataRate target = goog_cc.TargetRate();
        // 无丢包链路下的 WebRTC 协议开销约为 3.5%（RTP 包头 + 稀疏 IDR 帧冗余校验）
        const auto alloc = allocator.Allocate(target, 0.035);
        const size_t frame_bytes = static_cast<size_t>(
            (static_cast<uint64_t>(alloc.layers[1].target_bitrate_bps) * 33) /
            8000);
        size_t rem = frame_bytes;
        while (rem > 0) {
          const size_t chunk = std::min<size_t>(rem, 1150);
          rem -= chunk;
          auto pkt = std::make_unique<RtpPacket>();
          pkt->set_ssrc(0x1111);
          pkt->set_sequence_number(media_seq++);
          pkt->mutable_payload()->assign(chunk, 0x5A);
          pacer.EnqueuePacket(std::move(pkt), RtpPacketMediaType::kVideoDelta);
        }
      }

      pacer.ProcessPackets();
      pacer.UpdateOutstandingData(harness.adapter.outstanding_data());

      // 每 30ms 投递一次 TWCC 传输层反馈报文
      if ((ms % 30) == 0 && !harness.pending_rx.empty()) {
        std::vector<InFlightFeedbackEvent> ready;
        std::vector<InFlightFeedbackEvent> future;
        for (const auto& ev : harness.pending_rx) {
          if (ev.feedback_arrival_time <= now) {
            ready.push_back(ev);
          } else {
            future.push_back(ev);
          }
        }
        harness.pending_rx = std::move(future);
        if (!ready.empty()) {
          RtcpTransportFeedback fb;
          fb.SetBase(ready.front().twcc_seq, ready.front().wire_arrival_time);
          for (const auto& ev : ready) {
            fb.AddReceivedPacket(ev.twcc_seq, ev.wire_arrival_time);
          }
          if (auto rep = harness.adapter.ProcessTransportFeedback(fb, now)) {
            harness.ApplyUpdate(goog_cc.OnTransportPacketsFeedback(*rep));
          }
        }
      }

      if ((ms % 25) == 0) {
        harness.ApplyUpdate(goog_cc.OnProcessInterval(now));
      }
      clk.AdvanceTime(TimeDelta::Millis(1));
    }
  };

  // 阶段 1a（0..594ms，共 18 帧）：启动带宽探测从 800 kbps 快速爬升至 3000 kbps。
  run_simulation_ms(594);
  const int64_t est_after_probe_kbps = goog_cc.TargetRate().kbps();
  EXPECT_GE(est_after_probe_kbps, 2400);
  EXPECT_LE(est_after_probe_kbps, 3100);

  // 阶段 1b（随后 990ms，按 33ms 间隔共精确 30 帧）：测量稳态链路利用率。
  harness.phase_wire_bytes = 0;
  run_simulation_ms(990);
  const double steady_3m_wire_kbps =
      (static_cast<double>(harness.phase_wire_bytes) * 8.0) / 0.990 / 1000.0;
  const double util_3m = steady_3m_wire_kbps / 3000.0;
  RTC_LOG(kInfo) << "[BWE Phase 1] 3000 kbps link -> est="
                 << goog_cc.TargetRate().kbps()
                 << " kbps, wire=" << steady_3m_wire_kbps
                 << " kbps (utilization=" << (util_3m * 100.0) << "%)";
  EXPECT_GE(util_3m, 0.90);
  EXPECT_LE(util_3m, 1.02);

  // 阶段 2：瓶颈链路容量从 3000 kbps 骤降至 1000 kbps。
  harness.link_capacity = DataRate::KilobitsPerSec(1000);
  run_simulation_ms(1188);
  const int64_t est_after_drop_kbps = goog_cc.TargetRate().kbps();
  // 绝不能崩溃跌落至最小码率 min_bitrate（150 kbps），而应稳定收敛在约 850~1000 kbps 附近。
  EXPECT_GE(est_after_drop_kbps, 750);
  EXPECT_LE(est_after_drop_kbps, 1050);

  harness.phase_wire_bytes = 0;
  run_simulation_ms(990);
  const double steady_1m_wire_kbps =
      (static_cast<double>(harness.phase_wire_bytes) * 8.0) / 0.990 / 1000.0;
  const double util_1m = steady_1m_wire_kbps / 1000.0;
  RTC_LOG(kInfo) << "[BWE Phase 2] 1000 kbps link -> est="
                 << goog_cc.TargetRate().kbps()
                 << " kbps, wire=" << steady_1m_wire_kbps
                 << " kbps (utilization=" << (util_1m * 100.0) << "%)";
  EXPECT_GE(util_1m, 0.85);
  EXPECT_LE(util_1m, 1.02);

  // 阶段 3：验证丢包 + FlexFEC + RTX 总带宽守恒定律（90ms RTT 下 10% 丢包率），
  // 确保物理链路总发送码率不会超出 target_rate。
  const double loss = 0.10;
  const double fec_ratio = std::clamp(loss * 1.4 * 1.35, 0.05, 0.40) + 0.01;
  const double rtx_ratio = loss * 0.55;
  const double overhead_ratio = 0.030 + fec_ratio + rtx_ratio;
  const DataRate lossy_target = DataRate::KilobitsPerSec(2000);
  const auto lossy_alloc = allocator.Allocate(lossy_target, overhead_ratio);
  const double expected_wire_bps =
      static_cast<double>(lossy_alloc.layers[1].target_bitrate_bps) *
      (1.0 + overhead_ratio);
  EXPECT_NEAR(expected_wire_bps, static_cast<double>(lossy_target.bps()),
              5000.0);
}

// 13. 验证 MoqBweAdapter 按 1.0 倍 BDP（cwnd / RTT）映射目标码率，避免 1.25 倍 Pacing
//     增益导致码率超调，并准确追踪近期滑动窗口丢包率。
TEST(MoqQuicTest, MoqBweBdpAndSlidingLossAccuracy) {
  MoqBweAdapter adapter(DataRate::KilobitsPerSec(150),
                        DataRate::KilobitsPerSec(8000));
  QuicCongestionSnapshot snap;
  snap.timestamp = Timestamp::Millis(5000);
  snap.smoothed_rtt = TimeDelta::Millis(40);
  // 15,000 字节 / 40ms = 375,000 字节/秒 = 精确 3,000 kbps 带宽时延积（BDP）。
  snap.cwnd = DataSize::Bytes(15'000);
  snap.bytes_in_flight = DataSize::Bytes(12'000);
  snap.pacing_rate = DataRate::KilobitsPerSec(3750);  // 1.25 倍突发平滑发送速率
  snap.delivery_rate = DataRate::KilobitsPerSec(2900);
  snap.recent_loss_ratio = 0.08;
  snap.packets_sent = 100'000;
  snap.packets_lost = 80;  // 被全生命周期总包数稀释后的累计丢包率仅为 0.0008，必须忽略！

  const TargetTransferRate rate = adapter.ConvertSnapshot(snap);
  // 即使 pacing_rate 为 3,750 kbps，目标码率也绝不能超过 3,000 kbps（1.0 倍 BDP）！
  EXPECT_LE(rate.target_rate.kbps(), 3000);
  EXPECT_GE(rate.target_rate.kbps(), 2850);
  EXPECT_NEAR(rate.loss_rate_ratio, 0.08, 1e-6);
}

// 14. 验证全部 5 种主流可插拔 QUIC 拥塞控制模块
//     （BBRv1、BBRv2、CUBIC+HyStart++、Copa、NewReno）及热切换状态平滑继承。
TEST(MoqQuicTest, PluggableCongestionControlAllFiveAlgorithmsAndHotSwap) {
  constexpr size_t kMss = 1200;
  const rtc_quic_cc_algo_e algos[] = {
      RTC_QUIC_CC_BBR,     RTC_QUIC_CC_BBR2,    RTC_QUIC_CC_CUBIC,
      RTC_QUIC_CC_COPA,    RTC_QUIC_CC_NEWRENO,
  };

  // 第一部分：对全部 5 种拥塞控制算法分别进行闭环瓶颈链路仿真
  // （3.0 Mbps 瓶颈带宽，30ms 基础 RTT）。
  for (rtc_quic_cc_algo_e algo : algos) {
    auto cc = CreateBuiltinQuicCongestionController(algo, kMss);
    ASSERT_NE(cc, nullptr);
    EXPECT_FALSE(cc->Name().empty());

    int64_t now_us = 1'000'000;
    uint64_t next_pn = 1;
    uint64_t delivered_bytes = 0;
    int64_t delivered_time_us = now_us;
    int64_t first_sent_us = now_us;

    // 模拟在 3.0 Mbps 链路上进行 25 个 RTT 轮次的 BDP 饱和传输（30ms RTT 对应 BDP = 11,250 字节）。
    for (int round = 0; round < 25; ++round) {
      const size_t cwnd = cc->GetCongestionWindowBytes();
      const size_t pkts_in_round = std::clamp<size_t>(cwnd / kMss, 2, 24);
      size_t in_flight = pkts_in_round * kMss;

      std::vector<QuicAckedPacket> acked;
      const int64_t round_send_start = now_us;
      for (size_t i = 0; i < pkts_in_round; ++i) {
        const uint64_t pn = next_pn++;
        cc->OnPacketSent(now_us, pn, kMss, true, i * kMss);
        QuicAckedPacket ap;
        ap.packet_number = pn;
        ap.bytes = kMss;
        ap.sent_time_us = now_us;
        ap.prior_in_flight_bytes = in_flight;
        ap.delivered_bytes_at_send = delivered_bytes;
        ap.delivered_time_us_at_send = delivered_time_us;
        ap.first_sent_time_us_at_send = first_sent_us;
        ap.is_app_limited = false;
        acked.push_back(ap);
        now_us += 3200;  // 1200 字节在 3.0 Mbps 速率下的串行化发送间隔为 3200 微秒
      }

      // 当 cwnd 超过 BDP（11,250 字节）时计算排队时延
      const int64_t excess_bytes =
          (in_flight > 11'250) ? static_cast<int64_t>(in_flight - 11'250) : 0;
      const int64_t queue_delay_us = (excess_bytes * 8'000'000) / 3'000'000;
      const int64_t rtt_us = 30'000 + queue_delay_us;
      now_us = std::max(now_us, round_send_start + rtt_us);

      delivered_bytes += in_flight;
      delivered_time_us = now_us;
      first_sent_us = round_send_start;

      std::vector<QuicLostPacket> lost;
      // 当排队积压超过 24 KB 时模拟浅缓冲区尾部丢包（Tail Drop）
      if (excess_bytes > 24'000) {
        lost.push_back(
            QuicLostPacket{acked.back().packet_number, kMss, acked.back().sent_time_us});
        acked.pop_back();
      }

      QuicRttSample rtt_sample{rtt_us, rtt_us, 30'000, 3000};
      cc->OnCongestionEvent(now_us, in_flight, 0, rtt_sample, acked, lost);
    }

    const int64_t bw_kbps = cc->GetBandwidthEstimateBps() / 1000;
    const int64_t pace_kbps = cc->GetPacingRateBps(30'000) / 1000;
    RTC_LOG(kInfo) << "[QUIC-CC Benchmark] algo=" << cc->Name()
                   << " cwnd=" << cc->GetCongestionWindowBytes()
                   << "B, est_kbps=" << bw_kbps
                   << ", pacing_kbps=" << pace_kbps;
    EXPECT_GE(cc->GetCongestionWindowBytes(), 2 * kMss);
    EXPECT_GT(bw_kbps, 500);
    EXPECT_GT(pace_kbps, 500);
  }

  // 第二部分：验证无缝热切换状态迁移链：
  // BBRv1 -> BBRv2 -> CUBIC -> Copa -> NewReno -> BBRv1（循环平滑交接）
  auto active_cc = CreateBuiltinQuicCongestionController(RTC_QUIC_CC_BBR, kMss);
  QuicCcMigrationState seed;
  seed.cwnd_bytes = 24'000;
  seed.ssthresh_bytes = 30'000;
  seed.bandwidth_estimate_bps = 4'800'000;
  seed.pacing_rate_bps = 4'800'000;
  seed.min_rtt_us = 40'000;
  seed.smoothed_rtt_us = 42'000;
  active_cc->ImportMigrationState(seed, 2'000'000);

  const rtc_quic_cc_algo_e swap_chain[] = {
      RTC_QUIC_CC_BBR2,    RTC_QUIC_CC_CUBIC, RTC_QUIC_CC_COPA,
      RTC_QUIC_CC_NEWRENO, RTC_QUIC_CC_BBR,
  };
  int64_t t_us = 2'100'000;
  for (rtc_quic_cc_algo_e next_algo : swap_chain) {
    const QuicCcMigrationState exported = active_cc->ExportMigrationState();
    EXPECT_GE(exported.cwnd_bytes, 4 * kMss);
    EXPECT_GT(exported.bandwidth_estimate_bps, 2'000'000);

    auto next_cc = CreateBuiltinQuicCongestionController(next_algo, kMss);
    ASSERT_NE(next_cc, nullptr);
    next_cc->ImportMigrationState(exported, t_us);
    EXPECT_EQ(next_cc->GetCongestionWindowBytes(), exported.cwnd_bytes);
    active_cc = std::move(next_cc);
    t_us += 50'000;
  }
}

// 17. 验证 RFC 3309 第 3 节标准 SCTP Castagnoli CRC-32c 测试向量
TEST(SctpDataChannelTest, Rfc3309Crc32cVectorsAndCorruptionCheck) {
  const std::vector<uint8_t> zeros32(32, 0x00);
  EXPECT_EQ(ComputeSctpCrc32c(zeros32), 0x8A9136AAu);

  const std::vector<uint8_t> ones32(32, 0xFF);
  EXPECT_EQ(ComputeSctpCrc32c(ones32), 0x62A8AB43u);

  std::vector<uint8_t> inc32(32, 0);
  for (size_t i = 0; i < 32; ++i) {
    inc32[i] = static_cast<uint8_t>(i);
  }
  EXPECT_EQ(ComputeSctpCrc32c(inc32), 0x46DD794Eu);
}

// 18. 验证 RFC 8841 WebRTC DataChannel SDP 解析、序列化与 RFC 3264 m= 段保序
TEST(SctpDataChannelTest, SdpApplicationNegotiationAndMsectionOrder) {
  // 模拟浏览器先调用 createDataChannel 再 addTransceiver('video') 生成的 Offer
  const char* app_first_offer =
      "v=0\r\n"
      "o=- 12345 2 IN IP4 127.0.0.1\r\n"
      "s=-\r\n"
      "t=0 0\r\n"
      "a=group:BUNDLE dc_mid vid_mid\r\n"
      "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
      "c=IN IP4 0.0.0.0\r\n"
      "a=ice-ufrag:ufrag123\r\n"
      "a=ice-pwd:password1234567890123456\r\n"
      "a=fingerprint:sha-256 AA:BB:CC:DD\r\n"
      "a=setup:actpass\r\n"
      "a=mid:dc_mid\r\n"
      "a=sctp-port:5002\r\n"
      "a=max-message-size:131072\r\n"
      "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
      "c=IN IP4 0.0.0.0\r\n"
      "a=mid:vid_mid\r\n"
      "a=sendrecv\r\n"
      "a=rtpmap:96 H264/90000\r\n"
      "a=fmtp:96 packetization-mode=1;profile-level-id=42e01f\r\n";

  const auto parsed =
      PureVideoSdpDescription::Parse(app_first_offer, VideoCodec::kH264);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_TRUE(parsed->data_m_section.has_value());
  EXPECT_EQ(parsed->data_m_section->mid, "dc_mid");
  EXPECT_EQ(parsed->data_m_section->sctp_port, 5002);
  EXPECT_EQ(parsed->data_m_section->max_message_size, 131072u);
  ASSERT_EQ(parsed->m_section_order.size(), 2u);
  EXPECT_EQ(parsed->m_section_order[0], SdpMediaKind::kApplication);
  EXPECT_EQ(parsed->m_section_order[1], SdpMediaKind::kVideo);

  const std::string serialized = parsed->Serialize();
  const size_t app_pos = serialized.find("m=application ");
  const size_t vid_pos = serialized.find("m=video ");
  ASSERT_NE(app_pos, std::string::npos);
  ASSERT_NE(vid_pos, std::string::npos);
  EXPECT_LT(app_pos, vid_pos);
  EXPECT_NE(serialized.find("a=group:BUNDLE dc_mid vid_mid"),
            std::string::npos);

  // 验证纯 DataChannel（无 m=video）SDP Offer 的解析兼容性
  const char* dc_only_offer =
      "v=0\r\n"
      "o=- 999 2 IN IP4 127.0.0.1\r\n"
      "s=-\r\n"
      "t=0 0\r\n"
      "m=application 9 DTLS/SCTP 5000\r\n"
      "a=ice-ufrag:dc_u\r\n"
      "a=ice-pwd:dc_pwd_1234567890123456\r\n"
      "a=fingerprint:sha-256 11:22:33:44\r\n"
      "a=mid:0\r\n"
      "a=sctpmap:5000 webrtc-datachannel 1024\r\n";
  const auto dc_only = PureVideoSdpDescription::Parse(dc_only_offer);
  ASSERT_TRUE(dc_only.has_value());
  EXPECT_TRUE(dc_only->video_m_sections.empty());
  ASSERT_TRUE(dc_only->data_m_section.has_value());
  EXPECT_EQ(dc_only->data_m_section->sctp_port, 5000);
}

// 19. 验证完整 SCTP 四次握手、DCEP 通道建立、32KB 大包分片丢包重传与 PR-SCTP FORWARD-TSN
TEST(SctpDataChannelTest, DcepFragmentationLossRecoveryAndPrSctpForwardTsn) {
  SimulatedClock sim_clock(Timestamp::Micros(1'000'000));

  struct SctpHarness final : public SctpDataChannelObserver {
    SctpHarness* peer = nullptr;
    SctpDataChannelManager* mgr = nullptr;
    SimulatedClock* clock = nullptr;
    bool drop_next_tx = false;
    std::deque<std::vector<uint8_t>> wire_queue;

    struct RxMsg {
      int cid = -1;
      bool is_binary = false;
      std::vector<uint8_t> data;
    };
    std::vector<std::pair<int, rtc_data_channel_state_e>> states;
    std::vector<RxMsg> messages;

    bool SendSctpPacketOverDtls(ArrayView<const uint8_t> packet) override {
      if (drop_next_tx) {
        drop_next_tx = false;
        return true;
      }
      wire_queue.emplace_back(packet.begin(), packet.end());
      return true;
    }
    void OnSctpDataChannelState(int channel_id,
                                const std::string& /*label*/,
                                rtc_data_channel_state_e state) override {
      states.emplace_back(channel_id, state);
    }
    void OnSctpDataChannelMessage(int channel_id,
                                  bool is_binary,
                                  std::vector<uint8_t> payload) override {
      messages.push_back(RxMsg{channel_id, is_binary, std::move(payload)});
    }
  };

  SctpHarness ha;
  SctpHarness hb;
  SctpDataChannelManager sctp_a(&sim_clock, &ha);
  SctpDataChannelManager sctp_b(&sim_clock, &hb);
  ha.peer = &hb;
  ha.mgr = &sctp_a;
  ha.clock = &sim_clock;
  hb.peer = &ha;
  hb.mgr = &sctp_b;
  hb.clock = &sim_clock;

  auto pump_wire = [&]() {
    bool progressed = true;
    while (progressed) {
      progressed = false;
      while (!ha.wire_queue.empty()) {
        auto pkt = std::move(ha.wire_queue.front());
        ha.wire_queue.pop_front();
        sctp_b.OnInboundSctpPacket(pkt, sim_clock.CurrentTime());
        progressed = true;
      }
      while (!hb.wire_queue.empty()) {
        auto pkt = std::move(hb.wire_queue.front());
        hb.wire_queue.pop_front();
        sctp_a.OnInboundSctpPacket(pkt, sim_clock.CurrentTime());
        progressed = true;
      }
    }
  };

  // 在握手前预先创建可靠有序通道与 PR-SCTP 限次重传（max_retransmits=0）通道
  DataChannelConfig reliable_cfg;
  reliable_cfg.label = "ctrl_reliable";
  reliable_cfg.ordered = true;
  const int ch_rel = sctp_a.CreateDataChannel(reliable_cfg);
  ASSERT_GE(ch_rel, 0);

  DataChannelConfig pr_cfg;
  pr_cfg.label = "telemetry_pr";
  pr_cfg.ordered = true;
  pr_cfg.max_retransmits = 0;
  const int ch_pr = sctp_a.CreateDataChannel(pr_cfg);
  ASSERT_GE(ch_pr, 0);

  // 预入队空文本消息（验证 RFC 8831 PPID 56 空负载编码）
  EXPECT_EQ(sctp_a.SendData(ch_rel, ArrayView<const uint8_t>(), false), RTC_OK);

  sctp_a.ConfigureAndStart(DtlsRole::kClient, 5000, 5000);
  sctp_b.ConfigureAndStart(DtlsRole::kServer, 5000, 5000);
  pump_wire();

  ASSERT_TRUE(sctp_a.IsAssociationEstablished());
  ASSERT_TRUE(sctp_b.IsAssociationEstablished());
  ASSERT_EQ(hb.messages.size(), 1u);
  EXPECT_FALSE(hb.messages[0].is_binary);
  EXPECT_TRUE(hb.messages[0].data.empty());

  // 测试 32 KB 多分片大二进制报文在丢包触发 T3 重传下的比特级精确恢复
  std::vector<uint8_t> big_blob(32 * 1024, 0);
  for (size_t i = 0; i < big_blob.size(); ++i) {
    big_blob[i] = static_cast<uint8_t>((i * 37 + 13) & 0xFFu);
  }
  ha.drop_next_tx = true;  // 故意丢弃首个分片包
  ASSERT_EQ(sctp_a.SendData(ch_rel, big_blob, true), RTC_OK);
  pump_wire();
  for (int step = 0; step < 30 && hb.messages.size() < 2; ++step) {
    sim_clock.AdvanceTime(TimeDelta::Millis(30));
    sctp_a.OnPeriodicTick(sim_clock.CurrentTime());
    sctp_b.OnPeriodicTick(sim_clock.CurrentTime());
    pump_wire();
  }
  ASSERT_EQ(hb.messages.size(), 2u);
  EXPECT_TRUE(hb.messages[1].is_binary);
  EXPECT_EQ(hb.messages[1].data, big_blob);

  // 测试 PR-SCTP（max_retransmits=0）：第一条报文丢失后通过 FORWARD-TSN 自动跳过，不阻塞第二条报文
  const std::string msg_lost = "stale_telemetry_1";
  const std::string msg_fresh = "fresh_telemetry_2";
  ha.drop_next_tx = true;
  ASSERT_EQ(
      sctp_a.SendData(
          ch_pr,
          MakeArrayView(reinterpret_cast<const uint8_t*>(msg_lost.data()),
                        msg_lost.size()),
          false),
      RTC_OK);
  ASSERT_EQ(
      sctp_a.SendData(
          ch_pr,
          MakeArrayView(reinterpret_cast<const uint8_t*>(msg_fresh.data()),
                        msg_fresh.size()),
          false),
      RTC_OK);
  pump_wire();
  for (int step = 0; step < 20 && hb.messages.size() < 3; ++step) {
    sim_clock.AdvanceTime(TimeDelta::Millis(40));
    sctp_a.OnPeriodicTick(sim_clock.CurrentTime());
    sctp_b.OnPeriodicTick(sim_clock.CurrentTime());
    pump_wire();
  }
  ASSERT_EQ(hb.messages.size(), 3u);
  const std::string delivered_str(hb.messages[2].data.begin(),
                                  hb.messages[2].data.end());
  EXPECT_EQ(delivered_str, msg_fresh);

  // 测试 RFC 6525 RE-CONFIG 流关闭通知
  EXPECT_EQ(sctp_a.CloseDataChannel(ch_rel), RTC_OK);
  pump_wire();
  bool saw_remote_close = false;
  for (const auto& [cid, st] : hb.states) {
    (void)cid;
    if (st == RTC_DATA_CHANNEL_CLOSED) {
      saw_remote_close = true;
    }
  }
  EXPECT_TRUE(saw_remote_close);
}

// 20. 验证 IETF MoQ 数据对象封包器在逐字节流式分块到达与零字节负载下的解包准确性
TEST(MoqDataChannelTest, MoqDataPackagerStreamingUnpackAndZeroLengthPayload) {
  MoqDataObject obj_empty;
  obj_empty.object_id = 0;
  obj_empty.sender_peer_id = "drone_01";
  obj_empty.label = "heartbeat";
  obj_empty.is_binary = false;
  obj_empty.ordered = true;

  MoqDataObject obj_bin;
  obj_bin.object_id = 1;
  obj_bin.sender_peer_id = "drone_01";
  obj_bin.label = "lidar_scan";
  obj_bin.protocol = "raw_v1";
  obj_bin.timestamp_us = 987654321ULL;
  obj_bin.is_binary = true;
  obj_bin.ordered = false;
  obj_bin.payload.resize(4096);
  for (size_t i = 0; i < obj_bin.payload.size(); ++i) {
    obj_bin.payload[i] = static_cast<uint8_t>((i * 19) & 0xFFu);
  }

  std::vector<uint8_t> stream_bytes = MoqDataPackager::PackObject(obj_empty);
  const auto bin_bytes = MoqDataPackager::PackObject(obj_bin);
  stream_bytes.insert(stream_bytes.end(), bin_bytes.begin(), bin_bytes.end());

  std::vector<uint8_t> rx_buf;
  std::vector<MoqDataObject> decoded;
  for (size_t off = 0; off < stream_bytes.size(); off += 137) {
    const size_t chunk = std::min<size_t>(137, stream_bytes.size() - off);
    rx_buf.insert(rx_buf.end(), stream_bytes.begin() + off,
                  stream_bytes.begin() + off + chunk);
    while (!rx_buf.empty()) {
      size_t consumed = 0;
      auto parsed = MoqDataPackager::UnpackObject(rx_buf, &consumed);
      if (!parsed.has_value()) {
        break;
      }
      decoded.push_back(std::move(*parsed));
      rx_buf.erase(rx_buf.begin(),
                   rx_buf.begin() + static_cast<ptrdiff_t>(consumed));
    }
  }

  ASSERT_EQ(decoded.size(), 2u);
  EXPECT_EQ(decoded[0].sender_peer_id, "drone_01");
  EXPECT_EQ(decoded[0].label, "heartbeat");
  EXPECT_FALSE(decoded[0].is_binary);
  EXPECT_TRUE(decoded[0].payload.empty());

  EXPECT_EQ(decoded[1].object_id, 1u);
  EXPECT_EQ(decoded[1].label, "lidar_scan");
  EXPECT_EQ(decoded[1].protocol, "raw_v1");
  EXPECT_TRUE(decoded[1].is_binary);
  EXPECT_FALSE(decoded[1].ordered);
  EXPECT_EQ(decoded[1].payload, obj_bin.payload);
}

}  // namespace
}  // namespace rtc
