#ifndef SRC_MOQ_MOQ_TRANSPORT_H_
#define SRC_MOQ_MOQ_TRANSPORT_H_

// 原生 IETF Media over QUIC（draft-ietf-moq-transport-17 与低开销容器 LOC）实现：
//   - QuicVarInt：底层 QUIC/HTTP3 2-bit 变长整数编解码（RFC 9000 第 16 节）
//   - MoqtVarInt：MOQT draft-17 前导 1 比特计数变长整数（vi64，第 1.4.1 节）
//   - MoqtKeyValuePair / MoqtMessageParameters / MoqtTrackNamespace：结构化元组与参数编解码
//   - 控制与数据封装结构（MoqControlMessage / MoqSubgroupHeader / MoqtSubgroupObject / MoqtObjectDatagram）：
//     严格遵循 draft-17 第 9 章与第 10 章的控制流、双向请求流、子组数据流与对象数据报
//   - MoqRelayBackend：同时支持原生 QUIC（moqt://，ALPN "moqt-17"）与
//     WebTransport over HTTP/3（https:// 或 wt://，ALPN "h3"）的双栖会话后端

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "api/array_view.h"
#include "api/session_backend_interface.h"
#include "modules/video_coding/video_coding_module.h"
#include "rtc_base/pending_task_safety_flag.h"
#include "rtc_base/sequence_checker.h"
#include "rtc_base/task_queue.h"
#include "rtc_base/time_utils.h"

namespace rtc {

// IETF draft-ietf-moq-transport-17 标准 ALPN 协议标识。
inline constexpr const char* kMoqtDraft17Alpn = "moqt-17";
inline constexpr const char* kHttp3Alpn = "h3";

// RFC 9000 第 16 节 QUIC 变长整数编解码（供 QUIC v1 与 HTTP/3 / WebTransport 层使用）。
class QuicVarInt {
 public:
  static void Append(uint64_t val, std::vector<uint8_t>* dst);
  static bool Read(ArrayView<const uint8_t> data,
                   size_t* offset,
                   uint64_t* out_val);
  static void AppendString(std::string_view str, std::vector<uint8_t>* dst);
  static bool ReadString(ArrayView<const uint8_t> data,
                         size_t* offset,
                         std::string* out_str);
};

// draft-ietf-moq-transport-17 第 1.4.1 节定义的 vi64 变长整数编解码器：
// 使用首字节前导 1 比特个数表示总字节长度（1/2/3/4/5/6/8/9 字节，最高支持完整 64 位无符号整数；
// 0xFC/0xFD 为非法编码点，收到时必须以 PROTOCOL_VIOLATION 终止会话）。
class MoqtVarInt {
 public:
  static void Append(uint64_t val, std::vector<uint8_t>* dst);
  static bool Read(ArrayView<const uint8_t> data,
                   size_t* offset,
                   uint64_t* out_val,
                   bool* out_invalid_codepoint = nullptr);
  static void AppendBytes(ArrayView<const uint8_t> bytes,
                          std::vector<uint8_t>* dst);
  static bool ReadBytes(ArrayView<const uint8_t> data,
                        size_t* offset,
                        std::vector<uint8_t>* out_bytes,
                        size_t max_len = 65535);
  static void AppendString(std::string_view str, std::vector<uint8_t>* dst);
  static bool ReadString(ArrayView<const uint8_t> data,
                         size_t* offset,
                         std::string* out_str,
                         size_t max_len = 65535);
};

// draft-17 第 1.4.2 节对象位置结构（Group ID + Object ID）。
struct MoqtLocation {
  uint64_t group = 0;
  uint64_t object = 0;

  bool operator==(const MoqtLocation& o) const {
    return group == o.group && object == o.object;
  }
  bool operator<(const MoqtLocation& o) const {
    return group < o.group || (group == o.group && object < o.object);
  }
};

// draft-17 第 1.4.3 节 Key-Value-Pair 结构（用于 Setup Options 与 Track/Object Properties）：
// 偶数 Type 编码单个 vi64 整数，奇数 Type 编码 Length(vi64) + 字节序列，Type 采用升序差分编码。
struct MoqtKeyValuePair {
  uint64_t type = 0;
  uint64_t int_value = 0;
  std::vector<uint8_t> bytes_value;

  static MoqtKeyValuePair MakeVarInt(uint64_t even_type, uint64_t val);
  static MoqtKeyValuePair MakeBytes(uint64_t odd_type,
                                    ArrayView<const uint8_t> bytes);
  static MoqtKeyValuePair MakeString(uint64_t odd_type, std::string_view str);

  static bool EncodeList(const std::vector<MoqtKeyValuePair>& items,
                         std::vector<uint8_t>* out);
  static bool DecodeList(ArrayView<const uint8_t> data,
                         size_t* offset,
                         std::vector<MoqtKeyValuePair>* out_items);
};

// draft-17 第 9.4.1 节 SETUP 选项类型与第 14.4 节 Track/Object 属性类型常量。
inline constexpr uint64_t kMoqtSetupOptionPath = 0x01;
inline constexpr uint64_t kMoqtSetupOptionAuthToken = 0x03;
inline constexpr uint64_t kMoqtSetupOptionMaxAuthTokenCacheSize = 0x04;
inline constexpr uint64_t kMoqtSetupOptionAuthority = 0x05;
inline constexpr uint64_t kMoqtSetupOptionImplementation = 0x07;

inline constexpr uint64_t kMoqtPropDeliveryTimeout = 0x02;
inline constexpr uint64_t kMoqtPropMaxCacheDuration = 0x04;
inline constexpr uint64_t kMoqtPropDefaultPublisherPriority = 0x0E;
inline constexpr uint64_t kMoqtPropDefaultPublisherGroupOrder = 0x22;
inline constexpr uint64_t kMoqtPropDynamicGroups = 0x30;

// draft-17 第 10.4.4 节 FETCH_HEADER 单向数据流类型标识。
inline constexpr uint64_t kMoqtStreamTypeFetchHeader = 0x05;

// draft-17 第 14.5 节会话级与请求级错误码常量。
inline constexpr uint64_t kMoqtErrNoError = 0x00;
inline constexpr uint64_t kMoqtErrInternalError = 0x01;
inline constexpr uint64_t kMoqtErrUnauthorized = 0x02;
inline constexpr uint64_t kMoqtErrProtocolViolation = 0x03;
inline constexpr uint64_t kMoqtErrInvalidRequestId = 0x04;
inline constexpr uint64_t kMoqtErrDuplicateTrackAlias = 0x05;
inline constexpr uint64_t kMoqtErrKeyValueFormattingError = 0x06;
inline constexpr uint64_t kMoqtErrInvalidRequiredRequestId = 0x07;
inline constexpr uint64_t kMoqtErrInvalidPath = 0x08;
inline constexpr uint64_t kMoqtErrInvalidAuthority = 0x19;

inline constexpr uint64_t kMoqtReqErrInternal = 0x00;
inline constexpr uint64_t kMoqtReqErrUnauthorized = 0x01;
inline constexpr uint64_t kMoqtReqErrTimeout = 0x02;
inline constexpr uint64_t kMoqtReqErrNotSupported = 0x03;
inline constexpr uint64_t kMoqtReqErrDoesNotExist = 0x10;
inline constexpr uint64_t kMoqtReqErrInvalidRange = 0x11;
inline constexpr uint64_t kMoqtReqErrDuplicateSubscription = 0x19;
inline constexpr uint64_t kMoqtReqErrPrefixOverlap = 0x30;

// draft-17 第 2.4.1 节结构化轨道命名空间（0..32 个非空字节字段元组）。
struct MoqtTrackNamespace {
  std::vector<std::string> fields;

  bool empty() const { return fields.empty(); }
  bool operator==(const MoqtTrackNamespace& o) const {
    return fields == o.fields;
  }
  bool operator!=(const MoqtTrackNamespace& o) const {
    return fields != o.fields;
  }
  bool operator<(const MoqtTrackNamespace& o) const {
    return fields < o.fields;
  }

  bool Encode(std::vector<uint8_t>* out) const;
  static bool Decode(ArrayView<const uint8_t> data,
                     size_t* offset,
                     MoqtTrackNamespace* out);

  bool StartsWith(const MoqtTrackNamespace& prefix) const;
  MoqtTrackNamespace SuffixAfter(const MoqtTrackNamespace& prefix) const;
  MoqtTrackNamespace WithSuffix(const MoqtTrackNamespace& suffix) const;

  std::string ToSlashString() const;
  static MoqtTrackNamespace FromSlashString(std::string_view text);
  static MoqtTrackNamespace MakeRoomPrefix(std::string_view room_id);
  static MoqtTrackNamespace MakePeerNamespace(std::string_view room_id,
                                              std::string_view peer_id);
};

// draft-17 第 5.1.2 节订阅过滤器类型与结构。
enum class MoqFilterType : uint64_t {
  kNextGroupStart = 0x01,
  kLargestObject = 0x02,
  kAbsoluteStart = 0x03,
  kAbsoluteRange = 0x04,
  // 兼容旧枚举别名：
  kLatestGroup = 0x01,
  kLatestObject = 0x02,
};

struct MoqtSubscriptionFilter {
  MoqFilterType type = MoqFilterType::kNextGroupStart;
  MoqtLocation start_location{};
  uint64_t end_group_delta = 0;

  std::vector<uint8_t> Encode() const;
  static std::optional<MoqtSubscriptionFilter> Decode(
      ArrayView<const uint8_t> data);
};

// draft-17 第 9.3 节与第 14.3 节控制消息参数集合（升序 Type Delta 编解码）。
struct MoqtMessageParameters {
  std::optional<uint64_t> delivery_timeout_ms;              // 参数 0x02（vi64 整数）
  std::vector<std::vector<uint8_t>> authorization_tokens;   // 参数 0x03（长度前缀字节串）
  std::optional<uint64_t> rendezvous_timeout_ms;            // 参数 0x04（vi64 整数）
  std::optional<uint64_t> expires_ms;                       // 参数 0x08（vi64 整数）
  std::optional<MoqtLocation> largest_object;               // 参数 0x09（Location 位置对）
  std::optional<uint8_t> forward;                           // 参数 0x10（单字节 0 或 1）
  std::optional<uint8_t> subscriber_priority;               // 参数 0x20（单字节优先级）
  std::optional<MoqtSubscriptionFilter> subscription_filter; // 参数 0x21（长度前缀过滤器）
  std::optional<uint8_t> group_order;                       // 参数 0x22（单字节组序 1 或 2）
  std::optional<uint64_t> new_group_request;                // 参数 0x32（vi64 新组请求）

  bool Encode(std::vector<uint8_t>* out) const;
  static bool Decode(ArrayView<const uint8_t> data,
                     size_t* offset,
                     MoqtMessageParameters* out);
};

// draft-17 第 9 章表 4 定义的全部标准控制与请求消息类型码。
enum class MoqControlMessageType : uint64_t {
  kRequestUpdate = 0x02,
  kSubscribe = 0x03,
  kSubscribeOk = 0x04,
  kRequestError = 0x05,
  kPublishNamespace = 0x06,
  kRequestOk = 0x07,
  kNamespace = 0x08,
  kPublishDone = 0x0B,
  kTrackStatus = 0x0D,
  kNamespaceDone = 0x0E,
  kPublishBlocked = 0x0F,
  kGoaway = 0x10,
  kSubscribeNamespace = 0x11,
  kFetch = 0x16,
  kFetchOk = 0x18,
  kPublish = 0x1D,
  kPublishOk = 0x1E,
  kSetup = 0x2F00,
};

// draft-17 第 9 章统一控制与请求消息编解码器：
// 外层帧格式严格为 Message Type (vi64) + Message Length (uint16_be) + Message Payload (..)。
struct MoqControlMessage {
  MoqControlMessageType type = MoqControlMessageType::kSetup;

  // 请求类消息通用字段（SUBSCRIBE / PUBLISH / PUBLISH_NAMESPACE / SUBSCRIBE_NAMESPACE / REQUEST_UPDATE / TRACK_STATUS）。
  uint64_t request_id = 0;
  uint64_t required_request_id_delta = 0;

  // 轨道标识与别名字段。
  MoqtTrackNamespace track_namespace;
  std::string track_name;
  uint64_t track_alias = 0;

  // SUBSCRIBE_NAMESPACE 选项字段（0x00=PUBLISH, 0x01=NAMESPACE, 0x02=BOTH）。
  uint64_t subscribe_options = 0x01;

  // SETUP 选项、消息参数与轨道属性。
  std::vector<MoqtKeyValuePair> setup_options;
  MoqtMessageParameters parameters;
  std::vector<MoqtKeyValuePair> track_properties;

  // REQUEST_ERROR / PUBLISH_DONE / GOAWAY 字段。
  uint64_t error_or_status_code = 0;
  uint64_t retry_interval_or_stream_count = 0;
  std::string reason_phrase;
  std::string new_session_uri;
  uint64_t goaway_timeout_ms = 0;

  // FETCH (0x16) / FETCH_OK (0x18) 字段（draft-17 第 9.14 / 9.15 节）。
  uint64_t fetch_type = 0x01;  // 0x01=Standalone, 0x02=RelativeJoining, 0x03=AbsoluteJoining
  MoqtLocation fetch_start_location{};
  MoqtLocation fetch_end_location{};
  uint64_t joining_request_id = 0;
  uint64_t joining_start = 0;
  bool end_of_track = false;
  MoqtLocation end_location{};

  std::vector<uint8_t> Encode() const;
  static std::optional<MoqControlMessage> Decode(
      ArrayView<const uint8_t> data,
      size_t* consumed,
      bool* out_protocol_violation = nullptr,
      uint64_t* out_error_code = nullptr);
};

// draft-17 第 10.4.2 节 SUBGROUP_HEADER 子组数据流头部（Type = 0x10..0x15 / 0x18..0x1D / 0x30..0x35 / 0x38..0x3D）。
struct MoqSubgroupHeader {
  uint64_t track_alias = 0;
  uint64_t group_id = 0;
  uint64_t subgroup_id = 0;
  uint8_t publisher_priority = 64;
  bool has_properties = false;
  bool subgroup_id_from_first_object = false;
  bool end_of_group = false;
  bool default_priority = false;

  std::vector<uint8_t> Encode() const;
  static std::optional<MoqSubgroupHeader> Decode(
      ArrayView<const uint8_t> data,
      size_t* consumed,
      bool* out_protocol_violation = nullptr);
};

// draft-17 第 10.2.1.1 节 Object Status 枚举。
enum class MoqtObjectStatus : uint64_t {
  kNormal = 0x00,
  kEndOfGroup = 0x03,
  kEndOfTrack = 0x04,
};

// draft-17 第 10.4.2 节图 25 子组流内单个对象记录（支持首对象与后续对象 Object ID Delta 差分编解码）。
struct MoqtSubgroupObject {
  uint64_t object_id = 0;
  std::vector<MoqtKeyValuePair> properties;
  MoqtObjectStatus status = MoqtObjectStatus::kNormal;
  std::vector<uint8_t> payload;

  std::vector<uint8_t> Encode(std::optional<uint64_t> prev_object_id,
                              bool header_has_properties = false) const;
  static std::optional<MoqtSubgroupObject> Decode(
      ArrayView<const uint8_t> data,
      std::optional<uint64_t> prev_object_id,
      bool header_has_properties,
      size_t* consumed,
      bool* out_protocol_violation = nullptr,
      uint64_t* out_error_code = nullptr);
};

// draft-17 第 10.3.1 节图 23 OBJECT_DATAGRAM（用于低延迟不可靠对象数据报传输）。
struct MoqtObjectDatagram {
  uint64_t track_alias = 0;
  uint64_t group_id = 0;
  uint64_t object_id = 0;
  uint8_t publisher_priority = 64;
  bool end_of_group = false;
  bool default_priority = false;
  std::vector<MoqtKeyValuePair> properties;
  MoqtObjectStatus status = MoqtObjectStatus::kNormal;
  std::vector<uint8_t> payload;

  std::vector<uint8_t> Encode() const;
  static std::optional<MoqtObjectDatagram> Decode(
      ArrayView<const uint8_t> data,
      bool* out_protocol_violation = nullptr,
      uint64_t* out_error_code = nullptr);
};

// MoQ 数据轨道固定轨道别名约定（与视频低清层=1、高清层=2 隔离解复用）。
inline constexpr uint64_t kMoqUpstreamDataTrackAlias = 3;
inline constexpr uint64_t kMoqDownstreamDataTrackAlias = 50;

// IETF MoQ 通用数据通道对象容器（承载二进制或 UTF-8 消息及通道元数据）。
struct MoqDataObject {
  uint64_t object_id = 0;
  std::string sender_peer_id;
  std::string label;
  std::string protocol;
  uint64_t timestamp_us = 0;
  bool is_binary = true;
  bool ordered = true;
  bool is_close = false;
  std::vector<uint8_t> payload;
};

class MoqDataPackager {
 public:
  static std::vector<uint8_t> PackObject(const MoqDataObject& obj);
  static std::optional<MoqDataObject> UnpackObject(
      ArrayView<const uint8_t> data,
      size_t* consumed);
};

class LocFramePackager {
 public:
  static std::vector<uint8_t> PackPayload(const EncodedVideoFrame& frame);
  static std::optional<EncodedVideoFrame> UnpackPayload(
      ArrayView<const uint8_t> payload);

  // 便捷封装：将 LOC 负载直接打包进 draft-17 MoqtSubgroupObject 记录。
  static std::vector<uint8_t> PackObject(
      uint64_t object_id,
      const EncodedVideoFrame& frame,
      std::optional<uint64_t> prev_object_id = std::nullopt);
  static std::optional<EncodedVideoFrame> UnpackObject(
      ArrayView<const uint8_t> data,
      size_t* consumed,
      uint64_t* out_object_id,
      std::optional<uint64_t> prev_object_id = std::nullopt);
};

class MoqBweAdapter {
 public:
  MoqBweAdapter(DataRate min_bitrate, DataRate max_bitrate);

  TargetTransferRate ConvertSnapshot(const QuicCongestionSnapshot& snap) const;

 private:
  DataRate min_bitrate_;
  DataRate max_bitrate_;
  mutable DataRate app_limited_probe_rate_ = DataRate::Zero();
  mutable Timestamp last_probe_step_ = Timestamp::MinusInfinity();
};

// 解析后的 MoQ 连接端点信息（自动区分原生 QUIC moqt:// 与 WebTransport https:// / wt://）。
struct ParsedMoqUrl {
  std::string scheme = "moqt";
  std::string host = "127.0.0.1";
  uint16_t port = 4433;
  std::string authority = "127.0.0.1:4433";
  std::string path = "/moq";
  bool use_webtransport = false;
};

class MoqRelayBackend final : public ISessionBackend,
                              public IMoqQuicEngineObserver {
 public:
  MoqRelayBackend(Clock* clock,
                  SdkTaskQueues* queues,
                  const EngineConfig& config,
                  ISessionBackendObserver* observer,
                  std::shared_ptr<IMoqQuicEngine> quic_engine = nullptr);
  ~MoqRelayBackend() override;

  static ParsedMoqUrl ParseMoqUrl(std::string_view url);

  int StartSession(const std::string& room_id,
                   const std::string& local_peer_id) override;
  void StopSession() override;
  int SendEncodedFrame(EncodedVideoFrame frame) override;
  void SetLayerActive(SpatialLayer layer, bool active) override;
  int SubscribeRemoteTrack(const std::string& track_id,
                           SpatialLayer preferred_layer) override;
  int SwitchSubscribedLayer(const std::string& track_id,
                            SpatialLayer preferred_layer) override;
  int UnsubscribeRemoteTrack(const std::string& track_id) override;
  int RequestRemoteKeyFrame(const std::string& track_id) override;
  int CreateDataChannel(const DataChannelConfig& config) override;
  int SendData(int channel_id,
               ArrayView<const uint8_t> payload,
               bool is_binary) override;
  int CloseDataChannel(int channel_id) override;
  int SetQuicCongestionControl(rtc_quic_cc_algo_e algo) override;
  int SetCustomQuicCongestionController(
      std::shared_ptr<IQuicCongestionControllerFactory> factory) override;

  void OnQuicConnected() override;
  void OnQuicDisconnected(int error_code) override;
  void OnStreamOpened(uint64_t stream_id, bool unidirectional) override;
  void OnStreamData(uint64_t stream_id,
                    ArrayView<const uint8_t> data,
                    bool fin) override;
  void OnStreamReset(uint64_t stream_id, uint64_t app_error_code) override;
  void OnStreamStopSending(uint64_t stream_id,
                           uint64_t app_error_code) override;
  void OnDatagramReceived(ArrayView<const uint8_t> data) override;

 private:
  struct OutboundSubgroupStream {
    uint64_t stream_id = 0;
    std::optional<uint64_t> prev_object_id;
  };

  struct ActiveOutboundGroup {
    uint64_t group_id = 0;
    uint64_t next_object_id = 0;
    Timestamp started_at = Timestamp::MinusInfinity();
    std::map<uint8_t, OutboundSubgroupStream> subgroup_streams;
  };

  struct InboundUniStreamState {
    enum class Kind : uint8_t {
      kUnknown,
      kControl,
      kSubgroupData,
      kIgnoredFetch,
    };
    Kind kind = Kind::kUnknown;
    MoqSubgroupHeader header;
    std::optional<uint64_t> prev_object_id;
    std::vector<uint8_t> buffer;
  };

  enum class OutboundRequestKind : uint8_t {
    kSubscribeNamespace,
    kPublishVideoNamespace,
    kPublishDataNamespace,
    kSubscribeData,
    kSubscribeVideoLow,
    kSubscribeVideoHigh,
    kRequestUpdate,
  };

  struct OutboundBidiRequestState {
    OutboundRequestKind kind = OutboundRequestKind::kSubscribeNamespace;
    uint64_t stream_id = 0;
    uint64_t request_id = 0;
    std::string target_track_id;
    std::string data_label;
    bool ok_received = false;
    std::vector<uint8_t> rx_buf;
  };

  struct InboundBidiRequestState {
    bool initial_parsed = false;
    uint64_t initial_request_id = 0;
    MoqControlMessageType initial_type = MoqControlMessageType::kSubscribe;
    MoqtTrackNamespace ns;
    std::string track_name;
    std::optional<uint64_t> published_track_alias;
    std::vector<uint8_t> rx_buf;
  };

  struct SubscribedTrackContext {
    std::string track_id;
    MoqtTrackNamespace remote_namespace;
    SpatialLayer preferred_layer = SpatialLayer::kHigh;
    SpatialLayer active_subscribed_layer = SpatialLayer::kHigh;
    uint64_t low_req_stream_id = 0;
    uint64_t high_req_stream_id = 0;
    std::optional<uint64_t> low_track_alias;
    std::optional<uint64_t> high_track_alias;
    uint64_t largest_group_seen = 0;
    bool has_received_group = false;
    uint64_t min_valid_group_id[2]{0, 0};
    std::optional<uint64_t> last_group_id_seen_per_layer[2];
    std::optional<int64_t> last_seen_frame_id_per_layer[2];
    std::optional<int64_t> last_inserted_frame_id;
    std::optional<uint32_t> last_keyframe_rtp_ts;
    std::optional<uint8_t> current_spatial_id;
    FrameBuffer3 frame_buffer;
    VCMJitterEstimator jitter_estimator;
    VCMTiming vcm_timing;
    std::optional<Timestamp> prev_recv_time;
    std::optional<DataSize> prev_frame_size;

    SubscribedTrackContext(Timestamp now, bool zero_delay)
        : frame_buffer(256), vcm_timing(now, zero_delay) {}
  };

  struct PendingMoqDataMsg {
    std::vector<uint8_t> payload;
    bool is_binary = true;
  };

  struct MoqDataChannelState {
    int channel_id = 0;
    DataChannelConfig config;
    rtc_data_channel_state_e state = RTC_DATA_CHANNEL_CONNECTING;
    bool local_created = false;
    bool announced = false;
    bool local_open_notified = false;
    std::optional<uint64_t> publish_ns_stream_id;
    std::optional<uint64_t> ordered_stream_id;
    std::optional<uint64_t> ordered_prev_obj_id;
    uint64_t next_object_id = 0;
    std::deque<PendingMoqDataMsg> pending_messages;
  };

  uint64_t AllocateClientRequestId();
  std::string ExtractPeerIdFromIdOrSlash(std::string_view track_or_peer_id) const;
  void SendSubscribePairForTrack(SubscribedTrackContext* ctx);
  void SendEncodedFrameOnWorker(EncodedVideoFrame f);
  void FlushPendingPreSetupTraffic();
  void HandleControlStreamBytes(std::vector<uint8_t>* buf);
  void HandleOutboundRequestResponseBytes(OutboundBidiRequestState* req_st,
                                          ArrayView<const uint8_t> data,
                                          bool fin);
  void HandleInboundBidiRequestBytes(uint64_t stream_id,
                                     InboundBidiRequestState* req_st,
                                     ArrayView<const uint8_t> data,
                                     bool fin);
  void HandleNamespaceSuffixNotification(const MoqtTrackNamespace& suffix,
                                         bool is_done);
  void HandleInboundUnidirectionalData(uint64_t stream_id,
                                       ArrayView<const uint8_t> data,
                                       bool fin);
  void DeliverUnpackedDataObject(MoqDataObject obj);
  int EnsureDataChannelForLabelOnWorker(const std::string& label,
                                        const DataChannelConfig* explicit_cfg);
  void AnnounceDataChannelNamespaceOnWorker(MoqDataChannelState* dch);
  void TransmitMoqDataMessageOnWorker(int channel_id,
                                      ArrayView<const uint8_t> payload,
                                      bool is_binary,
                                      bool is_close);
  void OnPeriodicMaintenanceTick();
  void DrainDecodableFrames(SubscribedTrackContext* sub);

  Clock* const clock_;
  SdkTaskQueues* const queues_;
  const EngineConfig config_;
  ISessionBackendObserver* const observer_;
  ParsedMoqUrl parsed_url_;
  std::shared_ptr<IMoqQuicEngine> quic_engine_;
  MoqBweAdapter bwe_adapter_;

  SequenceChecker work_checker_;
  std::string room_id_;
  std::string local_peer_id_;
  bool session_started_ = false;
  bool reconnecting_ = false;
  uint32_t reconnect_attempt_ = 0;
  uint64_t reconnect_generation_ = 0;
  bool connected_ = false;
  bool tick_scheduled_ = false;
  std::atomic<bool> session_ready_{false};
  bool peer_setup_received_ = false;
  std::optional<uint64_t> peer_control_stream_id_;
  uint64_t local_control_stream_id_ = 0;
  uint64_t next_client_request_id_ = 0;  // 客户端使用偶数 Request ID：0, 2, 4, ...

  uint64_t sub_ns_stream_id_ = 0;
  uint64_t pub_video_ns_stream_id_ = 0;
  uint64_t sub_data_stream_id_ = 0;
  uint64_t downstream_data_alias_ = kMoqDownstreamDataTrackAlias;

  std::map<uint64_t, OutboundBidiRequestState> outbound_requests_;
  std::map<uint64_t, InboundBidiRequestState> inbound_requests_;
  std::map<uint64_t, InboundUniStreamState> inbound_uni_streams_;
  std::set<uint64_t> seen_server_request_ids_;
  std::map<uint64_t, uint64_t> active_inbound_req_id_to_stream_;
  std::map<uint64_t, uint64_t> active_track_alias_to_stream_;
  std::set<uint64_t> inbound_published_aliases_;
  std::deque<EncodedVideoFrame> pending_pre_setup_frames_;
  bool had_local_video_published_ = false;

  bool layer_active_[2]{true, true};
  uint64_t current_group_id_[2]{0, 0};
  int64_t next_frame_id_[2]{0, 0};
  std::optional<int64_t> last_base_frame_id_[2];
  std::optional<int64_t> last_tl_frame_id_[2][8];
  std::optional<ActiveOutboundGroup> active_group_[2];
  uint64_t streams_reset_on_timeout_ = 0;

  std::map<std::string, std::unique_ptr<SubscribedTrackContext>> subscriptions_;
  std::map<uint64_t, std::string> alias_to_track_id_;

  // MoQ 数据轨道通道状态表与句柄校验集。
  int next_dc_id_ = 0;
  std::map<int, MoqDataChannelState> data_channels_;
  std::map<std::string, int> label_to_dc_id_;
  std::set<std::pair<std::string, int>> notified_remote_dc_peers_;
  std::vector<std::pair<uint64_t, Timestamp>> ttl_data_streams_;
  mutable std::mutex dc_handles_mu_;
  std::set<int> valid_dc_ids_;

  // 用于 OnBackendStatsSnapshot 回调的遥测统计计数器。
  Timestamp last_stats_time_ = Timestamp::MinusInfinity();
  uint64_t frames_decoded_ = 0;
  uint64_t keyframe_requests_sent_ = 0;
  uint32_t last_target_bps_ = 0;

  ScopedTaskSafety safety_;
};

class InMemoryMoqQuicPair {
 public:
  static std::pair<std::shared_ptr<IMoqQuicEngine>,
                   std::shared_ptr<IMoqQuicEngine>>
  CreateConnectedPair(
      TaskQueueBoost* network_queue,
      DataRate simulated_bandwidth = DataRate::KilobitsPerSec(3000),
      TimeDelta simulated_rtt = TimeDelta::Millis(25));
};

}  // namespace rtc

#endif  // SRC_MOQ_MOQ_TRANSPORT_H_
