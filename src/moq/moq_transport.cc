#include "moq/moq_transport.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstring>
#include <limits>

#include "modules/rtp_rtcp/byte_io.h"
#include "moq/asio_quic_transport.h"
#include "moq/http3_webtransport.h"
#include "rtc_base/json_utils.h"
#include "rtc_base/logging.h"

namespace rtc {

// ======================= QuicVarInt 变长整数编解码（RFC 9000 第 16 节） =======================

void QuicVarInt::Append(uint64_t val, std::vector<uint8_t>* dst) {
  if (val <= 63) {
    dst->push_back(static_cast<uint8_t>(val));
  } else if (val <= 16383) {
    uint8_t b[2];
    WriteBigEndian16(b, static_cast<uint16_t>(val) | 0x4000u);
    dst->insert(dst->end(), b, b + 2);
  } else if (val <= 1073741823ULL) {
    uint8_t b[4];
    WriteBigEndian32(b, static_cast<uint32_t>(val) | 0x80000000u);
    dst->insert(dst->end(), b, b + 4);
  } else {
    uint8_t b[8];
    WriteBigEndian32(
        b, static_cast<uint32_t>((val >> 32) & 0x3FFFFFFFULL) | 0xC0000000u);
    WriteBigEndian32(b + 4, static_cast<uint32_t>(val & 0xFFFFFFFFULL));
    dst->insert(dst->end(), b, b + 8);
  }
}

bool QuicVarInt::Read(ArrayView<const uint8_t> data,
                      size_t* offset,
                      uint64_t* out_val) {
  if (*offset >= data.size()) {
    return false;
  }
  const uint8_t first = data[*offset];
  const uint8_t prefix = first >> 6;
  const size_t nbytes = size_t{1} << prefix;
  if (*offset + nbytes > data.size()) {
    return false;
  }

  uint64_t v = first & 0x3Fu;
  for (size_t i = 1; i < nbytes; ++i) {
    v = (v << 8) | data[*offset + i];
  }
  *offset += nbytes;
  *out_val = v;
  return true;
}

void QuicVarInt::AppendString(std::string_view str, std::vector<uint8_t>* dst) {
  Append(str.size(), dst);
  dst->insert(dst->end(), str.begin(), str.end());
}

bool QuicVarInt::ReadString(ArrayView<const uint8_t> data,
                            size_t* offset,
                            std::string* out_str) {
  uint64_t slen = 0;
  if (!Read(data, offset, &slen) || *offset + slen > data.size()) {
    return false;
  }
  out_str->assign(reinterpret_cast<const char*>(data.data() + *offset),
                  static_cast<size_t>(slen));
  *offset += static_cast<size_t>(slen);
  return true;
}

// ======================= MoqtVarInt 变长整数编解码（draft-17 第 1.4.1 节 vi64） =======================

void MoqtVarInt::Append(uint64_t val, std::vector<uint8_t>* dst) {
  if (val < (uint64_t{1} << 7)) {
    dst->push_back(static_cast<uint8_t>(val));
  } else if (val < (uint64_t{1} << 14)) {
    dst->push_back(static_cast<uint8_t>(0x80u | (val >> 8)));
    dst->push_back(static_cast<uint8_t>(val & 0xFFu));
  } else if (val < (uint64_t{1} << 21)) {
    dst->push_back(static_cast<uint8_t>(0xC0u | (val >> 16)));
    dst->push_back(static_cast<uint8_t>((val >> 8) & 0xFFu));
    dst->push_back(static_cast<uint8_t>(val & 0xFFu));
  } else if (val < (uint64_t{1} << 28)) {
    dst->push_back(static_cast<uint8_t>(0xE0u | (val >> 24)));
    for (int s = 16; s >= 0; s -= 8) {
      dst->push_back(static_cast<uint8_t>((val >> s) & 0xFFu));
    }
  } else if (val < (uint64_t{1} << 35)) {
    dst->push_back(static_cast<uint8_t>(0xF0u | (val >> 32)));
    for (int s = 24; s >= 0; s -= 8) {
      dst->push_back(static_cast<uint8_t>((val >> s) & 0xFFu));
    }
  } else if (val < (uint64_t{1} << 42)) {
    dst->push_back(static_cast<uint8_t>(0xF8u | (val >> 40)));
    for (int s = 32; s >= 0; s -= 8) {
      dst->push_back(static_cast<uint8_t>((val >> s) & 0xFFu));
    }
  } else if (val < (uint64_t{1} << 56)) {
    dst->push_back(0xFEu);
    for (int s = 48; s >= 0; s -= 8) {
      dst->push_back(static_cast<uint8_t>((val >> s) & 0xFFu));
    }
  } else {
    dst->push_back(0xFFu);
    for (int s = 56; s >= 0; s -= 8) {
      dst->push_back(static_cast<uint8_t>((val >> s) & 0xFFu));
    }
  }
}

bool MoqtVarInt::Read(ArrayView<const uint8_t> data,
                      size_t* offset,
                      uint64_t* out_val,
                      bool* out_invalid_codepoint) {
  if (out_invalid_codepoint != nullptr) {
    *out_invalid_codepoint = false;
  }
  if (*offset >= data.size()) {
    return false;
  }
  const uint8_t b0 = data[*offset];
  if ((b0 & 0xFEu) == 0xFCu) {
    // draft-17 第 1.4.1 节：1111110x（0xFC / 0xFD）为非法编码点，须触发 PROTOCOL_VIOLATION。
    if (out_invalid_codepoint != nullptr) {
      *out_invalid_codepoint = true;
    }
    return false;
  }

  size_t total_len = 1;
  uint8_t first_mask = 0x7Fu;
  if ((b0 & 0x80u) == 0) {
    total_len = 1;
    first_mask = 0x7Fu;
  } else if ((b0 & 0xC0u) == 0x80u) {
    total_len = 2;
    first_mask = 0x3Fu;
  } else if ((b0 & 0xE0u) == 0xC0u) {
    total_len = 3;
    first_mask = 0x1Fu;
  } else if ((b0 & 0xF0u) == 0xE0u) {
    total_len = 4;
    first_mask = 0x0Fu;
  } else if ((b0 & 0xF8u) == 0xF0u) {
    total_len = 5;
    first_mask = 0x07u;
  } else if ((b0 & 0xFCu) == 0xF8u) {
    total_len = 6;
    first_mask = 0x03u;
  } else if (b0 == 0xFEu) {
    total_len = 8;
    first_mask = 0x00u;
  } else {
    total_len = 9;
    first_mask = 0x00u;
  }

  if (*offset + total_len > data.size()) {
    return false;
  }
  uint64_t val = b0 & first_mask;
  for (size_t i = 1; i < total_len; ++i) {
    val = (val << 8) | data[*offset + i];
  }
  *offset += total_len;
  *out_val = val;
  return true;
}

void MoqtVarInt::AppendBytes(ArrayView<const uint8_t> bytes,
                             std::vector<uint8_t>* dst) {
  Append(bytes.size(), dst);
  dst->insert(dst->end(), bytes.begin(), bytes.end());
}

bool MoqtVarInt::ReadBytes(ArrayView<const uint8_t> data,
                           size_t* offset,
                           std::vector<uint8_t>* out_bytes,
                           size_t max_len) {
  uint64_t len = 0;
  if (!Read(data, offset, &len) || len > max_len ||
      *offset + len > data.size()) {
    return false;
  }
  out_bytes->assign(data.data() + *offset,
                    data.data() + *offset + static_cast<size_t>(len));
  *offset += static_cast<size_t>(len);
  return true;
}

void MoqtVarInt::AppendString(std::string_view str, std::vector<uint8_t>* dst) {
  Append(str.size(), dst);
  dst->insert(dst->end(), str.begin(), str.end());
}

bool MoqtVarInt::ReadString(ArrayView<const uint8_t> data,
                            size_t* offset,
                            std::string* out_str,
                            size_t max_len) {
  uint64_t len = 0;
  if (!Read(data, offset, &len) || len > max_len ||
      *offset + len > data.size()) {
    return false;
  }
  out_str->assign(reinterpret_cast<const char*>(data.data() + *offset),
                  static_cast<size_t>(len));
  *offset += static_cast<size_t>(len);
  return true;
}

// ======================= MoqtKeyValuePair 与 MoqtTrackNamespace =======================

MoqtKeyValuePair MoqtKeyValuePair::MakeVarInt(uint64_t even_type,
                                              uint64_t val) {
  MoqtKeyValuePair kv;
  kv.type = even_type;
  kv.int_value = val;
  return kv;
}

MoqtKeyValuePair MoqtKeyValuePair::MakeBytes(uint64_t odd_type,
                                             ArrayView<const uint8_t> bytes) {
  MoqtKeyValuePair kv;
  kv.type = odd_type;
  kv.bytes_value.assign(bytes.begin(), bytes.end());
  return kv;
}

MoqtKeyValuePair MoqtKeyValuePair::MakeString(uint64_t odd_type,
                                              std::string_view str) {
  MoqtKeyValuePair kv;
  kv.type = odd_type;
  kv.bytes_value.assign(str.begin(), str.end());
  return kv;
}

bool MoqtKeyValuePair::EncodeList(const std::vector<MoqtKeyValuePair>& items,
                                  std::vector<uint8_t>* out) {
  std::vector<MoqtKeyValuePair> sorted = items;
  std::sort(sorted.begin(), sorted.end(),
            [](const MoqtKeyValuePair& a, const MoqtKeyValuePair& b) {
              return a.type < b.type;
            });
  uint64_t prev_type = 0;
  for (const auto& item : sorted) {
    if (item.type < prev_type) {
      return false;
    }
    const uint64_t delta = item.type - prev_type;
    prev_type = item.type;
    MoqtVarInt::Append(delta, out);
    if ((item.type & 1u) == 0) {
      MoqtVarInt::Append(item.int_value, out);
    } else {
      if (item.bytes_value.size() > 65535) {
        return false;
      }
      MoqtVarInt::AppendBytes(item.bytes_value, out);
    }
  }
  return true;
}

bool MoqtKeyValuePair::DecodeList(ArrayView<const uint8_t> data,
                                  size_t* offset,
                                  std::vector<MoqtKeyValuePair>* out_items) {
  out_items->clear();
  uint64_t prev_type = 0;
  while (*offset < data.size()) {
    uint64_t delta = 0;
    if (!MoqtVarInt::Read(data, offset, &delta) ||
        delta > std::numeric_limits<uint64_t>::max() - prev_type) {
      return false;
    }
    const uint64_t cur_type = prev_type + delta;
    prev_type = cur_type;
    MoqtKeyValuePair kv;
    kv.type = cur_type;
    if ((cur_type & 1u) == 0) {
      if (!MoqtVarInt::Read(data, offset, &kv.int_value)) {
        return false;
      }
    } else {
      if (!MoqtVarInt::ReadBytes(data, offset, &kv.bytes_value, 65535)) {
        return false;
      }
    }
    out_items->push_back(std::move(kv));
  }
  return true;
}

bool MoqtTrackNamespace::Encode(std::vector<uint8_t>* out) const {
  if (fields.size() > 32) {
    return false;
  }
  size_t total_len = 0;
  for (const auto& f : fields) {
    if (f.empty()) {
      return false;
    }
    total_len += f.size();
  }
  if (total_len > 4096) {
    return false;
  }
  MoqtVarInt::Append(fields.size(), out);
  for (const auto& f : fields) {
    MoqtVarInt::AppendString(f, out);
  }
  return true;
}

bool MoqtTrackNamespace::Decode(ArrayView<const uint8_t> data,
                                size_t* offset,
                                MoqtTrackNamespace* out) {
  out->fields.clear();
  uint64_t count = 0;
  if (!MoqtVarInt::Read(data, offset, &count) || count > 32) {
    return false;
  }
  size_t total_bytes = 0;
  out->fields.reserve(static_cast<size_t>(count));
  for (uint64_t i = 0; i < count; ++i) {
    std::string field;
    if (!MoqtVarInt::ReadString(data, offset, &field, 4096) || field.empty()) {
      return false;
    }
    total_bytes += field.size();
    if (total_bytes > 4096) {
      return false;
    }
    out->fields.push_back(std::move(field));
  }
  return true;
}

bool MoqtTrackNamespace::StartsWith(const MoqtTrackNamespace& prefix) const {
  if (prefix.fields.size() > fields.size()) {
    return false;
  }
  for (size_t i = 0; i < prefix.fields.size(); ++i) {
    if (fields[i] != prefix.fields[i]) {
      return false;
    }
  }
  return true;
}

MoqtTrackNamespace MoqtTrackNamespace::SuffixAfter(
    const MoqtTrackNamespace& prefix) const {
  MoqtTrackNamespace suf;
  if (!StartsWith(prefix)) {
    return suf;
  }
  suf.fields.assign(
      fields.begin() + static_cast<ptrdiff_t>(prefix.fields.size()),
      fields.end());
  return suf;
}

MoqtTrackNamespace MoqtTrackNamespace::WithSuffix(
    const MoqtTrackNamespace& suffix) const {
  MoqtTrackNamespace combined = *this;
  combined.fields.insert(combined.fields.end(), suffix.fields.begin(),
                         suffix.fields.end());
  return combined;
}

std::string MoqtTrackNamespace::ToSlashString() const {
  std::string out;
  for (size_t i = 0; i < fields.size(); ++i) {
    if (i > 0) {
      out.push_back('/');
    }
    out += fields[i];
  }
  return out;
}

MoqtTrackNamespace MoqtTrackNamespace::FromSlashString(std::string_view text) {
  MoqtTrackNamespace ns;
  size_t pos = 0;
  while (pos < text.size()) {
    const size_t slash = text.find('/', pos);
    const std::string_view part =
        (slash == std::string_view::npos) ? text.substr(pos)
                                          : text.substr(pos, slash - pos);
    if (!part.empty()) {
      ns.fields.emplace_back(part);
    }
    if (slash == std::string_view::npos) {
      break;
    }
    pos = slash + 1;
  }
  return ns;
}

MoqtTrackNamespace MoqtTrackNamespace::MakeRoomPrefix(std::string_view room_id) {
  MoqtTrackNamespace ns;
  ns.fields.push_back("rtc");
  ns.fields.emplace_back(room_id.empty() ? "default" : room_id);
  return ns;
}

MoqtTrackNamespace MoqtTrackNamespace::MakePeerNamespace(
    std::string_view room_id,
    std::string_view peer_id) {
  MoqtTrackNamespace ns = MakeRoomPrefix(room_id);
  ns.fields.emplace_back(peer_id.empty() ? "peer" : peer_id);
  return ns;
}

// ======================= MoqtSubscriptionFilter 与 MoqtMessageParameters =======================

std::vector<uint8_t> MoqtSubscriptionFilter::Encode() const {
  std::vector<uint8_t> out;
  MoqtVarInt::Append(static_cast<uint64_t>(type), &out);
  if (type == MoqFilterType::kAbsoluteStart ||
      type == MoqFilterType::kAbsoluteRange) {
    MoqtVarInt::Append(start_location.group, &out);
    MoqtVarInt::Append(start_location.object, &out);
  }
  if (type == MoqFilterType::kAbsoluteRange) {
    MoqtVarInt::Append(end_group_delta, &out);
  }
  return out;
}

std::optional<MoqtSubscriptionFilter> MoqtSubscriptionFilter::Decode(
    ArrayView<const uint8_t> data) {
  size_t off = 0;
  uint64_t raw_type = 0;
  if (!MoqtVarInt::Read(data, &off, &raw_type) || raw_type < 0x01 ||
      raw_type > 0x04) {
    return std::nullopt;
  }
  MoqtSubscriptionFilter f;
  f.type = static_cast<MoqFilterType>(raw_type);
  if (f.type == MoqFilterType::kAbsoluteStart ||
      f.type == MoqFilterType::kAbsoluteRange) {
    if (!MoqtVarInt::Read(data, &off, &f.start_location.group) ||
        !MoqtVarInt::Read(data, &off, &f.start_location.object)) {
      return std::nullopt;
    }
  }
  if (f.type == MoqFilterType::kAbsoluteRange &&
      !MoqtVarInt::Read(data, &off, &f.end_group_delta)) {
    return std::nullopt;
  }
  if (off != data.size()) {
    return std::nullopt;
  }
  return f;
}

bool MoqtMessageParameters::Encode(std::vector<uint8_t>* out) const {
  struct RawParam {
    uint64_t type = 0;
    std::vector<uint8_t> encoded_val;
  };
  std::vector<RawParam> params;

  if (delivery_timeout_ms.has_value()) {
    RawParam p{0x02, {}};
    MoqtVarInt::Append(*delivery_timeout_ms, &p.encoded_val);
    params.push_back(std::move(p));
  }
  for (const auto& tok : authorization_tokens) {
    RawParam p{0x03, {}};
    MoqtVarInt::AppendBytes(tok, &p.encoded_val);
    params.push_back(std::move(p));
  }
  if (rendezvous_timeout_ms.has_value()) {
    RawParam p{0x04, {}};
    MoqtVarInt::Append(*rendezvous_timeout_ms, &p.encoded_val);
    params.push_back(std::move(p));
  }
  if (expires_ms.has_value()) {
    RawParam p{0x08, {}};
    MoqtVarInt::Append(*expires_ms, &p.encoded_val);
    params.push_back(std::move(p));
  }
  if (largest_object.has_value()) {
    RawParam p{0x09, {}};
    MoqtVarInt::Append(largest_object->group, &p.encoded_val);
    MoqtVarInt::Append(largest_object->object, &p.encoded_val);
    params.push_back(std::move(p));
  }
  if (forward.has_value()) {
    if (*forward > 1) {
      return false;
    }
    params.push_back(RawParam{0x10, {*forward}});
  }
  if (subscriber_priority.has_value()) {
    params.push_back(RawParam{0x20, {*subscriber_priority}});
  }
  if (subscription_filter.has_value()) {
    RawParam p{0x21, {}};
    const auto fbytes = subscription_filter->Encode();
    MoqtVarInt::AppendBytes(fbytes, &p.encoded_val);
    params.push_back(std::move(p));
  }
  if (group_order.has_value()) {
    if (*group_order < 1 || *group_order > 2) {
      return false;
    }
    params.push_back(RawParam{0x22, {*group_order}});
  }
  if (new_group_request.has_value()) {
    RawParam p{0x32, {}};
    MoqtVarInt::Append(*new_group_request, &p.encoded_val);
    params.push_back(std::move(p));
  }

  MoqtVarInt::Append(params.size(), out);
  uint64_t prev_type = 0;
  for (const auto& p : params) {
    const uint64_t delta = p.type - prev_type;
    prev_type = p.type;
    MoqtVarInt::Append(delta, out);
    out->insert(out->end(), p.encoded_val.begin(), p.encoded_val.end());
  }
  return true;
}

bool MoqtMessageParameters::Decode(ArrayView<const uint8_t> data,
                                   size_t* offset,
                                   MoqtMessageParameters* out) {
  *out = MoqtMessageParameters{};
  uint64_t num_params = 0;
  if (!MoqtVarInt::Read(data, offset, &num_params) || num_params > 64) {
    return false;
  }
  uint64_t prev_type = 0;
  for (uint64_t i = 0; i < num_params; ++i) {
    uint64_t delta = 0;
    if (!MoqtVarInt::Read(data, offset, &delta) ||
        delta > std::numeric_limits<uint64_t>::max() - prev_type) {
      return false;
    }
    const uint64_t ptype = prev_type + delta;
    if (i > 0 && delta == 0 && ptype != 0x03) {
      // 除 AUTHORIZATION_TOKEN (0x03) 外，同一消息内禁止重复出现相同参数类型。
      return false;
    }
    prev_type = ptype;

    switch (ptype) {
      case 0x02: {
        uint64_t v = 0;
        if (!MoqtVarInt::Read(data, offset, &v)) {
          return false;
        }
        out->delivery_timeout_ms = v;
        break;
      }
      case 0x03: {
        std::vector<uint8_t> tok;
        if (!MoqtVarInt::ReadBytes(data, offset, &tok, 65535)) {
          return false;
        }
        out->authorization_tokens.push_back(std::move(tok));
        break;
      }
      case 0x04: {
        uint64_t v = 0;
        if (!MoqtVarInt::Read(data, offset, &v)) {
          return false;
        }
        out->rendezvous_timeout_ms = v;
        break;
      }
      case 0x08: {
        uint64_t v = 0;
        if (!MoqtVarInt::Read(data, offset, &v)) {
          return false;
        }
        out->expires_ms = v;
        break;
      }
      case 0x09: {
        MoqtLocation loc;
        if (!MoqtVarInt::Read(data, offset, &loc.group) ||
            !MoqtVarInt::Read(data, offset, &loc.object)) {
          return false;
        }
        out->largest_object = loc;
        break;
      }
      case 0x10: {
        if (*offset >= data.size()) {
          return false;
        }
        const uint8_t fwd = data[(*offset)++];
        if (fwd > 1) {
          return false;
        }
        out->forward = fwd;
        break;
      }
      case 0x20: {
        if (*offset >= data.size()) {
          return false;
        }
        out->subscriber_priority = data[(*offset)++];
        break;
      }
      case 0x21: {
        std::vector<uint8_t> fbytes;
        if (!MoqtVarInt::ReadBytes(data, offset, &fbytes, 64)) {
          return false;
        }
        auto parsed_f = MoqtSubscriptionFilter::Decode(fbytes);
        if (!parsed_f.has_value()) {
          return false;
        }
        out->subscription_filter = *parsed_f;
        break;
      }
      case 0x22: {
        if (*offset >= data.size()) {
          return false;
        }
        const uint8_t go = data[(*offset)++];
        if (go < 1 || go > 2) {
          return false;
        }
        out->group_order = go;
        break;
      }
      case 0x32: {
        uint64_t v = 0;
        if (!MoqtVarInt::Read(data, offset, &v)) {
          return false;
        }
        out->new_group_request = v;
        break;
      }
      default:
        // draft-17 第 9.3 节：收到未协商的未知 Message Parameter 必须作为协议违规拒绝。
        return false;
    }
  }
  return true;
}

// ======================= MoqControlMessage 控制消息编解码（draft-17 第 9 章） =======================

std::vector<uint8_t> MoqControlMessage::Encode() const {
  std::vector<uint8_t> body;
  body.reserve(64);

  switch (type) {
    case MoqControlMessageType::kSetup: {
      MoqtKeyValuePair::EncodeList(setup_options, &body);
      break;
    }
    case MoqControlMessageType::kGoaway: {
      MoqtVarInt::AppendString(new_session_uri, &body);
      MoqtVarInt::Append(goaway_timeout_ms, &body);
      break;
    }
    case MoqControlMessageType::kRequestOk:
    case MoqControlMessageType::kPublishOk: {
      parameters.Encode(&body);
      break;
    }
    case MoqControlMessageType::kRequestError: {
      MoqtVarInt::Append(error_or_status_code, &body);
      MoqtVarInt::Append(retry_interval_or_stream_count, &body);
      MoqtVarInt::AppendString(reason_phrase, &body);
      break;
    }
    case MoqControlMessageType::kSubscribe:
    case MoqControlMessageType::kTrackStatus: {
      MoqtVarInt::Append(request_id, &body);
      MoqtVarInt::Append(required_request_id_delta, &body);
      track_namespace.Encode(&body);
      MoqtVarInt::AppendString(track_name, &body);
      parameters.Encode(&body);
      break;
    }
    case MoqControlMessageType::kSubscribeOk: {
      MoqtVarInt::Append(track_alias, &body);
      parameters.Encode(&body);
      MoqtKeyValuePair::EncodeList(track_properties, &body);
      break;
    }
    case MoqControlMessageType::kRequestUpdate: {
      MoqtVarInt::Append(request_id, &body);
      MoqtVarInt::Append(required_request_id_delta, &body);
      parameters.Encode(&body);
      break;
    }
    case MoqControlMessageType::kPublish: {
      MoqtVarInt::Append(request_id, &body);
      MoqtVarInt::Append(required_request_id_delta, &body);
      track_namespace.Encode(&body);
      MoqtVarInt::AppendString(track_name, &body);
      MoqtVarInt::Append(track_alias, &body);
      parameters.Encode(&body);
      MoqtKeyValuePair::EncodeList(track_properties, &body);
      break;
    }
    case MoqControlMessageType::kPublishDone: {
      MoqtVarInt::Append(error_or_status_code, &body);
      MoqtVarInt::Append(retry_interval_or_stream_count, &body);
      MoqtVarInt::AppendString(reason_phrase, &body);
      break;
    }
    case MoqControlMessageType::kPublishNamespace: {
      MoqtVarInt::Append(request_id, &body);
      MoqtVarInt::Append(required_request_id_delta, &body);
      track_namespace.Encode(&body);
      parameters.Encode(&body);
      break;
    }
    case MoqControlMessageType::kSubscribeNamespace: {
      MoqtVarInt::Append(request_id, &body);
      MoqtVarInt::Append(required_request_id_delta, &body);
      track_namespace.Encode(&body);
      MoqtVarInt::Append(subscribe_options, &body);
      parameters.Encode(&body);
      break;
    }
    case MoqControlMessageType::kNamespace:
    case MoqControlMessageType::kNamespaceDone: {
      track_namespace.Encode(&body);
      break;
    }
    case MoqControlMessageType::kPublishBlocked: {
      track_namespace.Encode(&body);
      MoqtVarInt::AppendString(track_name, &body);
      break;
    }
    default:
      break;
  }

  if (body.size() > 65535) {
    return {};
  }
  std::vector<uint8_t> frame;
  frame.reserve(6 + body.size());
  MoqtVarInt::Append(static_cast<uint64_t>(type), &frame);
  uint8_t len_be[2];
  WriteBigEndian16(len_be, static_cast<uint16_t>(body.size()));
  frame.push_back(len_be[0]);
  frame.push_back(len_be[1]);
  frame.insert(frame.end(), body.begin(), body.end());
  return frame;
}

std::optional<MoqControlMessage> MoqControlMessage::Decode(
    ArrayView<const uint8_t> data,
    size_t* consumed,
    bool* out_protocol_violation) {
  if (out_protocol_violation != nullptr) {
    *out_protocol_violation = false;
  }
  size_t off = 0;
  uint64_t raw_type = 0;
  bool bad_vi = false;
  if (!MoqtVarInt::Read(data, &off, &raw_type, &bad_vi)) {
    if (bad_vi && out_protocol_violation != nullptr) {
      *out_protocol_violation = true;
    }
    return std::nullopt;
  }
  if (off + 2 > data.size()) {
    return std::nullopt;
  }
  const uint16_t body_len = ReadBigEndian16(data.data() + off);
  off += 2;
  if (off + body_len > data.size()) {
    return std::nullopt;
  }

  const ArrayView<const uint8_t> body = data.subview(off, body_len);
  size_t boff = 0;
  MoqControlMessage msg;
  msg.type = static_cast<MoqControlMessageType>(raw_type);

  auto fail_violation = [&]() -> std::optional<MoqControlMessage> {
    if (out_protocol_violation != nullptr) {
      *out_protocol_violation = true;
    }
    return std::nullopt;
  };

  switch (msg.type) {
    case MoqControlMessageType::kSetup:
      if (!MoqtKeyValuePair::DecodeList(body, &boff, &msg.setup_options)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kGoaway:
      if (!MoqtVarInt::ReadString(body, &boff, &msg.new_session_uri, 8192) ||
          !MoqtVarInt::Read(body, &boff, &msg.goaway_timeout_ms)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kRequestOk:
    case MoqControlMessageType::kPublishOk:
      if (!MoqtMessageParameters::Decode(body, &boff, &msg.parameters)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kRequestError:
    case MoqControlMessageType::kPublishDone:
      if (!MoqtVarInt::Read(body, &boff, &msg.error_or_status_code) ||
          !MoqtVarInt::Read(body, &boff, &msg.retry_interval_or_stream_count) ||
          !MoqtVarInt::ReadString(body, &boff, &msg.reason_phrase, 1024)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kSubscribe:
    case MoqControlMessageType::kTrackStatus:
      if (!MoqtVarInt::Read(body, &boff, &msg.request_id) ||
          !MoqtVarInt::Read(body, &boff, &msg.required_request_id_delta) ||
          2 * msg.required_request_id_delta > msg.request_id ||
          !MoqtTrackNamespace::Decode(body, &boff, &msg.track_namespace) ||
          !MoqtVarInt::ReadString(body, &boff, &msg.track_name, 4096) ||
          !MoqtMessageParameters::Decode(body, &boff, &msg.parameters)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kSubscribeOk:
      if (!MoqtVarInt::Read(body, &boff, &msg.track_alias) ||
          !MoqtMessageParameters::Decode(body, &boff, &msg.parameters) ||
          !MoqtKeyValuePair::DecodeList(body, &boff, &msg.track_properties)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kRequestUpdate:
      if (!MoqtVarInt::Read(body, &boff, &msg.request_id) ||
          !MoqtVarInt::Read(body, &boff, &msg.required_request_id_delta) ||
          2 * msg.required_request_id_delta > msg.request_id ||
          !MoqtMessageParameters::Decode(body, &boff, &msg.parameters)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kPublish:
      if (!MoqtVarInt::Read(body, &boff, &msg.request_id) ||
          !MoqtVarInt::Read(body, &boff, &msg.required_request_id_delta) ||
          2 * msg.required_request_id_delta > msg.request_id ||
          !MoqtTrackNamespace::Decode(body, &boff, &msg.track_namespace) ||
          !MoqtVarInt::ReadString(body, &boff, &msg.track_name, 4096) ||
          !MoqtVarInt::Read(body, &boff, &msg.track_alias) ||
          !MoqtMessageParameters::Decode(body, &boff, &msg.parameters) ||
          !MoqtKeyValuePair::DecodeList(body, &boff, &msg.track_properties)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kPublishNamespace:
      if (!MoqtVarInt::Read(body, &boff, &msg.request_id) ||
          !MoqtVarInt::Read(body, &boff, &msg.required_request_id_delta) ||
          2 * msg.required_request_id_delta > msg.request_id ||
          !MoqtTrackNamespace::Decode(body, &boff, &msg.track_namespace) ||
          !MoqtMessageParameters::Decode(body, &boff, &msg.parameters)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kSubscribeNamespace:
      if (!MoqtVarInt::Read(body, &boff, &msg.request_id) ||
          !MoqtVarInt::Read(body, &boff, &msg.required_request_id_delta) ||
          2 * msg.required_request_id_delta > msg.request_id ||
          !MoqtTrackNamespace::Decode(body, &boff, &msg.track_namespace) ||
          !MoqtVarInt::Read(body, &boff, &msg.subscribe_options) ||
          msg.subscribe_options > 0x02 ||
          !MoqtMessageParameters::Decode(body, &boff, &msg.parameters)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kNamespace:
    case MoqControlMessageType::kNamespaceDone:
      if (!MoqtTrackNamespace::Decode(body, &boff, &msg.track_namespace)) {
        return fail_violation();
      }
      break;
    case MoqControlMessageType::kPublishBlocked:
      if (!MoqtTrackNamespace::Decode(body, &boff, &msg.track_namespace) ||
          !MoqtVarInt::ReadString(body, &boff, &msg.track_name, 4096)) {
        return fail_violation();
      }
      break;
    default:
      return fail_violation();
  }

  if (boff != body.size()) {
    return fail_violation();
  }
  *consumed = off + body_len;
  return msg;
}

// ======================= 子组头部、子组对象与对象数据报编解码 =======================

std::vector<uint8_t> MoqSubgroupHeader::Encode() const {
  uint64_t type = 0x10u;
  if (has_properties) {
    type |= 0x01u;
  }
  if (subgroup_id_from_first_object) {
    type |= 0x02u;
  } else if (subgroup_id != 0) {
    type |= 0x04u;
  }
  if (end_of_group) {
    type |= 0x08u;
  }
  if (default_priority) {
    type |= 0x20u;
  }

  std::vector<uint8_t> out;
  out.reserve(16);
  MoqtVarInt::Append(type, &out);
  MoqtVarInt::Append(track_alias, &out);
  MoqtVarInt::Append(group_id, &out);
  if (!subgroup_id_from_first_object && subgroup_id != 0) {
    MoqtVarInt::Append(subgroup_id, &out);
  }
  if (!default_priority) {
    out.push_back(publisher_priority);
  }
  return out;
}

std::optional<MoqSubgroupHeader> MoqSubgroupHeader::Decode(
    ArrayView<const uint8_t> data,
    size_t* consumed,
    bool* out_protocol_violation) {
  if (out_protocol_violation != nullptr) {
    *out_protocol_violation = false;
  }
  size_t off = 0;
  uint64_t stype = 0;
  bool bad_vi = false;
  if (!MoqtVarInt::Read(data, &off, &stype, &bad_vi)) {
    if (bad_vi && out_protocol_violation != nullptr) {
      *out_protocol_violation = true;
    }
    return std::nullopt;
  }
  // draft-17 第 10.4.2 节：合法形式为 0b00X1XXXX（0x10..0x1F / 0x30..0x3F）且 SUBGROUP_ID_MODE != 0b11。
  const bool valid_range =
      (stype >= 0x10u && stype <= 0x1Fu) || (stype >= 0x30u && stype <= 0x3Fu);
  const uint64_t sid_mode = (stype & 0x06u) >> 1;
  if (!valid_range || sid_mode == 0x03u) {
    if (out_protocol_violation != nullptr) {
      *out_protocol_violation = true;
    }
    return std::nullopt;
  }

  MoqSubgroupHeader hdr;
  hdr.has_properties = (stype & 0x01u) != 0;
  hdr.subgroup_id_from_first_object = (sid_mode == 0x01u);
  hdr.end_of_group = (stype & 0x08u) != 0;
  hdr.default_priority = (stype & 0x20u) != 0;

  if (!MoqtVarInt::Read(data, &off, &hdr.track_alias, &bad_vi) ||
      !MoqtVarInt::Read(data, &off, &hdr.group_id, &bad_vi)) {
    if (bad_vi && out_protocol_violation != nullptr) {
      *out_protocol_violation = true;
    }
    return std::nullopt;
  }
  if (sid_mode == 0x00u) {
    hdr.subgroup_id = 0;
  } else if (sid_mode == 0x02u) {
    if (!MoqtVarInt::Read(data, &off, &hdr.subgroup_id, &bad_vi)) {
      if (bad_vi && out_protocol_violation != nullptr) {
        *out_protocol_violation = true;
      }
      return std::nullopt;
    }
  }
  if (!hdr.default_priority) {
    if (off + 1 > data.size()) {
      return std::nullopt;
    }
    hdr.publisher_priority = data[off++];
  }
  *consumed = off;
  return hdr;
}

std::vector<uint8_t> MoqtSubgroupObject::Encode(
    std::optional<uint64_t> prev_object_id,
    bool header_has_properties) const {
  const uint64_t delta =
      prev_object_id.has_value()
          ? (object_id > *prev_object_id ? (object_id - *prev_object_id - 1) : 0)
          : object_id;
  std::vector<uint8_t> out;
  out.reserve(16 + payload.size());
  MoqtVarInt::Append(delta, &out);
  if (header_has_properties) {
    std::vector<uint8_t> prop_bytes;
    MoqtKeyValuePair::EncodeList(properties, &prop_bytes);
    MoqtVarInt::AppendBytes(prop_bytes, &out);
  }
  if (!payload.empty()) {
    MoqtVarInt::Append(payload.size(), &out);
    out.insert(out.end(), payload.begin(), payload.end());
  } else {
    MoqtVarInt::Append(0, &out);
    MoqtVarInt::Append(static_cast<uint64_t>(status), &out);
  }
  return out;
}

std::optional<MoqtSubgroupObject> MoqtSubgroupObject::Decode(
    ArrayView<const uint8_t> data,
    std::optional<uint64_t> prev_object_id,
    bool header_has_properties,
    size_t* consumed,
    bool* out_protocol_violation) {
  if (out_protocol_violation != nullptr) {
    *out_protocol_violation = false;
  }
  size_t off = 0;
  uint64_t delta = 0;
  bool bad_vi = false;
  if (!MoqtVarInt::Read(data, &off, &delta, &bad_vi)) {
    if (bad_vi && out_protocol_violation != nullptr) {
      *out_protocol_violation = true;
    }
    return std::nullopt;
  }

  MoqtSubgroupObject obj;
  obj.object_id = prev_object_id.has_value() ? (*prev_object_id + delta + 1)
                                             : delta;
  if (header_has_properties) {
    std::vector<uint8_t> prop_bytes;
    if (!MoqtVarInt::ReadBytes(data, &off, &prop_bytes, 65535)) {
      return std::nullopt;
    }
    size_t poff = 0;
    if (!MoqtKeyValuePair::DecodeList(prop_bytes, &poff, &obj.properties)) {
      if (out_protocol_violation != nullptr) {
        *out_protocol_violation = true;
      }
      return std::nullopt;
    }
  }

  uint64_t payload_len = 0;
  if (!MoqtVarInt::Read(data, &off, &payload_len, &bad_vi)) {
    if (bad_vi && out_protocol_violation != nullptr) {
      *out_protocol_violation = true;
    }
    return std::nullopt;
  }

  if (payload_len == 0) {
    uint64_t raw_status = 0;
    if (!MoqtVarInt::Read(data, &off, &raw_status, &bad_vi)) {
      if (bad_vi && out_protocol_violation != nullptr) {
        *out_protocol_violation = true;
      }
      return std::nullopt;
    }
    if ((raw_status != 0x00 && raw_status != 0x03 && raw_status != 0x04) ||
        (raw_status != 0x00 && !obj.properties.empty())) {
      if (out_protocol_violation != nullptr) {
        *out_protocol_violation = true;
      }
      return std::nullopt;
    }
    obj.status = static_cast<MoqtObjectStatus>(raw_status);
  } else {
    if (off + payload_len > data.size()) {
      return std::nullopt;
    }
    obj.status = MoqtObjectStatus::kNormal;
    obj.payload.assign(data.data() + off,
                       data.data() + off + static_cast<size_t>(payload_len));
    off += static_cast<size_t>(payload_len);
  }
  *consumed = off;
  return obj;
}

std::vector<uint8_t> MoqtObjectDatagram::Encode() const {
  uint64_t dtype = 0;
  const bool has_props = !properties.empty();
  const bool is_status_only = payload.empty() && status != MoqtObjectStatus::kNormal;
  if (has_props) {
    dtype |= 0x01u;
  }
  if (end_of_group && !is_status_only) {
    dtype |= 0x02u;
  }
  if (object_id == 0) {
    dtype |= 0x04u;
  }
  if (default_priority) {
    dtype |= 0x08u;
  }
  if (is_status_only) {
    dtype |= 0x20u;
  }

  std::vector<uint8_t> out;
  out.reserve(20 + payload.size());
  MoqtVarInt::Append(dtype, &out);
  MoqtVarInt::Append(track_alias, &out);
  MoqtVarInt::Append(group_id, &out);
  if (object_id != 0) {
    MoqtVarInt::Append(object_id, &out);
  }
  if (!default_priority) {
    out.push_back(publisher_priority);
  }
  if (has_props) {
    std::vector<uint8_t> pbytes;
    MoqtKeyValuePair::EncodeList(properties, &pbytes);
    MoqtVarInt::AppendBytes(pbytes, &out);
  }
  if (is_status_only) {
    MoqtVarInt::Append(static_cast<uint64_t>(status), &out);
  } else {
    out.insert(out.end(), payload.begin(), payload.end());
  }
  return out;
}

std::optional<MoqtObjectDatagram> MoqtObjectDatagram::Decode(
    ArrayView<const uint8_t> data,
    bool* out_protocol_violation) {
  if (out_protocol_violation != nullptr) {
    *out_protocol_violation = false;
  }
  size_t off = 0;
  uint64_t dtype = 0;
  bool bad_vi = false;
  if (!MoqtVarInt::Read(data, &off, &dtype, &bad_vi)) {
    if (bad_vi && out_protocol_violation != nullptr) {
      *out_protocol_violation = true;
    }
    return std::nullopt;
  }
  const bool valid_range =
      (dtype <= 0x0Fu) || (dtype >= 0x20u && dtype <= 0x2Fu);
  const bool status_and_eog = ((dtype & 0x22u) == 0x22u);
  if (!valid_range || status_and_eog) {
    if (out_protocol_violation != nullptr) {
      *out_protocol_violation = true;
    }
    return std::nullopt;
  }

  MoqtObjectDatagram dg;
  dg.end_of_group = (dtype & 0x02u) != 0;
  const bool zero_obj_id = (dtype & 0x04u) != 0;
  dg.default_priority = (dtype & 0x08u) != 0;
  const bool has_status = (dtype & 0x20u) != 0;
  const bool has_props = (dtype & 0x01u) != 0;

  if (!MoqtVarInt::Read(data, &off, &dg.track_alias) ||
      !MoqtVarInt::Read(data, &off, &dg.group_id)) {
    return std::nullopt;
  }
  if (zero_obj_id) {
    dg.object_id = 0;
  } else if (!MoqtVarInt::Read(data, &off, &dg.object_id)) {
    return std::nullopt;
  }
  if (!dg.default_priority) {
    if (off >= data.size()) {
      return std::nullopt;
    }
    dg.publisher_priority = data[off++];
  }
  if (has_props) {
    std::vector<uint8_t> pbytes;
    if (!MoqtVarInt::ReadBytes(data, &off, &pbytes, 65535) || pbytes.empty()) {
      if (out_protocol_violation != nullptr) {
        *out_protocol_violation = true;
      }
      return std::nullopt;
    }
    size_t poff = 0;
    if (!MoqtKeyValuePair::DecodeList(pbytes, &poff, &dg.properties)) {
      if (out_protocol_violation != nullptr) {
        *out_protocol_violation = true;
      }
      return std::nullopt;
    }
  }
  if (has_status) {
    uint64_t raw_status = 0;
    if (!MoqtVarInt::Read(data, &off, &raw_status) || off != data.size()) {
      return std::nullopt;
    }
    if ((raw_status != 0x00 && raw_status != 0x03 && raw_status != 0x04) ||
        (raw_status != 0x00 && has_props)) {
      if (out_protocol_violation != nullptr) {
        *out_protocol_violation = true;
      }
      return std::nullopt;
    }
    dg.status = static_cast<MoqtObjectStatus>(raw_status);
  } else {
    dg.status = MoqtObjectStatus::kNormal;
    dg.payload.assign(data.data() + off, data.data() + data.size());
  }
  return dg;
}

// ======================= MoqDataPackager 与 LocFramePackager =======================

std::vector<uint8_t> MoqDataPackager::PackObject(const MoqDataObject& obj) {
  std::vector<uint8_t> out;
  out.reserve(32 + obj.sender_peer_id.size() + obj.label.size() +
              obj.protocol.size() + obj.payload.size());
  MoqtVarInt::Append(obj.object_id, &out);
  MoqtVarInt::AppendString(obj.sender_peer_id, &out);
  MoqtVarInt::AppendString(obj.label, &out);
  MoqtVarInt::AppendString(obj.protocol, &out);
  MoqtVarInt::Append(obj.timestamp_us, &out);
  uint8_t flags = 0;
  if (obj.is_binary) {
    flags |= 0x01u;
  }
  if (obj.ordered) {
    flags |= 0x02u;
  }
  if (obj.is_close) {
    flags |= 0x04u;
  }
  out.push_back(flags);
  MoqtVarInt::Append(obj.payload.size(), &out);
  out.insert(out.end(), obj.payload.begin(), obj.payload.end());
  return out;
}

std::optional<MoqDataObject> MoqDataPackager::UnpackObject(
    ArrayView<const uint8_t> data,
    size_t* consumed) {
  size_t off = 0;
  MoqDataObject obj;
  if (!MoqtVarInt::Read(data, &off, &obj.object_id) ||
      !MoqtVarInt::ReadString(data, &off, &obj.sender_peer_id, 1024) ||
      !MoqtVarInt::ReadString(data, &off, &obj.label, 1024) ||
      !MoqtVarInt::ReadString(data, &off, &obj.protocol, 1024) ||
      !MoqtVarInt::Read(data, &off, &obj.timestamp_us) ||
      off + 1 > data.size()) {
    return std::nullopt;
  }
  const uint8_t flags = data[off++];
  obj.is_binary = (flags & 0x01u) != 0u;
  obj.ordered = (flags & 0x02u) != 0u;
  obj.is_close = (flags & 0x04u) != 0u;

  uint64_t payload_len = 0;
  if (!MoqtVarInt::Read(data, &off, &payload_len) ||
      off + payload_len > data.size()) {
    return std::nullopt;
  }
  obj.payload.assign(data.data() + off,
                     data.data() + off + static_cast<size_t>(payload_len));
  off += static_cast<size_t>(payload_len);
  *consumed = off;
  return obj;
}

std::vector<uint8_t> LocFramePackager::PackPayload(
    const EncodedVideoFrame& frame) {
  std::vector<uint8_t> meta;
  meta.reserve(24);
  MoqtVarInt::Append(static_cast<uint64_t>(frame.capture_time.us()), &meta);
  MoqtVarInt::Append(frame.rtp_timestamp, &meta);
  MoqtVarInt::Append(
      static_cast<uint64_t>(frame.dep.frame_id >= 0 ? frame.dep.frame_id : 0),
      &meta);

  uint8_t flags = 0;
  if (frame.dep.is_keyframe) {
    flags |= 0x01u;
  }
  if (frame.dep.discardable) {
    flags |= 0x02u;
  }
  if (frame.codec == VideoCodec::kH265) {
    flags |= 0x04u;
  }
  if (frame.layer == SpatialLayer::kHigh) {
    flags |= 0x08u;
  }
  flags |= static_cast<uint8_t>((frame.dep.temporal_id & 0x07u) << 4);
  meta.push_back(flags);

  const uint8_t nrefs =
      static_cast<uint8_t>(std::min<size_t>(frame.dep.num_references, 4));
  meta.push_back(nrefs);
  for (uint8_t i = 0; i < nrefs; ++i) {
    const int64_t diff =
        std::max<int64_t>(1, frame.dep.frame_id - frame.dep.references[i]);
    MoqtVarInt::Append(static_cast<uint64_t>(diff), &meta);
  }

  std::vector<uint8_t> out;
  out.reserve(8 + meta.size() + frame.data.size());
  MoqtVarInt::Append(meta.size(), &out);
  out.insert(out.end(), meta.begin(), meta.end());
  out.insert(out.end(), frame.data.begin(), frame.data.end());
  return out;
}

std::optional<EncodedVideoFrame> LocFramePackager::UnpackPayload(
    ArrayView<const uint8_t> payload) {
  size_t off = 0;
  uint64_t meta_len = 0;
  if (!MoqtVarInt::Read(payload, &off, &meta_len) ||
      off + meta_len > payload.size()) {
    return std::nullopt;
  }

  const ArrayView<const uint8_t> meta_slice =
      payload.subview(off, static_cast<size_t>(meta_len));
  size_t moff = 0;
  uint64_t cap_us = 0;
  uint64_t rtp_ts = 0;
  uint64_t frame_id = 0;
  if (!MoqtVarInt::Read(meta_slice, &moff, &cap_us) ||
      !MoqtVarInt::Read(meta_slice, &moff, &rtp_ts) ||
      !MoqtVarInt::Read(meta_slice, &moff, &frame_id) ||
      moff + 2 > meta_slice.size()) {
    return std::nullopt;
  }

  const uint8_t flags = meta_slice[moff++];
  const uint8_t nrefs = std::min<uint8_t>(meta_slice[moff++], 4);

  EncodedVideoFrame frame;
  frame.capture_time = Timestamp::Micros(static_cast<int64_t>(cap_us));
  frame.rtp_timestamp = static_cast<uint32_t>(rtp_ts);
  frame.codec = (flags & 0x04u) != 0 ? VideoCodec::kH265 : VideoCodec::kH264;
  frame.layer =
      (flags & 0x08u) != 0 ? SpatialLayer::kHigh : SpatialLayer::kLow;
  frame.dep.frame_id = static_cast<int64_t>(frame_id);
  frame.dep.is_keyframe = (flags & 0x01u) != 0;
  frame.dep.discardable = (flags & 0x02u) != 0;
  frame.dep.spatial_id = static_cast<uint8_t>(frame.layer);
  frame.dep.temporal_id = (flags >> 4) & 0x07u;
  frame.dep.num_references = nrefs;
  for (uint8_t i = 0; i < nrefs; ++i) {
    uint64_t diff = 0;
    if (!MoqtVarInt::Read(meta_slice, &moff, &diff)) {
      return std::nullopt;
    }
    frame.dep.references[i] = frame.dep.frame_id - static_cast<int64_t>(diff);
  }

  const size_t bitstream_off = off + static_cast<size_t>(meta_len);
  frame.data.assign(payload.data() + bitstream_off,
                    payload.data() + payload.size());
  return frame;
}

std::vector<uint8_t> LocFramePackager::PackObject(
    uint64_t object_id,
    const EncodedVideoFrame& frame,
    std::optional<uint64_t> prev_object_id) {
  MoqtSubgroupObject sub_obj;
  sub_obj.object_id = object_id;
  sub_obj.status = MoqtObjectStatus::kNormal;
  sub_obj.payload = PackPayload(frame);
  return sub_obj.Encode(prev_object_id, /*header_has_properties=*/false);
}

std::optional<EncodedVideoFrame> LocFramePackager::UnpackObject(
    ArrayView<const uint8_t> data,
    size_t* consumed,
    uint64_t* out_object_id,
    std::optional<uint64_t> prev_object_id) {
  auto sub_obj = MoqtSubgroupObject::Decode(
      data, prev_object_id, /*header_has_properties=*/false, consumed);
  if (!sub_obj.has_value() || sub_obj->status != MoqtObjectStatus::kNormal) {
    return std::nullopt;
  }
  if (out_object_id != nullptr) {
    *out_object_id = sub_obj->object_id;
  }
  return UnpackPayload(sub_obj->payload);
}

// ======================= MoqBweAdapter 带宽估计适配器 =======================

MoqBweAdapter::MoqBweAdapter(DataRate min_bitrate, DataRate max_bitrate)
    : min_bitrate_(min_bitrate), max_bitrate_(max_bitrate) {}

TargetTransferRate MoqBweAdapter::ConvertSnapshot(
    const QuicCongestionSnapshot& snap) const {
  const TimeDelta rtt = std::max(TimeDelta::Millis(2), snap.smoothed_rtt);
  const DataRate cwnd_rate = snap.cwnd / rtt;
  // 优先采用当前可插拔 QUIC 拥塞控制模块的带宽估计值（如 BBRv1/BBRv2 的瓶颈带宽滤波器），
  // 并以 1.0 倍 cwnd/RTT 作为上限，避免流缓冲区膨胀。
  DataRate target = (snap.cc_bandwidth_estimate > DataRate::Zero())
                        ? std::min(snap.cc_bandwidth_estimate, cwnd_rate)
                        : cwnd_rate;
  const bool pipe_saturated =
      (snap.bytes_in_flight.bytes() * 2 >= snap.cwnd.bytes()) ||
      (snap.unsent_stream_bytes > snap.cwnd) ||
      (snap.min_rtt > TimeDelta::Zero() &&
       snap.smoothed_rtt > snap.min_rtt * 1.35 + TimeDelta::Millis(5));
  if (snap.delivery_rate > DataRate::Zero() && pipe_saturated) {
    // 当管道饱和或出现排队时，立即向真实 1-RTT 交付速率收敛，防止 BBR 10 轮最大值窗口在带宽骤降时滞后；
    // 若发送流缓冲区已出现积压或显著驻留排队，则施加 0.90 回推系数加速排空旧队列。
    const bool heavy_queue =
        (snap.unsent_stream_bytes > snap.cwnd) ||
        (snap.min_rtt > TimeDelta::Zero() &&
         snap.smoothed_rtt > snap.min_rtt * 1.60 + TimeDelta::Millis(10));
    const double gain = heavy_queue ? 0.90 : 1.03;
    target = std::min(target, snap.delivery_rate * gain);
    app_limited_probe_rate_ = DataRate::Zero();
    last_probe_step_ = snap.timestamp;
  } else if (!pipe_saturated && snap.unsent_stream_bytes == DataSize::Zero() &&
             snap.recent_loss_ratio < 0.015 && snap.timestamp.IsFinite() &&
             target < cwnd_rate) {
    // 当编码器处于应用受限（如 Simulcast 高清层暂停后仅发送低清层）且管道完全空闲无排队时，
    // 渐进向上试探至 cwnd_rate，以便在物理瓶颈恢复后自动重新唤醒高清层探测真实带宽。
    if (!last_probe_step_.IsFinite()) {
      last_probe_step_ = snap.timestamp;
      app_limited_probe_rate_ = target;
    } else if ((snap.timestamp - last_probe_step_) >= TimeDelta::Millis(200)) {
      last_probe_step_ = snap.timestamp;
      const DataRate base = std::max(target, app_limited_probe_rate_);
      app_limited_probe_rate_ =
          std::min(cwnd_rate, base * 1.25 + DataRate::KilobitsPerSec(60));
    }
    target = std::max(target, std::min(cwnd_rate, app_limited_probe_rate_));
  }
  target = std::clamp(target, min_bitrate_, max_bitrate_);

  TargetTransferRate msg;
  msg.at_time = snap.timestamp;
  msg.target_rate = target;
  msg.stable_target_rate = target * 0.92;
  msg.rtt = rtt;
  msg.loss_rate_ratio = std::clamp(snap.recent_loss_ratio, 0.0, 1.0);
  msg.network_estimate.update_time = snap.timestamp;
  msg.network_estimate.link_capacity = target;
  return msg;
}

// ======================= MoqRelayBackend MoQ draft-17 会话后端 =======================

namespace {

std::unique_ptr<IQuicCongestionController> MakeInitialMoqCc(
    const EngineConfig& config) {
  if (config.custom_quic_cc_factory) {
    auto custom = config.custom_quic_cc_factory->Create(kQuicMaxDatagramSize);
    if (custom) {
      return custom;
    }
  }
  auto builtin = CreateBuiltinQuicCongestionController(config.quic_cc_algo,
                                                       kQuicMaxDatagramSize);
  if (builtin) {
    return builtin;
  }
  return CreateBuiltinQuicCongestionController(RTC_QUIC_CC_BBR,
                                               kQuicMaxDatagramSize);
}

std::shared_ptr<IMoqQuicEngine> BuildDefaultMoqTransportEngine(
    Clock* clock,
    SdkTaskQueues* queues,
    const EngineConfig& config,
    const ParsedMoqUrl& parsed_url) {
  auto raw_quic = std::make_shared<AsioQuicClientEngine>(
      clock, queues->network(), MakeInitialMoqCc(config));
  if (parsed_url.use_webtransport ||
      config.transport_mode == RTC_TRANSPORT_MODE_MOQ_WEBTRANSPORT) {
    return std::make_shared<WebTransportClientEngine>(
        std::move(raw_quic), parsed_url.authority, parsed_url.path,
        std::vector<std::string>{kMoqtDraft17Alpn});
  }
  return raw_quic;
}

std::vector<uint8_t> EncodeAuthTokenValue(std::string_view token) {
  // draft-17 图 5 Token 结构：AliasType = USE_VALUE(0x03), TokenType = 0x00, TokenValue = UTF-8 字节。
  std::vector<uint8_t> out;
  MoqtVarInt::Append(0x03, &out);
  MoqtVarInt::Append(0x00, &out);
  out.insert(out.end(), token.begin(), token.end());
  return out;
}

}  // namespace

ParsedMoqUrl MoqRelayBackend::ParseMoqUrl(std::string_view url) {
  ParsedMoqUrl out;
  if (url.empty()) {
    return out;
  }
  size_t pos = 0;
  const size_t scheme_sep = url.find("://");
  if (scheme_sep != std::string_view::npos) {
    std::string sc(url.substr(0, scheme_sep));
    for (char& c : sc) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    out.scheme = sc;
    out.use_webtransport =
        (sc == "https" || sc == "wt" || sc == "moqt+wt" || sc == "h3");
    out.port = (sc == "moqt" || sc == "https") ? 443 : 4433;
    pos = scheme_sep + 3;
  }

  const size_t slash = url.find('/', pos);
  const std::string_view auth =
      (slash == std::string_view::npos) ? url.substr(pos)
                                        : url.substr(pos, slash - pos);
  if (slash != std::string_view::npos) {
    out.path = std::string(url.substr(slash));
  } else {
    out.path = "/moq";
  }

  const size_t colon = auth.rfind(':');
  if (colon != std::string_view::npos) {
    out.host = std::string(auth.substr(0, colon));
    uint16_t parsed_port = out.port;
    if (ParseUint16(auth.substr(colon + 1), &parsed_port)) {
      out.port = parsed_port;
    }
  } else if (!auth.empty()) {
    out.host = std::string(auth);
  }
  out.authority = out.host + ":" + std::to_string(out.port);
  return out;
}

MoqRelayBackend::MoqRelayBackend(Clock* clock,
                                 SdkTaskQueues* queues,
                                 const EngineConfig& config,
                                 ISessionBackendObserver* observer,
                                 std::shared_ptr<IMoqQuicEngine> quic_engine)
    : clock_(clock),
      queues_(queues),
      config_(config),
      observer_(observer),
      parsed_url_(ParseMoqUrl(config.signaling_or_moq_url)),
      quic_engine_(quic_engine ? std::move(quic_engine)
                               : BuildDefaultMoqTransportEngine(
                                     clock, queues, config, parsed_url_)),
      bwe_adapter_(DataRate::BitsPerSec(config.min_bitrate_bps),
                   DataRate::BitsPerSec(config.max_bitrate_bps)),
      work_checker_(queues->worker()),
      safety_(PendingTaskSafetyFlag::CreateDetached()) {
  if (quic_engine_) {
    quic_engine_->SetObserver(this);
  }
}

MoqRelayBackend::~MoqRelayBackend() { StopSession(); }

uint64_t MoqRelayBackend::AllocateClientRequestId() {
  const uint64_t id = next_client_request_id_;
  next_client_request_id_ += 2;
  return id;
}

std::string MoqRelayBackend::ExtractPeerIdFromIdOrSlash(
    std::string_view track_or_peer_id) const {
  const std::string room_pfx = room_id_ + "/";
  if (track_or_peer_id.size() > room_pfx.size() &&
      track_or_peer_id.substr(0, room_pfx.size()) == room_pfx) {
    return std::string(track_or_peer_id.substr(room_pfx.size()));
  }
  const size_t last_slash = track_or_peer_id.rfind('/');
  if (last_slash != std::string_view::npos &&
      last_slash + 1 < track_or_peer_id.size()) {
    return std::string(track_or_peer_id.substr(last_slash + 1));
  }
  return std::string(track_or_peer_id);
}

int MoqRelayBackend::StartSession(const std::string& room_id,
                                  const std::string& local_peer_id) {
  if (!quic_engine_) {
    RTC_LOG(kError) << "MoqRelayBackend started without IMoqQuicEngine";
    return RTC_ERR_NOT_INITIALIZED;
  }
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, room_id, local_peer_id]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        room_id_ = room_id;
        local_peer_id_ = local_peer_id;
        last_stats_time_ = clock_->CurrentTime();
        if (observer_ != nullptr) {
          observer_->OnBackendConnectionState(RTC_CONN_STATE_CONNECTING, 0);
        }
        RTC_LOG(kInfo) << "Connecting MOQT draft-17 session to "
                       << parsed_url_.scheme << "://" << parsed_url_.authority
                       << parsed_url_.path << " (webtransport="
                       << (quic_engine_->is_webtransport() ? "true" : "false")
                       << ", room=" << room_id_ << ", peer=" << local_peer_id_
                       << ")";
        quic_engine_->Connect(
            parsed_url_.host, parsed_url_.port,
            quic_engine_->is_webtransport() ? kHttp3Alpn : kMoqtDraft17Alpn);
        OnPeriodicMaintenanceTick();
      }));
  return RTC_OK;
}

void MoqRelayBackend::StopSession() {
  if (queues_->worker()->IsStopped()) {
    return;
  }
  queues_->worker()->Invoke([this]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    safety_.flag()->SetNotAlive();
    if (quic_engine_) {
      if (connected_) {
        // draft-17 第 3.3.1 节与第 9.5 节：重置所有活跃双向请求流并在控制流上发送 GOAWAY 后关闭会话。
        for (const auto& [cid, dch] : data_channels_) {
          (void)cid;
          if (dch.publish_ns_stream_id.has_value()) {
            quic_engine_->ResetStream(*dch.publish_ns_stream_id, 0);
          }
        }
        if (pub_video_ns_stream_id_ != 0 ||
            outbound_requests_.count(pub_video_ns_stream_id_) > 0) {
          quic_engine_->ResetStream(pub_video_ns_stream_id_, 0);
        }
        MoqControlMessage goaway;
        goaway.type = MoqControlMessageType::kGoaway;
        goaway.goaway_timeout_ms = 0;
        quic_engine_->WriteStream(local_control_stream_id_, goaway.Encode(),
                                  /*fin=*/false);
      }
      quic_engine_->Close(kMoqtErrNoError);
    }
    connected_ = false;
    peer_setup_received_ = false;
    outbound_requests_.clear();
    inbound_requests_.clear();
    inbound_uni_streams_.clear();
    subscriptions_.clear();
    alias_to_track_id_.clear();
    data_channels_.clear();
    label_to_dc_id_.clear();
    notified_remote_dc_peers_.clear();
    ttl_data_streams_.clear();
    {
      std::lock_guard<std::mutex> lock(dc_handles_mu_);
      valid_dc_ids_.clear();
    }
  });
}

void MoqRelayBackend::OnQuicConnected() {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    connected_ = true;
    next_client_request_id_ = 0;

    // 1. 打开持久化单向控制流并发送 draft-17 SETUP (0x2F00) 消息。
    local_control_stream_id_ = quic_engine_->OpenUnidirectionalStream(
        /*publisher_priority=*/0, std::numeric_limits<int64_t>::max());
    MoqControlMessage setup;
    setup.type = MoqControlMessageType::kSetup;
    if (!quic_engine_->is_webtransport()) {
      // draft-17 第 9.4.1.1 / 9.4.1.2 节：仅原生 QUIC 模式携带 AUTHORITY 与 PATH，WebTransport 严禁携带。
      setup.setup_options.push_back(MoqtKeyValuePair::MakeString(
          kMoqtSetupOptionPath, parsed_url_.path));
      setup.setup_options.push_back(MoqtKeyValuePair::MakeString(
          kMoqtSetupOptionAuthority, parsed_url_.authority));
    }
    if (!config_.auth_token.empty()) {
      const auto tok = EncodeAuthTokenValue(config_.auth_token);
      setup.setup_options.push_back(
          MoqtKeyValuePair::MakeBytes(kMoqtSetupOptionAuthToken, tok));
    }
    setup.setup_options.push_back(MoqtKeyValuePair::MakeString(
        kMoqtSetupOptionImplementation, "RTCSDK-moqt-17"));
    quic_engine_->WriteStream(local_control_stream_id_, setup.Encode(),
                              /*fin=*/false);

    // 2. 打开双向请求流发送 SUBSCRIBE_NAMESPACE (0x11) 订阅当前房间内所有发布者命名空间。
    sub_ns_stream_id_ = quic_engine_->OpenBidirectionalStream();
    MoqControlMessage sub_ns;
    sub_ns.type = MoqControlMessageType::kSubscribeNamespace;
    sub_ns.request_id = AllocateClientRequestId();
    sub_ns.track_namespace = MoqtTrackNamespace::MakeRoomPrefix(room_id_);
    sub_ns.subscribe_options = 0x01;  // 请求 NAMESPACE 增量通知
    OutboundBidiRequestState sub_ns_st;
    sub_ns_st.kind = OutboundRequestKind::kSubscribeNamespace;
    sub_ns_st.stream_id = sub_ns_stream_id_;
    sub_ns_st.request_id = sub_ns.request_id;
    outbound_requests_[sub_ns_stream_id_] = std::move(sub_ns_st);
    quic_engine_->WriteStream(sub_ns_stream_id_, sub_ns.Encode(),
                              /*fin=*/false);

    // 3. 打开双向请求流发送 PUBLISH_NAMESPACE (0x06) 声明本端视频轨道命名空间。
    pub_video_ns_stream_id_ = quic_engine_->OpenBidirectionalStream();
    MoqControlMessage pub_ns;
    pub_ns.type = MoqControlMessageType::kPublishNamespace;
    pub_ns.request_id = AllocateClientRequestId();
    pub_ns.track_namespace =
        MoqtTrackNamespace::MakePeerNamespace(room_id_, local_peer_id_);
    pub_ns.track_namespace.fields.push_back("video");
    pub_ns.track_namespace.fields.push_back(
        config_.publish_codec == RTC_CODEC_H265 ? "h265" : "h264");
    OutboundBidiRequestState pub_ns_st;
    pub_ns_st.kind = OutboundRequestKind::kPublishVideoNamespace;
    pub_ns_st.stream_id = pub_video_ns_stream_id_;
    pub_ns_st.request_id = pub_ns.request_id;
    outbound_requests_[pub_video_ns_stream_id_] = std::move(pub_ns_st);
    quic_engine_->WriteStream(pub_video_ns_stream_id_, pub_ns.Encode(),
                              /*fin=*/false);

    // 4. 若启用了数据通道，则订阅房间级数据轨道并声明已预创建的本地数据通道命名空间。
    if (config_.enable_datachannel) {
      sub_data_stream_id_ = quic_engine_->OpenBidirectionalStream();
      MoqControlMessage sub_data;
      sub_data.type = MoqControlMessageType::kSubscribe;
      sub_data.request_id = AllocateClientRequestId();
      sub_data.track_namespace =
          MoqtTrackNamespace::MakePeerNamespace(room_id_, "*");
      sub_data.track_name = "data";
      sub_data.parameters.subscriber_priority = 8;
      sub_data.parameters.subscription_filter =
          MoqtSubscriptionFilter{MoqFilterType::kLargestObject, {}, 0};
      OutboundBidiRequestState sdata_st;
      sdata_st.kind = OutboundRequestKind::kSubscribeData;
      sdata_st.stream_id = sub_data_stream_id_;
      sdata_st.request_id = sub_data.request_id;
      outbound_requests_[sub_data_stream_id_] = std::move(sdata_st);
      quic_engine_->WriteStream(sub_data_stream_id_, sub_data.Encode(),
                                /*fin=*/false);

      for (auto& [cid, dch] : data_channels_) {
        if (dch.state == RTC_DATA_CHANNEL_CLOSED) {
          continue;
        }
        if (dch.local_created && !dch.announced) {
          AnnounceDataChannelNamespaceOnWorker(&dch);
        }
        dch.state = RTC_DATA_CHANNEL_OPEN;
        if (!dch.local_open_notified && observer_ != nullptr) {
          dch.local_open_notified = true;
          observer_->OnBackendDataChannelState(
              local_peer_id_, cid, dch.config.label, RTC_DATA_CHANNEL_OPEN);
        }
        while (!dch.pending_messages.empty()) {
          PendingMoqDataMsg msg = std::move(dch.pending_messages.front());
          dch.pending_messages.pop_front();
          TransmitMoqDataMessageOnWorker(cid, msg.payload, msg.is_binary,
                                         /*is_close=*/false);
        }
      }
    }

    for (auto& [tid, sub_ctx] : subscriptions_) {
      (void)tid;
      SendSubscribePairForTrack(sub_ctx.get());
    }

    RTC_LOG(kInfo) << "MOQT draft-17 session connected (ALPN="
                   << quic_engine_->negotiated_alpn() << ", namespace="
                   << pub_ns.track_namespace.ToSlashString() << ")";
    if (observer_ != nullptr) {
      observer_->OnBackendConnectionState(RTC_CONN_STATE_CONNECTED, 0);
    }
  }));
}

void MoqRelayBackend::OnQuicDisconnected(int error_code) {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this, error_code]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    connected_ = false;
    RTC_LOG(kWarning) << "MOQT draft-17 session disconnected (code="
                      << error_code << ")";
    if (observer_ != nullptr) {
      observer_->OnBackendConnectionState(RTC_CONN_STATE_DISCONNECTED,
                                          error_code);
    }
  }));
}

void MoqRelayBackend::SetLayerActive(SpatialLayer layer, bool active) {
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, layer, active]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const size_t idx = (layer == SpatialLayer::kHigh) ? 1 : 0;
        const bool was_active = layer_active_[idx];
        layer_active_[idx] = active;
        if (!was_active && active && observer_ != nullptr) {
          observer_->OnBackendForceKeyFrame(layer);
        }
      }));
}

int MoqRelayBackend::SendEncodedFrame(EncodedVideoFrame frame) {
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, f = std::move(frame)]() mutable {
        RTC_DCHECK_RUN_ON(&work_checker_);
        if (!connected_ || !quic_engine_) {
          return;
        }

        const size_t layer_idx = (f.layer == SpatialLayer::kHigh) ? 1 : 0;
        if (config_.enable_simulcast && !layer_active_[layer_idx]) {
          return;
        }
        const Timestamp now = clock_->CurrentTime();

        const int64_t fid = ++next_frame_id_[layer_idx];
        f.dep.frame_id = fid;
        if (f.dep.is_keyframe) {
          f.dep.num_references = 0;
        } else if (fid > 1) {
          f.dep.num_references = 1;
          f.dep.references[0] = fid - 1;
        }

        if (active_group_[layer_idx].has_value()) {
          auto& prev_grp = *active_group_[layer_idx];
          const QuicCongestionSnapshot qsnap =
              quic_engine_->GetCongestionSnapshot();
          const DataRate drain_rate = std::max(
              DataRate::KilobitsPerSec(150),
              qsnap.delivery_rate > DataRate::Zero() ? qsnap.delivery_rate
                                                     : qsnap.pacing_rate);
          const TimeDelta est_delivery_delay =
              qsnap.smoothed_rtt + (qsnap.unsent_stream_bytes / drain_rate);
          // 仅当 GOP 持续时间与实际排队时延均超过 moq_delivery_timeout_ms 时才判定为投递超时，
          // 使用 draft-17 表 16 DELIVERY_TIMEOUT (0x02) 错误码重置旧子组流。
          const bool expired =
              (now - prev_grp.started_at) >
                  TimeDelta::Millis(config_.moq_delivery_timeout_ms) &&
              est_delivery_delay >
                  TimeDelta::Millis(config_.moq_delivery_timeout_ms);
          if (f.dep.is_keyframe) {
            for (const auto& [tid, sg_st] : prev_grp.subgroup_streams) {
              (void)tid;
              if (expired) {
                quic_engine_->ResetStream(sg_st.stream_id, 0x02);
                ++streams_reset_on_timeout_;
              } else {
                quic_engine_->WriteStream(
                    sg_st.stream_id, ArrayView<const uint8_t>(), /*fin=*/true);
              }
            }
            active_group_[layer_idx].reset();
          } else if (expired) {
            RTC_LOG(kWarning)
                << "MOQT GOP group_id=" << prev_grp.group_id
                << " exceeded delivery_timeout_ms="
                << config_.moq_delivery_timeout_ms
                << ", issuing RESET_STREAM(DELIVERY_TIMEOUT=0x02) and IDR";
            for (const auto& [tid, sg_st] : prev_grp.subgroup_streams) {
              (void)tid;
              quic_engine_->ResetStream(sg_st.stream_id, 0x02);
              ++streams_reset_on_timeout_;
            }
            active_group_[layer_idx].reset();
            if (observer_ != nullptr) {
              observer_->OnBackendForceKeyFrame(f.layer);
            }
            return;
          }
        }

        if (!active_group_[layer_idx].has_value()) {
          if (!f.dep.is_keyframe) {
            if (observer_ != nullptr) {
              observer_->OnBackendForceKeyFrame(f.layer);
            }
            return;
          }
          ActiveOutboundGroup grp;
          grp.group_id = ++current_group_id_[layer_idx];
          grp.next_object_id = 0;
          grp.started_at = now;
          active_group_[layer_idx] = std::move(grp);
        }

        auto& grp = *active_group_[layer_idx];
        const uint8_t tid = f.dep.temporal_id;
        auto sg_it = grp.subgroup_streams.find(tid);
        if (sg_it == grp.subgroup_streams.end()) {
          const uint8_t pub_prio =
              static_cast<uint8_t>((layer_idx == 0 ? 16 : 32) + tid * 8);
          const int64_t send_order =
              static_cast<int64_t>(grp.group_id * 100) +
              (layer_idx == 0 ? 50 : 20) - tid;
          const uint64_t sid =
              quic_engine_->OpenUnidirectionalStream(pub_prio, send_order);

          MoqSubgroupHeader shdr;
          shdr.track_alias = layer_idx + 1;
          shdr.group_id = grp.group_id;
          shdr.subgroup_id = tid;
          shdr.publisher_priority = pub_prio;
          const auto hdr_bytes = shdr.Encode();
          quic_engine_->WriteStream(sid, hdr_bytes, /*fin=*/false);

          sg_it =
              grp.subgroup_streams
                  .emplace(tid, OutboundSubgroupStream{sid, std::nullopt})
                  .first;
        }

        const uint64_t obj_id = grp.next_object_id++;
        const auto obj_wire =
            LocFramePackager::PackObject(obj_id, f, sg_it->second.prev_object_id);
        sg_it->second.prev_object_id = obj_id;
        quic_engine_->WriteStream(sg_it->second.stream_id, obj_wire,
                                  /*fin=*/false);
      }));
  return RTC_OK;
}

void MoqRelayBackend::SendSubscribePairForTrack(SubscribedTrackContext* ctx) {
  if (ctx == nullptr || !connected_ || !quic_engine_) {
    return;
  }
  // 使用 draft-17 标准 SUBSCRIBE + FORWARD(0/1) 双空间层双向请求流订阅，支持零间隙 GOP 对齐层切换。
  auto open_layer_sub = [&](SpatialLayer layer, OutboundRequestKind kind) {
    const uint64_t sid = quic_engine_->OpenBidirectionalStream();
    MoqControlMessage sub;
    sub.type = MoqControlMessageType::kSubscribe;
    sub.request_id = AllocateClientRequestId();
    sub.track_namespace = ctx->remote_namespace;
    sub.track_name =
        (layer == SpatialLayer::kLow) ? "video/low" : "video/high";
    sub.parameters.delivery_timeout_ms = config_.moq_delivery_timeout_ms;
    sub.parameters.forward = (ctx->preferred_layer == layer) ? 1 : 0;
    sub.parameters.subscriber_priority =
        (layer == SpatialLayer::kLow) ? 16 : 32;
    sub.parameters.subscription_filter =
        MoqtSubscriptionFilter{MoqFilterType::kNextGroupStart, {}, 0};
    if (ctx->preferred_layer == layer) {
      sub.parameters.new_group_request = 0;
    }

    OutboundBidiRequestState rst;
    rst.kind = kind;
    rst.stream_id = sid;
    rst.request_id = sub.request_id;
    rst.target_track_id = ctx->track_id;
    outbound_requests_[sid] = std::move(rst);
    quic_engine_->WriteStream(sid, sub.Encode(), /*fin=*/false);
    return sid;
  };

  ctx->low_req_stream_id =
      open_layer_sub(SpatialLayer::kLow, OutboundRequestKind::kSubscribeVideoLow);
  ctx->high_req_stream_id = open_layer_sub(
      SpatialLayer::kHigh, OutboundRequestKind::kSubscribeVideoHigh);
}

int MoqRelayBackend::SubscribeRemoteTrack(const std::string& track_id,
                                          SpatialLayer preferred_layer) {
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, track_id, preferred_layer]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const std::string canonical_id = ExtractPeerIdFromIdOrSlash(track_id);
        auto ctx = std::make_unique<SubscribedTrackContext>(
            clock_->CurrentTime(), config_.zero_playout_delay);
        ctx->track_id = canonical_id;
        ctx->remote_namespace =
            MoqtTrackNamespace::MakePeerNamespace(room_id_, canonical_id);
        ctx->preferred_layer = preferred_layer;
        SubscribedTrackContext* raw_ctx = ctx.get();
        subscriptions_[canonical_id] = std::move(ctx);

        if (connected_ && quic_engine_) {
          SendSubscribePairForTrack(raw_ctx);
        }
        RTC_LOG(kInfo) << "MOQT draft-17 subscribed track=" << canonical_id
                       << " namespace="
                       << raw_ctx->remote_namespace.ToSlashString()
                       << " layer="
                       << (preferred_layer == SpatialLayer::kHigh ? "HIGH"
                                                                  : "LOW");
      }));
  return RTC_OK;
}

int MoqRelayBackend::SwitchSubscribedLayer(const std::string& track_id,
                                           SpatialLayer preferred_layer) {
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, track_id, preferred_layer]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const std::string canonical_id = ExtractPeerIdFromIdOrSlash(track_id);
        const auto it = subscriptions_.find(canonical_id);
        if (it == subscriptions_.end()) {
          return;
        }
        SubscribedTrackContext* ctx = it->second.get();
        ctx->preferred_layer = preferred_layer;
        if (!connected_ || !quic_engine_) {
          return;
        }

        const uint64_t next_grp_req =
            ctx->has_received_group ? (ctx->largest_group_seen + 1) : 0;

        // 在目标空间层的 SUBSCRIBE 双向流上发送 REQUEST_UPDATE(FORWARD=1, NEW_GROUP_REQUEST)，
        // 并在旧空间层的双向流上发送 REQUEST_UPDATE(FORWARD=0)。
        MoqControlMessage activate_upd;
        activate_upd.type = MoqControlMessageType::kRequestUpdate;
        activate_upd.request_id = AllocateClientRequestId();
        activate_upd.parameters.forward = 1;
        activate_upd.parameters.new_group_request = next_grp_req;

        MoqControlMessage pause_upd;
        pause_upd.type = MoqControlMessageType::kRequestUpdate;
        pause_upd.request_id = AllocateClientRequestId();
        pause_upd.parameters.forward = 0;

        const uint64_t active_sid = (preferred_layer == SpatialLayer::kHigh)
                                        ? ctx->high_req_stream_id
                                        : ctx->low_req_stream_id;
        const uint64_t paused_sid = (preferred_layer == SpatialLayer::kHigh)
                                        ? ctx->low_req_stream_id
                                        : ctx->high_req_stream_id;
        quic_engine_->WriteStream(active_sid, activate_upd.Encode(),
                                  /*fin=*/false);
        quic_engine_->WriteStream(paused_sid, pause_upd.Encode(),
                                  /*fin=*/false);

        RTC_LOG(kInfo) << "MOQT draft-17 sent REQUEST_UPDATE layer switch on "
                       << canonical_id << " -> "
                       << (preferred_layer == SpatialLayer::kHigh ? "HIGH"
                                                                  : "LOW");
      }));
  return RTC_OK;
}

int MoqRelayBackend::UnsubscribeRemoteTrack(const std::string& track_id) {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this, track_id]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    const std::string canonical_id = ExtractPeerIdFromIdOrSlash(track_id);
    const auto it = subscriptions_.find(canonical_id);
    if (it == subscriptions_.end()) {
      return;
    }
    SubscribedTrackContext* ctx = it->second.get();
    if (connected_ && quic_engine_) {
      // draft-17 第 5.1 节：订阅端通过发送 STOP_SENDING / RESET_STREAM 终止双向请求流以取消订阅。
      for (uint64_t sid : {ctx->low_req_stream_id, ctx->high_req_stream_id}) {
        quic_engine_->StopSending(sid, 0);
        quic_engine_->ResetStream(sid, 0);
        outbound_requests_.erase(sid);
      }
    }
    if (ctx->low_track_alias.has_value()) {
      alias_to_track_id_.erase(*ctx->low_track_alias);
    }
    if (ctx->high_track_alias.has_value()) {
      alias_to_track_id_.erase(*ctx->high_track_alias);
    }
    subscriptions_.erase(it);
  }));
  return RTC_OK;
}

int MoqRelayBackend::RequestRemoteKeyFrame(const std::string& track_id) {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this, track_id]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    const std::string canonical_id = ExtractPeerIdFromIdOrSlash(track_id);
    const auto it = subscriptions_.find(canonical_id);
    if (it == subscriptions_.end() || !connected_ || !quic_engine_) {
      return;
    }
    SubscribedTrackContext* ctx = it->second.get();
    const uint64_t active_sid = (ctx->preferred_layer == SpatialLayer::kLow)
                                    ? ctx->low_req_stream_id
                                    : ctx->high_req_stream_id;
    // draft-17 第 9.3.11 节：在订阅双向流上发送携带 NEW_GROUP_REQUEST 参数的 REQUEST_UPDATE 请求新关键帧组。
    MoqControlMessage upd;
    upd.type = MoqControlMessageType::kRequestUpdate;
    upd.request_id = AllocateClientRequestId();
    upd.parameters.new_group_request =
        ctx->has_received_group ? (ctx->largest_group_seen + 1) : 0;
    ++keyframe_requests_sent_;
    quic_engine_->WriteStream(active_sid, upd.Encode(), /*fin=*/false);
  }));
  return RTC_OK;
}

int MoqRelayBackend::EnsureDataChannelForLabelOnWorker(
    const std::string& label,
    const DataChannelConfig* explicit_cfg) {
  RTC_DCHECK_RUN_ON(&work_checker_);
  const std::string norm_label = label.empty() ? "data" : label;
  const auto existing_it = label_to_dc_id_.find(norm_label);
  if (existing_it != label_to_dc_id_.end()) {
    const int cid = existing_it->second;
    auto& st = data_channels_[cid];
    if (explicit_cfg != nullptr) {
      st.config = *explicit_cfg;
      st.config.label = norm_label;
      st.local_created = true;
    }
    if (st.state == RTC_DATA_CHANNEL_CLOSED) {
      st.state =
          connected_ ? RTC_DATA_CHANNEL_OPEN : RTC_DATA_CHANNEL_CONNECTING;
      st.local_open_notified = false;
      std::lock_guard<std::mutex> lock(dc_handles_mu_);
      valid_dc_ids_.insert(cid);
    }
    return cid;
  }

  int cid = next_dc_id_++;
  if (explicit_cfg != nullptr && explicit_cfg->negotiated &&
      explicit_cfg->id >= 0 &&
      data_channels_.find(explicit_cfg->id) == data_channels_.end()) {
    cid = explicit_cfg->id;
    next_dc_id_ = std::max(next_dc_id_, cid + 1);
  }

  MoqDataChannelState st;
  st.channel_id = cid;
  if (explicit_cfg != nullptr) {
    st.config = *explicit_cfg;
    st.local_created = true;
  }
  st.config.label = norm_label;
  st.state = connected_ ? RTC_DATA_CHANNEL_OPEN : RTC_DATA_CHANNEL_CONNECTING;
  data_channels_.emplace(cid, std::move(st));
  label_to_dc_id_[norm_label] = cid;
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    valid_dc_ids_.insert(cid);
  }
  return cid;
}

void MoqRelayBackend::AnnounceDataChannelNamespaceOnWorker(
    MoqDataChannelState* dch) {
  if (dch == nullptr || dch->announced || !connected_ || !quic_engine_) {
    return;
  }
  const uint64_t sid = quic_engine_->OpenBidirectionalStream();
  MoqControlMessage pub_ns;
  pub_ns.type = MoqControlMessageType::kPublishNamespace;
  pub_ns.request_id = AllocateClientRequestId();
  pub_ns.track_namespace =
      MoqtTrackNamespace::MakePeerNamespace(room_id_, local_peer_id_);
  pub_ns.track_namespace.fields.push_back("data");
  pub_ns.track_namespace.fields.push_back(dch->config.label);

  OutboundBidiRequestState st;
  st.kind = OutboundRequestKind::kPublishDataNamespace;
  st.stream_id = sid;
  st.request_id = pub_ns.request_id;
  st.data_label = dch->config.label;
  outbound_requests_[sid] = std::move(st);

  quic_engine_->WriteStream(sid, pub_ns.Encode(), /*fin=*/false);
  dch->publish_ns_stream_id = sid;
  dch->announced = true;
}

void MoqRelayBackend::TransmitMoqDataMessageOnWorker(
    int channel_id,
    ArrayView<const uint8_t> payload,
    bool is_binary,
    bool is_close) {
  RTC_DCHECK_RUN_ON(&work_checker_);
  const auto it = data_channels_.find(channel_id);
  if (it == data_channels_.end() || !connected_ || !quic_engine_) {
    return;
  }
  MoqDataChannelState& dch = it->second;
  if (!dch.announced && !is_close) {
    AnnounceDataChannelNamespaceOnWorker(&dch);
  }

  const Timestamp now = clock_->CurrentTime();
  MoqDataObject obj;
  obj.object_id = dch.next_object_id++;
  obj.sender_peer_id = local_peer_id_;
  obj.label = dch.config.label;
  obj.protocol = dch.config.protocol;
  obj.timestamp_us = static_cast<uint64_t>(now.us());
  obj.is_binary = is_binary;
  obj.ordered = dch.config.ordered;
  obj.is_close = is_close;
  obj.payload.assign(payload.begin(), payload.end());
  const auto packed_data = MoqDataPackager::PackObject(obj);

  const bool persistent_ordered =
      dch.config.ordered && dch.config.max_packet_lifetime_ms < 0 &&
      dch.config.max_retransmits < 0 && !is_close;

  // 若通道配置为无序零重传（max_retransmits == 0）且负载尺寸不超过单包数据报上限，
  // 直接使用 draft-17 OBJECT_DATAGRAM 承载于 QUIC/WebTransport 不可靠数据报上以获得零队头阻塞延迟。
  const size_t max_dgram = quic_engine_->max_datagram_size();
  if (!dch.config.ordered && dch.config.max_retransmits == 0 && !is_close &&
      max_dgram > 32 && packed_data.size() + 24 <= max_dgram) {
    MoqtObjectDatagram dg;
    dg.track_alias = kMoqUpstreamDataTrackAlias;
    dg.group_id = static_cast<uint64_t>(channel_id + 1);
    dg.object_id = obj.object_id;
    dg.publisher_priority = 10;
    dg.payload = packed_data;
    if (quic_engine_->SendDatagram(dg.Encode()) == RTC_OK) {
      return;
    }
  }

  MoqtSubgroupObject sg_obj;
  sg_obj.object_id = obj.object_id;
  sg_obj.status = MoqtObjectStatus::kNormal;
  sg_obj.payload = packed_data;

  if (persistent_ordered) {
    if (!dch.ordered_stream_id.has_value()) {
      const int64_t send_order =
          (int64_t{1} << 50) - static_cast<int64_t>(channel_id);
      const uint64_t sid = quic_engine_->OpenUnidirectionalStream(
          /*publisher_priority=*/8, send_order);
      dch.ordered_stream_id = sid;
      dch.ordered_prev_obj_id.reset();
      MoqSubgroupHeader shdr;
      shdr.track_alias = kMoqUpstreamDataTrackAlias;
      shdr.group_id = static_cast<uint64_t>(channel_id + 1);
      shdr.subgroup_id = 0;
      shdr.publisher_priority = 8;
      quic_engine_->WriteStream(sid, shdr.Encode(), /*fin=*/false);
    }
    const auto wire = sg_obj.Encode(dch.ordered_prev_obj_id, false);
    dch.ordered_prev_obj_id = obj.object_id;
    quic_engine_->WriteStream(*dch.ordered_stream_id, wire, /*fin=*/false);
  } else {
    const int64_t send_order =
        (int64_t{1} << 48) + static_cast<int64_t>(obj.object_id);
    const uint64_t sid = quic_engine_->OpenUnidirectionalStream(
        /*publisher_priority=*/10, send_order);
    MoqSubgroupHeader shdr;
    shdr.track_alias = kMoqUpstreamDataTrackAlias;
    shdr.group_id = static_cast<uint64_t>(channel_id + 1);
    shdr.subgroup_id = obj.object_id + 1;
    shdr.publisher_priority = 10;
    shdr.end_of_group = true;
    std::vector<uint8_t> combined = shdr.Encode();
    const auto obj_wire = sg_obj.Encode(std::nullopt, false);
    combined.insert(combined.end(), obj_wire.begin(), obj_wire.end());
    quic_engine_->WriteStream(sid, combined, /*fin=*/true);

    if (!is_close && (dch.config.max_packet_lifetime_ms >= 0 ||
                      dch.config.max_retransmits >= 0)) {
      const auto snap = quic_engine_->GetCongestionSnapshot();
      const int64_t ttl_ms =
          (dch.config.max_packet_lifetime_ms >= 0)
              ? dch.config.max_packet_lifetime_ms
              : std::max<int64_t>(
                    25,
                    snap.smoothed_rtt.ms() * (1 + dch.config.max_retransmits));
      ttl_data_streams_.emplace_back(sid, now + TimeDelta::Millis(ttl_ms));
    }
  }
}

int MoqRelayBackend::CreateDataChannel(const DataChannelConfig& config) {
  if (!config_.enable_datachannel) {
    return RTC_ERR_PROTOCOL;
  }
  if (config.negotiated && config.id < 0) {
    return RTC_ERR_INVALID_ARG;
  }
  int cid = RTC_ERR_INTERNAL;
  queues_->worker()->Invoke([this, &config, &cid]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    cid = EnsureDataChannelForLabelOnWorker(config.label, &config);
    auto& dch = data_channels_[cid];
    if (connected_ && quic_engine_) {
      AnnounceDataChannelNamespaceOnWorker(&dch);
      dch.state = RTC_DATA_CHANNEL_OPEN;
      if (!dch.local_open_notified && observer_ != nullptr) {
        dch.local_open_notified = true;
        observer_->OnBackendDataChannelState(
            local_peer_id_, cid, dch.config.label, RTC_DATA_CHANNEL_OPEN);
      }
    }
  });
  return cid;
}

int MoqRelayBackend::SendData(int channel_id,
                              ArrayView<const uint8_t> payload,
                              bool is_binary) {
  if (!config_.enable_datachannel) {
    return RTC_ERR_PROTOCOL;
  }
  if (channel_id < 0 || (payload.size() > 0 && payload.data() == nullptr)) {
    return RTC_ERR_INVALID_ARG;
  }
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    if (valid_dc_ids_.find(channel_id) == valid_dc_ids_.end()) {
      return RTC_ERR_INVALID_ARG;
    }
  }
  std::vector<uint8_t> copy(payload.begin(), payload.end());
  queues_->worker()->PostTask(SafeTask(
      safety_.flag(),
      [this, channel_id, buf = std::move(copy), is_binary]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const auto it = data_channels_.find(channel_id);
        if (it == data_channels_.end() ||
            it->second.state == RTC_DATA_CHANNEL_CLOSED) {
          return;
        }
        if (!connected_ || !quic_engine_) {
          if (it->second.pending_messages.size() < 512) {
            it->second.pending_messages.push_back(
                PendingMoqDataMsg{std::move(buf), is_binary});
          }
          return;
        }
        TransmitMoqDataMessageOnWorker(channel_id, buf, is_binary,
                                       /*is_close=*/false);
      }));
  return RTC_OK;
}

int MoqRelayBackend::CloseDataChannel(int channel_id) {
  if (!config_.enable_datachannel) {
    return RTC_ERR_PROTOCOL;
  }
  if (channel_id < 0) {
    return RTC_ERR_INVALID_ARG;
  }
  {
    std::lock_guard<std::mutex> lock(dc_handles_mu_);
    if (valid_dc_ids_.find(channel_id) == valid_dc_ids_.end()) {
      return RTC_ERR_INVALID_ARG;
    }
    valid_dc_ids_.erase(channel_id);
  }
  queues_->worker()->Invoke([this, channel_id]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    const auto it = data_channels_.find(channel_id);
    if (it == data_channels_.end() ||
        it->second.state == RTC_DATA_CHANNEL_CLOSED) {
      return;
    }
    MoqDataChannelState& dch = it->second;
    const std::string label = dch.config.label;
    if (connected_ && quic_engine_) {
      TransmitMoqDataMessageOnWorker(channel_id, ArrayView<const uint8_t>(),
                                     /*is_binary=*/true, /*is_close=*/true);
      if (dch.ordered_stream_id.has_value()) {
        quic_engine_->WriteStream(*dch.ordered_stream_id,
                                  ArrayView<const uint8_t>(), /*fin=*/true);
        dch.ordered_stream_id.reset();
        dch.ordered_prev_obj_id.reset();
      }
      if (dch.publish_ns_stream_id.has_value()) {
        quic_engine_->ResetStream(*dch.publish_ns_stream_id, 0);
        outbound_requests_.erase(*dch.publish_ns_stream_id);
        dch.publish_ns_stream_id.reset();
      }
      dch.announced = false;
    }
    dch.pending_messages.clear();
    dch.state = RTC_DATA_CHANNEL_CLOSED;
    label_to_dc_id_.erase(label);
    for (auto np_it = notified_remote_dc_peers_.begin();
         np_it != notified_remote_dc_peers_.end();) {
      if (np_it->second == channel_id) {
        np_it = notified_remote_dc_peers_.erase(np_it);
      } else {
        ++np_it;
      }
    }
    data_channels_.erase(it);
    if (observer_ != nullptr) {
      observer_->OnBackendDataChannelState(local_peer_id_, channel_id, label,
                                           RTC_DATA_CHANNEL_CLOSED);
    }
  });
  return RTC_OK;
}

int MoqRelayBackend::SetQuicCongestionControl(rtc_quic_cc_algo_e algo) {
  if (!quic_engine_) {
    return RTC_ERR_NOT_INITIALIZED;
  }
  auto cc = CreateBuiltinQuicCongestionController(algo, kQuicMaxDatagramSize);
  if (!cc) {
    return RTC_ERR_INVALID_ARG;
  }
  return quic_engine_->SetCongestionController(std::move(cc));
}

int MoqRelayBackend::SetCustomQuicCongestionController(
    std::shared_ptr<IQuicCongestionControllerFactory> factory) {
  if (!factory) {
    return RTC_ERR_INVALID_ARG;
  }
  if (!quic_engine_) {
    return RTC_ERR_NOT_INITIALIZED;
  }
  auto cc = factory->Create(kQuicMaxDatagramSize);
  if (!cc) {
    return RTC_ERR_INVALID_ARG;
  }
  return quic_engine_->SetCongestionController(std::move(cc));
}

void MoqRelayBackend::OnStreamOpened(uint64_t stream_id, bool unidirectional) {
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, stream_id, unidirectional]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        if (unidirectional) {
          inbound_uni_streams_.try_emplace(stream_id);
        } else if (outbound_requests_.find(stream_id) ==
                   outbound_requests_.end()) {
          inbound_requests_.try_emplace(stream_id);
        }
      }));
}

void MoqRelayBackend::OnStreamData(uint64_t stream_id,
                                   ArrayView<const uint8_t> data,
                                   bool fin) {
  std::vector<uint8_t> copy(data.begin(), data.end());
  queues_->worker()->PostTask(SafeTask(
      safety_.flag(), [this, stream_id, buf = std::move(copy), fin]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        const bool is_uni = (stream_id & 0x02u) != 0;
        if (is_uni) {
          HandleInboundUnidirectionalData(stream_id, buf, fin);
          return;
        }
        const auto out_it = outbound_requests_.find(stream_id);
        if (out_it != outbound_requests_.end()) {
          HandleOutboundRequestResponseBytes(&out_it->second, buf, fin);
          if (fin) {
            outbound_requests_.erase(out_it);
          }
          return;
        }
        auto& in_req = inbound_requests_[stream_id];
        HandleInboundBidiRequestBytes(stream_id, &in_req, buf, fin);
        if (fin) {
          inbound_requests_.erase(stream_id);
        }
      }));
}

void MoqRelayBackend::OnStreamReset(uint64_t stream_id,
                                    uint64_t /*app_error_code*/) {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this, stream_id]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    inbound_uni_streams_.erase(stream_id);
    const auto in_it = inbound_requests_.find(stream_id);
    if (in_it != inbound_requests_.end()) {
      if (in_it->second.initial_parsed &&
          in_it->second.initial_type ==
              MoqControlMessageType::kPublishNamespace) {
        const auto room_pfx = MoqtTrackNamespace::MakeRoomPrefix(room_id_);
        if (in_it->second.ns.StartsWith(room_pfx)) {
          HandleNamespaceSuffixNotification(
              in_it->second.ns.SuffixAfter(room_pfx), /*is_done=*/true);
        }
      }
      inbound_requests_.erase(in_it);
    }
    outbound_requests_.erase(stream_id);
  }));
}

void MoqRelayBackend::OnStreamStopSending(uint64_t stream_id,
                                          uint64_t /*app_error_code*/) {
  queues_->worker()->PostTask(SafeTask(safety_.flag(), [this, stream_id]() {
    RTC_DCHECK_RUN_ON(&work_checker_);
    outbound_requests_.erase(stream_id);
    inbound_requests_.erase(stream_id);
  }));
}

void MoqRelayBackend::OnDatagramReceived(ArrayView<const uint8_t> data) {
  std::vector<uint8_t> copy(data.begin(), data.end());
  queues_->worker()->PostTask(
      SafeTask(safety_.flag(), [this, buf = std::move(copy)]() {
        RTC_DCHECK_RUN_ON(&work_checker_);
        bool violation = false;
        auto dg = MoqtObjectDatagram::Decode(buf, &violation);
        if (violation) {
          if (quic_engine_) {
            quic_engine_->Close(kMoqtErrProtocolViolation);
          }
          return;
        }
        if (!dg.has_value() || dg->status != MoqtObjectStatus::kNormal) {
          return;
        }
        if (dg->track_alias == downstream_data_alias_ ||
            dg->track_alias == kMoqDownstreamDataTrackAlias ||
            dg->track_alias == kMoqUpstreamDataTrackAlias) {
          size_t consumed = 0;
          auto data_obj = MoqDataPackager::UnpackObject(dg->payload, &consumed);
          if (data_obj.has_value()) {
            DeliverUnpackedDataObject(std::move(*data_obj));
          }
        }
      }));
}

void MoqRelayBackend::HandleControlStreamBytes(std::vector<uint8_t>* buf) {
  while (!buf->empty()) {
    size_t consumed = 0;
    bool violation = false;
    auto msg = MoqControlMessage::Decode(*buf, &consumed, &violation);
    if (violation) {
      if (quic_engine_) {
        quic_engine_->Close(kMoqtErrProtocolViolation);
      }
      buf->clear();
      return;
    }
    if (!msg.has_value()) {
      break;
    }
    buf->erase(buf->begin(), buf->begin() + static_cast<ptrdiff_t>(consumed));

    if (msg->type == MoqControlMessageType::kSetup) {
      if (peer_setup_received_) {
        quic_engine_->Close(kMoqtErrProtocolViolation);
        return;
      }
      peer_setup_received_ = true;
    } else if (msg->type == MoqControlMessageType::kGoaway) {
      RTC_LOG(kInfo) << "MOQT received GOAWAY (new_uri=" << msg->new_session_uri
                     << ", timeout_ms=" << msg->goaway_timeout_ms << ")";
    } else {
      quic_engine_->Close(kMoqtErrProtocolViolation);
      return;
    }
  }
}

void MoqRelayBackend::HandleNamespaceSuffixNotification(
    const MoqtTrackNamespace& suffix,
    bool is_done) {
  // Suffix 结构约定：{remote_peer_id, "video", "h264"|"h265"} 或 {remote_peer_id, "data", label}。
  if (suffix.fields.empty()) {
    return;
  }
  const std::string& remote_peer = suffix.fields[0];
  if (remote_peer.empty() || remote_peer == local_peer_id_ ||
      remote_peer == "*") {
    return;
  }
  const std::string kind =
      (suffix.fields.size() >= 2) ? suffix.fields[1] : "video";
  if (kind == "data") {
    if (!config_.enable_datachannel) {
      return;
    }
    const std::string label =
        (suffix.fields.size() >= 3) ? suffix.fields[2] : "data";
    if (!is_done) {
      const int cid = EnsureDataChannelForLabelOnWorker(label, nullptr);
      if (notified_remote_dc_peers_.emplace(remote_peer, cid).second &&
          observer_ != nullptr) {
        observer_->OnBackendDataChannelState(remote_peer, cid, label,
                                             RTC_DATA_CHANNEL_OPEN);
      }
    } else {
      const auto dc_it = label_to_dc_id_.find(label);
      if (dc_it != label_to_dc_id_.end()) {
        const int cid = dc_it->second;
        if (notified_remote_dc_peers_.erase({remote_peer, cid}) > 0 &&
            observer_ != nullptr) {
          observer_->OnBackendDataChannelState(remote_peer, cid, label,
                                               RTC_DATA_CHANNEL_CLOSED);
        }
      }
    }
    return;
  }

  if (observer_ != nullptr) {
    if (!is_done) {
      VideoCodec codec = static_cast<VideoCodec>(config_.publish_codec);
      if (suffix.fields.size() >= 3) {
        if (suffix.fields[2].find("h265") != std::string::npos) {
          codec = VideoCodec::kH265;
        } else if (suffix.fields[2].find("h264") != std::string::npos) {
          codec = VideoCodec::kH264;
        }
      }
      observer_->OnBackendRemoteTrackPublished(remote_peer, remote_peer, codec);
    } else {
      observer_->OnBackendRemoteTrackUnpublished(remote_peer, remote_peer);
    }
  }
}

void MoqRelayBackend::HandleOutboundRequestResponseBytes(
    OutboundBidiRequestState* req_st,
    ArrayView<const uint8_t> data,
    bool /*fin*/) {
  req_st->rx_buf.insert(req_st->rx_buf.end(), data.begin(), data.end());
  while (!req_st->rx_buf.empty()) {
    size_t consumed = 0;
    bool violation = false;
    auto msg = MoqControlMessage::Decode(req_st->rx_buf, &consumed, &violation);
    if (violation) {
      if (quic_engine_) {
        quic_engine_->Close(kMoqtErrProtocolViolation);
      }
      req_st->rx_buf.clear();
      return;
    }
    if (!msg.has_value()) {
      break;
    }
    req_st->rx_buf.erase(req_st->rx_buf.begin(),
                         req_st->rx_buf.begin() +
                             static_cast<ptrdiff_t>(consumed));

    switch (msg->type) {
      case MoqControlMessageType::kSubscribeOk: {
        req_st->ok_received = true;
        if (req_st->kind == OutboundRequestKind::kSubscribeData) {
          downstream_data_alias_ = msg->track_alias;
        } else if (req_st->kind == OutboundRequestKind::kSubscribeVideoLow ||
                   req_st->kind == OutboundRequestKind::kSubscribeVideoHigh) {
          alias_to_track_id_[msg->track_alias] = req_st->target_track_id;
          const auto sit = subscriptions_.find(req_st->target_track_id);
          if (sit != subscriptions_.end()) {
            if (req_st->kind == OutboundRequestKind::kSubscribeVideoLow) {
              sit->second->low_track_alias = msg->track_alias;
            } else {
              sit->second->high_track_alias = msg->track_alias;
            }
          }
        }
        break;
      }
      case MoqControlMessageType::kRequestOk:
        req_st->ok_received = true;
        break;
      case MoqControlMessageType::kNamespace:
        if (req_st->kind == OutboundRequestKind::kSubscribeNamespace) {
          HandleNamespaceSuffixNotification(msg->track_namespace,
                                            /*is_done=*/false);
        }
        break;
      case MoqControlMessageType::kNamespaceDone:
        if (req_st->kind == OutboundRequestKind::kSubscribeNamespace) {
          HandleNamespaceSuffixNotification(msg->track_namespace,
                                            /*is_done=*/true);
        }
        break;
      case MoqControlMessageType::kPublishDone:
      case MoqControlMessageType::kRequestError:
        break;
      default:
        break;
    }
  }
}

void MoqRelayBackend::HandleInboundBidiRequestBytes(
    uint64_t stream_id,
    InboundBidiRequestState* req_st,
    ArrayView<const uint8_t> data,
    bool /*fin*/) {
  req_st->rx_buf.insert(req_st->rx_buf.end(), data.begin(), data.end());
  while (!req_st->rx_buf.empty()) {
    size_t consumed = 0;
    bool violation = false;
    auto msg = MoqControlMessage::Decode(req_st->rx_buf, &consumed, &violation);
    if (violation) {
      if (quic_engine_) {
        quic_engine_->Close(kMoqtErrProtocolViolation);
      }
      req_st->rx_buf.clear();
      return;
    }
    if (!msg.has_value()) {
      break;
    }
    req_st->rx_buf.erase(req_st->rx_buf.begin(),
                         req_st->rx_buf.begin() +
                             static_cast<ptrdiff_t>(consumed));

    if (!req_st->initial_parsed) {
      req_st->initial_parsed = true;
      req_st->initial_type = msg->type;
      req_st->ns = msg->track_namespace;
      req_st->track_name = msg->track_name;
    }

    switch (msg->type) {
      case MoqControlMessageType::kSubscribe: {
        // 中继或直连对端向本发布者发起上游 SUBSCRIBE：回复 SUBSCRIBE_OK 并声明支持 DYNAMIC_GROUPS(0x30=1)。
        MoqControlMessage ok;
        ok.type = MoqControlMessageType::kSubscribeOk;
        if (msg->track_name == "video/low") {
          ok.track_alias = 1;
        } else if (msg->track_name == "video/high") {
          ok.track_alias = 2;
        } else {
          ok.track_alias = kMoqUpstreamDataTrackAlias;
        }
        ok.track_properties.push_back(
            MoqtKeyValuePair::MakeVarInt(kMoqtPropDynamicGroups, 1));
        quic_engine_->WriteStream(stream_id, ok.Encode(), /*fin=*/false);

        if (msg->track_name.rfind("video", 0) == 0 && observer_ != nullptr &&
            msg->parameters.forward.value_or(1) == 1) {
          const SpatialLayer layer =
              (msg->track_name == "video/low") ? SpatialLayer::kLow
                                               : SpatialLayer::kHigh;
          observer_->OnBackendForceKeyFrame(layer);
        }
        break;
      }
      case MoqControlMessageType::kRequestUpdate: {
        MoqControlMessage rok;
        rok.type = MoqControlMessageType::kRequestOk;
        quic_engine_->WriteStream(stream_id, rok.Encode(), /*fin=*/false);

        if (msg->parameters.new_group_request.has_value() &&
            observer_ != nullptr) {
          if (req_st->track_name == "video/low") {
            observer_->OnBackendForceKeyFrame(SpatialLayer::kLow);
          } else if (req_st->track_name == "video/high") {
            observer_->OnBackendForceKeyFrame(SpatialLayer::kHigh);
          } else {
            observer_->OnBackendForceKeyFrame(SpatialLayer::kHigh);
            if (config_.enable_simulcast) {
              observer_->OnBackendForceKeyFrame(SpatialLayer::kLow);
            }
          }
        }
        break;
      }
      case MoqControlMessageType::kPublishNamespace: {
        MoqControlMessage rok;
        rok.type = MoqControlMessageType::kRequestOk;
        quic_engine_->WriteStream(stream_id, rok.Encode(), /*fin=*/false);
        const auto room_pfx = MoqtTrackNamespace::MakeRoomPrefix(room_id_);
        if (msg->track_namespace.StartsWith(room_pfx)) {
          HandleNamespaceSuffixNotification(
              msg->track_namespace.SuffixAfter(room_pfx), /*is_done=*/false);
        }
        break;
      }
      case MoqControlMessageType::kSubscribeNamespace: {
        MoqControlMessage rok;
        rok.type = MoqControlMessageType::kRequestOk;
        std::vector<uint8_t> resp = rok.Encode();
        const auto self_ns = [&]() {
          auto ns =
              MoqtTrackNamespace::MakePeerNamespace(room_id_, local_peer_id_);
          ns.fields.push_back("video");
          ns.fields.push_back(
              config_.publish_codec == RTC_CODEC_H265 ? "h265" : "h264");
          return ns;
        }();
        if (self_ns.StartsWith(msg->track_namespace)) {
          MoqControlMessage nm;
          nm.type = MoqControlMessageType::kNamespace;
          nm.track_namespace = self_ns.SuffixAfter(msg->track_namespace);
          const auto nm_bytes = nm.Encode();
          resp.insert(resp.end(), nm_bytes.begin(), nm_bytes.end());
        }
        quic_engine_->WriteStream(stream_id, resp, /*fin=*/false);
        break;
      }
      default: {
        MoqControlMessage err;
        err.type = MoqControlMessageType::kRequestError;
        err.error_or_status_code = kMoqtReqErrNotSupported;
        err.reason_phrase = "not supported";
        quic_engine_->WriteStream(stream_id, err.Encode(), /*fin=*/true);
        break;
      }
    }
  }
}

void MoqRelayBackend::HandleInboundUnidirectionalData(
    uint64_t stream_id,
    ArrayView<const uint8_t> data,
    bool fin) {
  auto& st = inbound_uni_streams_[stream_id];
  if (!data.empty()) {
    st.buffer.insert(st.buffer.end(), data.begin(), data.end());
  }

  if (st.kind == InboundUniStreamState::Kind::kUnknown) {
    size_t peek_off = 0;
    uint64_t stype = 0;
    bool bad_vi = false;
    if (!MoqtVarInt::Read(st.buffer, &peek_off, &stype, &bad_vi)) {
      if (bad_vi && quic_engine_) {
        quic_engine_->Close(kMoqtErrProtocolViolation);
      }
      return;
    }
    if (stype == static_cast<uint64_t>(MoqControlMessageType::kSetup)) {
      st.kind = InboundUniStreamState::Kind::kControl;
    } else {
      size_t hdr_consumed = 0;
      bool violation = false;
      auto hdr = MoqSubgroupHeader::Decode(st.buffer, &hdr_consumed, &violation);
      if (violation) {
        if (quic_engine_) {
          quic_engine_->Close(kMoqtErrProtocolViolation);
        }
        return;
      }
      if (!hdr.has_value()) {
        return;
      }
      st.kind = InboundUniStreamState::Kind::kSubgroupData;
      st.header = *hdr;
      st.buffer.erase(st.buffer.begin(),
                      st.buffer.begin() + static_cast<ptrdiff_t>(hdr_consumed));
    }
  }

  if (st.kind == InboundUniStreamState::Kind::kControl) {
    if (fin) {
      // draft-17 第 3.3 节：控制单向流在会话生命周期内严禁以 FIN 关闭。
      if (quic_engine_) {
        quic_engine_->Close(kMoqtErrProtocolViolation);
      }
      return;
    }
    HandleControlStreamBytes(&st.buffer);
    return;
  }

  const bool is_data_track =
      (st.header.track_alias == downstream_data_alias_ ||
       st.header.track_alias == kMoqDownstreamDataTrackAlias ||
       st.header.track_alias == kMoqUpstreamDataTrackAlias);

  const Timestamp now = clock_->CurrentTime();
  while (!st.buffer.empty()) {
    size_t obj_consumed = 0;
    bool violation = false;
    auto sg_obj = MoqtSubgroupObject::Decode(
        st.buffer, st.prev_object_id, st.header.has_properties, &obj_consumed,
        &violation);
    if (violation) {
      if (quic_engine_) {
        quic_engine_->Close(kMoqtErrProtocolViolation);
      }
      return;
    }
    if (!sg_obj.has_value()) {
      break;
    }
    st.buffer.erase(st.buffer.begin(),
                    st.buffer.begin() + static_cast<ptrdiff_t>(obj_consumed));
    if (!st.prev_object_id.has_value() &&
        st.header.subgroup_id_from_first_object) {
      st.header.subgroup_id = sg_obj->object_id;
    }
    st.prev_object_id = sg_obj->object_id;

    if (sg_obj->status != MoqtObjectStatus::kNormal ||
        sg_obj->payload.empty()) {
      continue;
    }

    if (is_data_track) {
      size_t d_consumed = 0;
      auto data_obj = MoqDataPackager::UnpackObject(sg_obj->payload, &d_consumed);
      if (data_obj.has_value()) {
        DeliverUnpackedDataObject(std::move(*data_obj));
      }
      continue;
    }

    auto frame = LocFramePackager::UnpackPayload(sg_obj->payload);
    if (!frame.has_value()) {
      continue;
    }

    SubscribedTrackContext* sub_ctx = nullptr;
    const auto alias_it = alias_to_track_id_.find(st.header.track_alias);
    if (alias_it != alias_to_track_id_.end()) {
      const auto sub_it = subscriptions_.find(alias_it->second);
      if (sub_it != subscriptions_.end()) {
        sub_ctx = sub_it->second.get();
      }
    } else if ((st.header.track_alias == 1 || st.header.track_alias == 2) &&
               subscriptions_.size() == 1) {
      sub_ctx = subscriptions_.begin()->second.get();
    }
    if (sub_ctx == nullptr) {
      continue;
    }

    sub_ctx->has_received_group = true;
    sub_ctx->largest_group_seen =
        std::max(sub_ctx->largest_group_seen, st.header.group_id);

    const DataSize fsize = DataSize::Bytes(frame->data.size());
    if (sub_ctx->prev_recv_time.has_value() &&
        sub_ctx->prev_frame_size.has_value()) {
      sub_ctx->jitter_estimator.UpdateEstimate(
          now - *sub_ctx->prev_recv_time, fsize - *sub_ctx->prev_frame_size,
          fsize, false);
    }
    sub_ctx->prev_recv_time = now;
    sub_ctx->prev_frame_size = fsize;
    sub_ctx->vcm_timing.IncomingTimestamp(frame->rtp_timestamp, now);

    if (frame->dep.is_keyframe && sub_ctx->current_spatial_id.has_value() &&
        *sub_ctx->current_spatial_id != frame->dep.spatial_id) {
      sub_ctx->frame_buffer.Clear();
    }
    sub_ctx->current_spatial_id = frame->dep.spatial_id;

    AssembledRtpFrame rtp_frame;
    rtp_frame.rtp_timestamp = frame->rtp_timestamp;
    rtp_frame.received_time = now;
    rtp_frame.codec = frame->codec;
    rtp_frame.is_keyframe = frame->dep.is_keyframe;
    rtp_frame.dep = frame->dep;
    rtp_frame.annexb_bitstream = std::move(frame->data);

    sub_ctx->frame_buffer.InsertFrame(std::move(rtp_frame));
    DrainDecodableFrames(sub_ctx);
  }

  if (fin) {
    inbound_uni_streams_.erase(stream_id);
  }
}

void MoqRelayBackend::DeliverUnpackedDataObject(MoqDataObject obj) {
  if (!config_.enable_datachannel || obj.sender_peer_id == local_peer_id_) {
    return;
  }
  const int cid = EnsureDataChannelForLabelOnWorker(obj.label, nullptr);
  const std::string peer =
      obj.sender_peer_id.empty() ? "remote_peer" : obj.sender_peer_id;
  if (obj.is_close) {
    if (notified_remote_dc_peers_.erase({peer, cid}) > 0 &&
        observer_ != nullptr) {
      observer_->OnBackendDataChannelState(peer, cid, obj.label,
                                           RTC_DATA_CHANNEL_CLOSED);
    }
    return;
  }
  if (notified_remote_dc_peers_.emplace(peer, cid).second &&
      observer_ != nullptr) {
    observer_->OnBackendDataChannelState(peer, cid, obj.label,
                                         RTC_DATA_CHANNEL_OPEN);
  }
  if (observer_ != nullptr) {
    observer_->OnBackendDataChannelMessage(peer, cid, obj.is_binary,
                                           std::move(obj.payload));
  }
}

void MoqRelayBackend::DrainDecodableFrames(SubscribedTrackContext* sub) {
  while (auto dec = sub->frame_buffer.ExtractNextDecodableFrame()) {
    ++frames_decoded_;
    EncodedVideoFrame out;
    out.data = std::move(dec->annexb_bitstream);
    out.capture_time = dec->received_time;
    out.rtp_timestamp = dec->rtp_timestamp;
    out.codec = dec->codec;
    out.layer = static_cast<SpatialLayer>(dec->dep.spatial_id);
    out.dep = dec->dep;
    if (observer_ != nullptr) {
      observer_->OnBackendDecodableFrame(sub->track_id, sub->track_id,
                                         std::move(out));
    }
  }
}

void MoqRelayBackend::OnPeriodicMaintenanceTick() {
  RTC_DCHECK_RUN_ON(&work_checker_);
  if (connected_ && quic_engine_) {
    const QuicCongestionSnapshot snap = quic_engine_->GetCongestionSnapshot();
    const TargetTransferRate rate = bwe_adapter_.ConvertSnapshot(snap);
    last_target_bps_ = static_cast<uint32_t>(rate.target_rate.bps());
    if (observer_ != nullptr) {
      observer_->OnBackendTargetTransferRate(rate);
    }

    const Timestamp now = clock_->CurrentTime();
    if (!ttl_data_streams_.empty()) {
      for (auto it = ttl_data_streams_.begin();
           it != ttl_data_streams_.end();) {
        if (now >= it->second) {
          if (snap.unsent_stream_bytes > DataSize::Zero()) {
            quic_engine_->ResetStream(it->first, 0x02);
          }
          it = ttl_data_streams_.erase(it);
        } else {
          ++it;
        }
      }
    }
    for (auto& [track_id, sub] : subscriptions_) {
      if (sub->frame_buffer.IsCorruptedOrStalled(now, TimeDelta::Millis(250))) {
        RequestRemoteKeyFrame(track_id);
      }
    }

    if (last_stats_time_.IsFinite() &&
        (now - last_stats_time_) >= TimeDelta::Millis(500)) {
      rtc_network_stats_t stats{};
      stats.rtt_ms = snap.smoothed_rtt.ms();
      stats.target_bitrate_bps = last_target_bps_;
      stats.pacing_bitrate_bps =
          static_cast<uint32_t>(snap.pacing_rate.bps());
      stats.uplink_packet_loss = static_cast<float>(rate.loss_rate_ratio);
      stats.packets_sent = snap.packets_sent;
      stats.frames_decoded = frames_decoded_;
      stats.keyframe_requests_sent = keyframe_requests_sent_;
      last_stats_time_ = now;
      if (observer_ != nullptr) {
        observer_->OnBackendStatsSnapshot(stats);
      }
    }
  }
  queues_->worker()->PostDelayedTask(
      SafeTask(safety_.flag(), [this]() { OnPeriodicMaintenanceTick(); }),
      TimeDelta::Millis(50));
}

// ======================= InMemoryMoqQuicPair 内存回环 QUIC 测试对 =======================

namespace {
class LoopbackQuicEndpoint final
    : public IMoqQuicEngine,
      public std::enable_shared_from_this<LoopbackQuicEndpoint> {
 public:
  LoopbackQuicEndpoint(TaskQueueBoost* net_q,
                       bool is_client,
                       DataRate bw,
                       TimeDelta rtt)
      : net_q_(net_q),
        next_bidi_id_(is_client ? 0 : 1),
        next_uni_id_(is_client ? 2 : 3),
        bw_(bw),
        rtt_(rtt) {}

  void BindPeer(std::weak_ptr<LoopbackQuicEndpoint> peer) {
    peer_ = std::move(peer);
  }

  void SetObserver(IMoqQuicEngineObserver* obs) override { observer_ = obs; }

  int Connect(const std::string& /*host*/,
              uint16_t /*port*/,
              const std::string& alpn) override {
    alpn_ = alpn;
    auto self = shared_from_this();
    net_q_->PostTask([self]() {
      if (self->observer_ != nullptr) {
        self->observer_->OnQuicConnected();
      }
      if (auto p = self->peer_.lock()) {
        p->alpn_ = self->alpn_;
        if (p->observer_ != nullptr) {
          p->observer_->OnQuicConnected();
        }
      }
    });
    return 0;
  }

  void Close(uint64_t code) override {
    auto self = shared_from_this();
    net_q_->PostTask([self, code]() {
      if (self->observer_ != nullptr) {
        self->observer_->OnQuicDisconnected(static_cast<int>(code));
      }
    });
  }

  uint64_t OpenBidirectionalStream() override {
    const uint64_t id = next_bidi_id_.fetch_add(4);
    if (auto peer = peer_.lock()) {
      net_q_->PostTask([peer, id]() {
        if (peer->observer_ != nullptr) {
          peer->observer_->OnStreamOpened(id, false);
        }
      });
    }
    return id;
  }

  uint64_t OpenUnidirectionalStream(uint8_t /*prio*/,
                                    int64_t /*send_order*/) override {
    const uint64_t id = next_uni_id_.fetch_add(4);
    if (auto peer = peer_.lock()) {
      net_q_->PostTask([peer, id]() {
        if (peer->observer_ != nullptr) {
          peer->observer_->OnStreamOpened(id, true);
        }
      });
    }
    return id;
  }

  int WriteStream(uint64_t stream_id,
                  ArrayView<const uint8_t> data,
                  bool fin) override {
    auto peer = peer_.lock();
    if (!peer) {
      return -1;
    }
    std::vector<uint8_t> buf(data.begin(), data.end());
    pkts_sent_.fetch_add(1);
    net_q_->PostTask([peer, stream_id, b = std::move(buf), fin]() {
      if (peer->observer_ != nullptr) {
        peer->observer_->OnStreamData(stream_id, b, fin);
      }
    });
    return static_cast<int>(data.size());
  }

  void ResetStream(uint64_t stream_id, uint64_t app_error_code) override {
    if (auto peer = peer_.lock()) {
      net_q_->PostTask([peer, stream_id, app_error_code]() {
        if (peer->observer_ != nullptr) {
          peer->observer_->OnStreamReset(stream_id, app_error_code);
        }
      });
    }
  }

  void StopSending(uint64_t stream_id, uint64_t app_error_code) override {
    if (auto peer = peer_.lock()) {
      net_q_->PostTask([peer, stream_id, app_error_code]() {
        if (peer->observer_ != nullptr) {
          peer->observer_->OnStreamStopSending(stream_id, app_error_code);
        }
      });
    }
  }

  int SendDatagram(ArrayView<const uint8_t> data) override {
    auto peer = peer_.lock();
    if (!peer) {
      return RTC_ERR_NOT_CONNECTED;
    }
    std::vector<uint8_t> buf(data.begin(), data.end());
    pkts_sent_.fetch_add(1);
    net_q_->PostTask([peer, b = std::move(buf)]() {
      if (peer->observer_ != nullptr) {
        peer->observer_->OnDatagramReceived(b);
      }
    });
    return RTC_OK;
  }

  size_t max_datagram_size() const override { return 1160; }
  std::string negotiated_alpn() const override { return alpn_; }

  QuicCongestionSnapshot GetCongestionSnapshot() const override {
    QuicCongestionSnapshot s;
    s.timestamp = Clock::GetRealTimeClock()->CurrentTime();
    s.smoothed_rtt = rtt_;
    s.min_rtt = rtt_;
    s.pacing_rate = bw_;
    s.cwnd = bw_ * (rtt_ * 2);
    s.packets_sent = pkts_sent_.load();
    return s;
  }

 private:
  TaskQueueBoost* net_q_;
  IMoqQuicEngineObserver* observer_ = nullptr;
  std::weak_ptr<LoopbackQuicEndpoint> peer_;
  std::atomic<uint64_t> next_bidi_id_;
  std::atomic<uint64_t> next_uni_id_;
  DataRate bw_;
  TimeDelta rtt_;
  std::string alpn_ = kMoqtDraft17Alpn;
  std::atomic<uint64_t> pkts_sent_{0};
};
}  // namespace

std::pair<std::shared_ptr<IMoqQuicEngine>, std::shared_ptr<IMoqQuicEngine>>
InMemoryMoqQuicPair::CreateConnectedPair(TaskQueueBoost* network_queue,
                                         DataRate simulated_bandwidth,
                                         TimeDelta simulated_rtt) {
  auto a = std::make_shared<LoopbackQuicEndpoint>(
      network_queue, true, simulated_bandwidth, simulated_rtt);
  auto b = std::make_shared<LoopbackQuicEndpoint>(
      network_queue, false, simulated_bandwidth, simulated_rtt);
  a->BindPeer(b);
  b->BindPeer(a);
  return {a, b};
}

}  // namespace rtc
