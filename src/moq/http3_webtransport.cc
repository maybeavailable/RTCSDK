#include "moq/http3_webtransport.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>

#include "modules/rtp_rtcp/byte_io.h"
#include "moq/moq_transport.h"
#include "rtc_base/logging.h"

namespace rtc {

namespace {

struct HuffSym {
  uint32_t code;
  uint8_t bit_len;
};

struct StaticHeaderEntry {
  const char* name;
  const char* value;
};

// 严格遵循 RFC 7541 附录 B 的标准静态 Huffman 码表（共 257 项，第 256 项为 EOS）。
constexpr HuffSym kRfc7541Huffman[257] = {
    {0x00001ff8u, 13u}, {0x007fffd8u, 23u}, {0x0fffffe2u, 28u},
    {0x0fffffe3u, 28u}, {0x0fffffe4u, 28u}, {0x0fffffe5u, 28u},
    {0x0fffffe6u, 28u}, {0x0fffffe7u, 28u}, {0x0fffffe8u, 28u},
    {0x00ffffeau, 24u}, {0x3ffffffcu, 30u}, {0x0fffffe9u, 28u},
    {0x0fffffeau, 28u}, {0x3ffffffdu, 30u}, {0x0fffffebu, 28u},
    {0x0fffffecu, 28u}, {0x0fffffedu, 28u}, {0x0fffffeeu, 28u},
    {0x0fffffefu, 28u}, {0x0ffffff0u, 28u}, {0x0ffffff1u, 28u},
    {0x0ffffff2u, 28u}, {0x3ffffffeu, 30u}, {0x0ffffff3u, 28u},
    {0x0ffffff4u, 28u}, {0x0ffffff5u, 28u}, {0x0ffffff6u, 28u},
    {0x0ffffff7u, 28u}, {0x0ffffff8u, 28u}, {0x0ffffff9u, 28u},
    {0x0ffffffau, 28u}, {0x0ffffffbu, 28u}, {0x00000014u, 6u},
    {0x000003f8u, 10u}, {0x000003f9u, 10u}, {0x00000ffau, 12u},
    {0x00001ff9u, 13u}, {0x00000015u, 6u},  {0x000000f8u, 8u},
    {0x000007fau, 11u}, {0x000003fau, 10u}, {0x000003fbu, 10u},
    {0x000000f9u, 8u},  {0x000007fbu, 11u}, {0x000000fau, 8u},
    {0x00000016u, 6u},  {0x00000017u, 6u},  {0x00000018u, 6u},
    {0x00000000u, 5u},  {0x00000001u, 5u},  {0x00000002u, 5u},
    {0x00000019u, 6u},  {0x0000001au, 6u},  {0x0000001bu, 6u},
    {0x0000001cu, 6u},  {0x0000001du, 6u},  {0x0000001eu, 6u},
    {0x0000001fu, 6u},  {0x0000005cu, 7u},  {0x000000fbu, 8u},
    {0x00007ffcu, 15u}, {0x00000020u, 6u},  {0x00000ffbu, 12u},
    {0x000003fcu, 10u}, {0x00001ffau, 13u}, {0x00000021u, 6u},
    {0x0000005du, 7u},  {0x0000005eu, 7u},  {0x0000005fu, 7u},
    {0x00000060u, 7u},  {0x00000061u, 7u},  {0x00000062u, 7u},
    {0x00000063u, 7u},  {0x00000064u, 7u},  {0x00000065u, 7u},
    {0x00000066u, 7u},  {0x00000067u, 7u},  {0x00000068u, 7u},
    {0x00000069u, 7u},  {0x0000006au, 7u},  {0x0000006bu, 7u},
    {0x0000006cu, 7u},  {0x0000006du, 7u},  {0x0000006eu, 7u},
    {0x0000006fu, 7u},  {0x00000070u, 7u},  {0x00000071u, 7u},
    {0x00000072u, 7u},  {0x000000fcu, 8u},  {0x00000073u, 7u},
    {0x000000fdu, 8u},  {0x00001ffbu, 13u}, {0x0007fff0u, 19u},
    {0x00001ffcu, 13u}, {0x00003ffcu, 14u}, {0x00000022u, 6u},
    {0x00007ffdu, 15u}, {0x00000003u, 5u},  {0x00000023u, 6u},
    {0x00000004u, 5u},  {0x00000024u, 6u},  {0x00000005u, 5u},
    {0x00000025u, 6u},  {0x00000026u, 6u},  {0x00000027u, 6u},
    {0x00000006u, 5u},  {0x00000074u, 7u},  {0x00000075u, 7u},
    {0x00000028u, 6u},  {0x00000029u, 6u},  {0x0000002au, 6u},
    {0x00000007u, 5u},  {0x0000002bu, 6u},  {0x00000076u, 7u},
    {0x0000002cu, 6u},  {0x00000008u, 5u},  {0x00000009u, 5u},
    {0x0000002du, 6u},  {0x00000077u, 7u},  {0x00000078u, 7u},
    {0x00000079u, 7u},  {0x0000007au, 7u},  {0x0000007bu, 7u},
    {0x00007ffeu, 15u}, {0x000007fcu, 11u}, {0x00003ffdu, 14u},
    {0x00001ffdu, 13u}, {0x0ffffffcu, 28u}, {0x000fffe6u, 20u},
    {0x003fffd2u, 22u}, {0x000fffe7u, 20u}, {0x000fffe8u, 20u},
    {0x003fffd3u, 22u}, {0x003fffd4u, 22u}, {0x003fffd5u, 22u},
    {0x007fffd9u, 23u}, {0x003fffd6u, 22u}, {0x007fffdau, 23u},
    {0x007fffdbu, 23u}, {0x007fffdcu, 23u}, {0x007fffddu, 23u},
    {0x007fffdeu, 23u}, {0x00ffffebu, 24u}, {0x007fffdfu, 23u},
    {0x00ffffecu, 24u}, {0x00ffffedu, 24u}, {0x003fffd7u, 22u},
    {0x007fffe0u, 23u}, {0x00ffffeeu, 24u}, {0x007fffe1u, 23u},
    {0x007fffe2u, 23u}, {0x007fffe3u, 23u}, {0x007fffe4u, 23u},
    {0x001fffdcu, 21u}, {0x003fffd8u, 22u}, {0x007fffe5u, 23u},
    {0x003fffd9u, 22u}, {0x007fffe6u, 23u}, {0x007fffe7u, 23u},
    {0x00ffffefu, 24u}, {0x003fffdau, 22u}, {0x001fffddu, 21u},
    {0x000fffe9u, 20u}, {0x003fffdbu, 22u}, {0x003fffdcu, 22u},
    {0x007fffe8u, 23u}, {0x007fffe9u, 23u}, {0x001fffdeu, 21u},
    {0x007fffeau, 23u}, {0x003fffddu, 22u}, {0x003fffdeu, 22u},
    {0x00fffff0u, 24u}, {0x001fffdfu, 21u}, {0x003fffdfu, 22u},
    {0x007fffebu, 23u}, {0x007fffecu, 23u}, {0x001fffe0u, 21u},
    {0x001fffe1u, 21u}, {0x003fffe0u, 22u}, {0x001fffe2u, 21u},
    {0x007fffedu, 23u}, {0x003fffe1u, 22u}, {0x007fffeeu, 23u},
    {0x007fffefu, 23u}, {0x000fffeau, 20u}, {0x003fffe2u, 22u},
    {0x003fffe3u, 22u}, {0x003fffe4u, 22u}, {0x007ffff0u, 23u},
    {0x003fffe5u, 22u}, {0x003fffe6u, 22u}, {0x007ffff1u, 23u},
    {0x03ffffe0u, 26u}, {0x03ffffe1u, 26u}, {0x000fffebu, 20u},
    {0x0007fff1u, 19u}, {0x003fffe7u, 22u}, {0x007ffff2u, 23u},
    {0x003fffe8u, 22u}, {0x01ffffecu, 25u}, {0x03ffffe2u, 26u},
    {0x03ffffe3u, 26u}, {0x03ffffe4u, 26u}, {0x07ffffdeu, 27u},
    {0x07ffffdfu, 27u}, {0x03ffffe5u, 26u}, {0x00fffff1u, 24u},
    {0x01ffffedu, 25u}, {0x0007fff2u, 19u}, {0x001fffe3u, 21u},
    {0x03ffffe6u, 26u}, {0x07ffffe0u, 27u}, {0x07ffffe1u, 27u},
    {0x03ffffe7u, 26u}, {0x07ffffe2u, 27u}, {0x00fffff2u, 24u},
    {0x001fffe4u, 21u}, {0x001fffe5u, 21u}, {0x03ffffe8u, 26u},
    {0x03ffffe9u, 26u}, {0x0ffffffdu, 28u}, {0x07ffffe3u, 27u},
    {0x07ffffe4u, 27u}, {0x07ffffe5u, 27u}, {0x000fffecu, 20u},
    {0x00fffff3u, 24u}, {0x000fffedu, 20u}, {0x001fffe6u, 21u},
    {0x003fffe9u, 22u}, {0x001fffe7u, 21u}, {0x001fffe8u, 21u},
    {0x007ffff3u, 23u}, {0x003fffeau, 22u}, {0x003fffebu, 22u},
    {0x01ffffeeu, 25u}, {0x01ffffefu, 25u}, {0x00fffff4u, 24u},
    {0x00fffff5u, 24u}, {0x03ffffeau, 26u}, {0x007ffff4u, 23u},
    {0x03ffffebu, 26u}, {0x07ffffe6u, 27u}, {0x03ffffecu, 26u},
    {0x03ffffedu, 26u}, {0x07ffffe7u, 27u}, {0x07ffffe8u, 27u},
    {0x07ffffe9u, 27u}, {0x07ffffeau, 27u}, {0x07ffffebu, 27u},
    {0x0ffffffeu, 28u}, {0x07ffffecu, 27u}, {0x07ffffedu, 27u},
    {0x07ffffeeu, 27u}, {0x07ffffefu, 27u}, {0x07fffff0u, 27u},
    {0x03ffffeeu, 26u}, {0x3fffffffu, 30u},
};

// 严格遵循 RFC 9204 附录 A 的 QPACK 静态头部表（共 99 项，索引 0..98）。
constexpr StaticHeaderEntry kQpackStaticTable[99] = {
    {":authority", ""},
    {":path", "/"},
    {"age", "0"},
    {"content-disposition", ""},
    {"content-length", "0"},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"referer", ""},
    {"set-cookie", ""},
    {":method", "CONNECT"},
    {":method", "DELETE"},
    {":method", "GET"},
    {":method", "HEAD"},
    {":method", "OPTIONS"},
    {":method", "POST"},
    {":method", "PUT"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "103"},
    {":status", "200"},
    {":status", "304"},
    {":status", "404"},
    {":status", "503"},
    {"accept", "*/*"},
    {"accept", "application/dns-message"},
    {"accept-encoding", "gzip, deflate, br"},
    {"accept-ranges", "bytes"},
    {"access-control-allow-headers", "cache-control"},
    {"access-control-allow-headers", "content-type"},
    {"access-control-allow-origin", "*"},
    {"cache-control", "max-age=0"},
    {"cache-control", "max-age=2592000"},
    {"cache-control", "max-age=604800"},
    {"cache-control", "no-cache"},
    {"cache-control", "no-store"},
    {"cache-control", "public, max-age=31536000"},
    {"content-encoding", "br"},
    {"content-encoding", "gzip"},
    {"content-type", "application/dns-message"},
    {"content-type", "application/javascript"},
    {"content-type", "application/json"},
    {"content-type", "application/x-www-form-urlencoded"},
    {"content-type", "image/gif"},
    {"content-type", "image/jpeg"},
    {"content-type", "image/png"},
    {"content-type", "text/css"},
    {"content-type", "text/html;charset=utf-8"},
    {"content-type", "text/plain"},
    {"content-type", "text/plain;charset=utf-8"},
    {"range", "bytes=0-"},
    {"strict-transport-security", "max-age=31536000"},
    {"strict-transport-security", "max-age=31536000;includesubdomains"},
    {"strict-transport-security",
     "max-age=31536000;includesubdomains;preload"},
    {"vary", "accept-encoding"},
    {"vary", "origin"},
    {"x-content-type-options", "nosniff"},
    {"x-xss-protection", "1; mode=block"},
    {":status", "100"},
    {":status", "204"},
    {":status", "206"},
    {":status", "302"},
    {":status", "400"},
    {":status", "403"},
    {":status", "421"},
    {":status", "425"},
    {":status", "500"},
    {"accept-language", ""},
    {"access-control-allow-credentials", "FALSE"},
    {"access-control-allow-credentials", "TRUE"},
    {"access-control-allow-headers", "*"},
    {"access-control-allow-methods", "get"},
    {"access-control-allow-methods", "get, post, options"},
    {"access-control-allow-methods", "options"},
    {"access-control-expose-headers", "content-length"},
    {"access-control-request-headers", "content-type"},
    {"access-control-request-method", "get"},
    {"access-control-request-method", "post"},
    {"alt-svc", "clear"},
    {"authorization", ""},
    {"content-security-policy",
     "script-src 'none';object-src 'none';base-uri 'none'"},
    {"early-data", "1"},
    {"expect-ct", ""},
    {"forwarded", ""},
    {"if-range", ""},
    {"origin", ""},
    {"purpose", "prefetch"},
    {"server", ""},
    {"timing-allow-origin", "*"},
    {"upgrade-insecure-requests", "1"},
    {"user-agent", ""},
    {"x-forwarded-for", ""},
    {"x-frame-options", "deny"},
    {"x-frame-options", "sameorigin"},
};

struct HuffTrieNode {
  int16_t child[2]{-1, -1};
  int16_t sym = -1;
};

const std::vector<HuffTrieNode>& GetHuffmanTrie() {
  static const std::vector<HuffTrieNode> trie = []() {
    std::vector<HuffTrieNode> nodes(1);
    nodes.reserve(514);
    for (int sym = 0; sym < 257; ++sym) {
      const uint32_t code = kRfc7541Huffman[sym].code;
      const uint8_t bl = kRfc7541Huffman[sym].bit_len;
      int cur = 0;
      for (int b = static_cast<int>(bl) - 1; b >= 0; --b) {
        const int bit = static_cast<int>((code >> b) & 1u);
        if (nodes[static_cast<size_t>(cur)].child[bit] < 0) {
          nodes[static_cast<size_t>(cur)].child[bit] =
              static_cast<int16_t>(nodes.size());
          nodes.emplace_back();
        }
        cur = nodes[static_cast<size_t>(cur)].child[bit];
      }
      nodes[static_cast<size_t>(cur)].sym = static_cast<int16_t>(sym);
    }
    return nodes;
  }();
  return trie;
}

// RFC 7541 第 5.1 节 N 位前缀整数编码与解码。
void AppendPrefixInt(uint64_t val,
                     uint8_t prefix_bits,
                     uint8_t high_bits_mask,
                     std::vector<uint8_t>* out) {
  const uint64_t max_prefix = (uint64_t{1} << prefix_bits) - 1;
  if (val < max_prefix) {
    out->push_back(static_cast<uint8_t>(high_bits_mask | val));
    return;
  }
  out->push_back(static_cast<uint8_t>(high_bits_mask | max_prefix));
  val -= max_prefix;
  while (val >= 128) {
    out->push_back(static_cast<uint8_t>((val & 0x7Fu) | 0x80u));
    val >>= 7;
  }
  out->push_back(static_cast<uint8_t>(val));
}

bool ReadPrefixInt(ArrayView<const uint8_t> data,
                   size_t* offset,
                   uint8_t prefix_bits,
                   uint64_t* out_val) {
  if (*offset >= data.size()) {
    return false;
  }
  const uint64_t max_prefix = (uint64_t{1} << prefix_bits) - 1;
  uint64_t val = data[*offset] & max_prefix;
  ++(*offset);
  if (val < max_prefix) {
    *out_val = val;
    return true;
  }
  uint32_t shift = 0;
  while (*offset < data.size()) {
    if (shift > 56) {
      return false;
    }
    const uint8_t b = data[(*offset)++];
    val += static_cast<uint64_t>(b & 0x7Fu) << shift;
    if ((b & 0x80u) == 0) {
      *out_val = val;
      return true;
    }
    shift += 7;
  }
  return false;
}

void AppendQpackString(std::string_view str,
                       uint8_t prefix_bits,
                       uint8_t high_mask,
                       uint8_t huffman_bit_mask,
                       bool use_huffman,
                       std::vector<uint8_t>* out) {
  if (use_huffman && !str.empty()) {
    const auto huff = QpackCodec::HuffmanEncode(str);
    if (huff.size() < str.size()) {
      AppendPrefixInt(huff.size(), prefix_bits,
                      static_cast<uint8_t>(high_mask | huffman_bit_mask), out);
      out->insert(out->end(), huff.begin(), huff.end());
      return;
    }
  }
  AppendPrefixInt(str.size(), prefix_bits, high_mask, out);
  out->insert(out->end(), str.begin(), str.end());
}

bool ReadQpackString(ArrayView<const uint8_t> data,
                     size_t* offset,
                     uint8_t prefix_bits,
                     uint8_t huffman_bit_mask,
                     std::string* out_str) {
  if (*offset >= data.size()) {
    return false;
  }
  const bool is_huffman = (data[*offset] & huffman_bit_mask) != 0;
  uint64_t slen = 0;
  if (!ReadPrefixInt(data, offset, prefix_bits, &slen) ||
      *offset + slen > data.size()) {
    return false;
  }
  const ArrayView<const uint8_t> slice =
      data.subview(*offset, static_cast<size_t>(slen));
  *offset += static_cast<size_t>(slen);
  if (is_huffman) {
    return QpackCodec::HuffmanDecode(slice, out_str);
  }
  out_str->assign(reinterpret_cast<const char*>(slice.data()), slice.size());
  return true;
}

std::string ToLowerAscii(std::string_view s) {
  std::string out(s.size(), '\0');
  for (size_t i = 0; i < s.size(); ++i) {
    out[i] = static_cast<char>(
        std::tolower(static_cast<unsigned char>(s[i])));
  }
  return out;
}

std::vector<uint8_t> BuildHttp3HeadersFrameFromMap(
    const std::vector<HttpHeaderField>& all_headers) {
  const auto qpack_block = QpackCodec::EncodeFieldSection(all_headers, true);
  std::vector<uint8_t> frame;
  Http3Frame::Append(kH3FrameHeaders, qpack_block, &frame);
  return frame;
}

}  // namespace

// ======================= QpackCodec 实现 =======================

std::vector<uint8_t> QpackCodec::HuffmanEncode(std::string_view plain) {
  std::vector<uint8_t> out;
  out.reserve(plain.size());
  uint64_t bit_buf = 0;
  uint32_t bit_count = 0;
  for (unsigned char ch : plain) {
    const HuffSym sym = kRfc7541Huffman[ch];
    bit_buf = (bit_buf << sym.bit_len) | sym.code;
    bit_count += sym.bit_len;
    while (bit_count >= 8) {
      bit_count -= 8;
      out.push_back(static_cast<uint8_t>((bit_buf >> bit_count) & 0xFFu));
    }
  }
  if (bit_count > 0) {
    const uint32_t pad_bits = 8 - bit_count;
    bit_buf = (bit_buf << pad_bits) | ((uint64_t{1} << pad_bits) - 1);
    out.push_back(static_cast<uint8_t>(bit_buf & 0xFFu));
  }
  return out;
}

bool QpackCodec::HuffmanDecode(ArrayView<const uint8_t> encoded,
                               std::string* out_plain) {
  out_plain->clear();
  out_plain->reserve(encoded.size() * 2);
  const auto& trie = GetHuffmanTrie();
  int node = 0;
  uint32_t pending_bits = 0;
  bool all_ones_padding = true;

  for (uint8_t byte : encoded) {
    for (int b = 7; b >= 0; --b) {
      const int bit = (byte >> b) & 1;
      if (bit == 0) {
        all_ones_padding = false;
      }
      ++pending_bits;
      node = trie[static_cast<size_t>(node)].child[bit];
      if (node < 0) {
        return false;
      }
      const int16_t sym = trie[static_cast<size_t>(node)].sym;
      if (sym >= 0) {
        if (sym == 256) {
          // RFC 7541 第 5.2 节：显式出现完整 EOS 符号属于解码错误。
          return false;
        }
        out_plain->push_back(static_cast<char>(sym));
        node = 0;
        pending_bits = 0;
        all_ones_padding = true;
      }
    }
  }
  return pending_bits <= 7 && all_ones_padding;
}

std::vector<uint8_t> QpackCodec::EncodeFieldSection(
    const std::vector<HttpHeaderField>& headers,
    bool use_huffman) {
  std::vector<uint8_t> out;
  out.reserve(64 + headers.size() * 24);
  // Required Insert Count = 0, Delta Base = 0（不使用动态表，避免流间队头阻塞）。
  out.push_back(0x00u);
  out.push_back(0x00u);

  for (const auto& h : headers) {
    const std::string lower_name = ToLowerAscii(h.name);
    int exact_idx = -1;
    int name_idx = -1;
    for (int i = 0; i < 99; ++i) {
      if (lower_name == kQpackStaticTable[i].name) {
        if (name_idx < 0) {
          name_idx = i;
        }
        if (h.value == kQpackStaticTable[i].value) {
          exact_idx = i;
          break;
        }
      }
    }
    if (exact_idx >= 0) {
      // Indexed Field Line: 1 | T=1 | Index(6+) -> 掩码 0xC0。
      AppendPrefixInt(static_cast<uint64_t>(exact_idx), 6, 0xC0u, &out);
    } else if (name_idx >= 0) {
      // Literal Field Line With Name Reference: 01 | N=0 | T=1 | Index(4+) -> 掩码 0x50。
      AppendPrefixInt(static_cast<uint64_t>(name_idx), 4, 0x50u, &out);
      AppendQpackString(h.value, 7, 0x00u, 0x80u, use_huffman, &out);
    } else {
      // Literal Field Line With Literal Name: 001 | N=0 | H(1) | NameLen(3+) -> 掩码 0x20。
      AppendQpackString(lower_name, 3, 0x20u, 0x08u, use_huffman, &out);
      AppendQpackString(h.value, 7, 0x00u, 0x80u, use_huffman, &out);
    }
  }
  return out;
}

bool QpackCodec::DecodeFieldSection(ArrayView<const uint8_t> data,
                                    std::vector<HttpHeaderField>* out_headers) {
  out_headers->clear();
  size_t off = 0;
  uint64_t req_insert_cnt = 0;
  uint64_t delta_base = 0;
  if (!ReadPrefixInt(data, &off, 8, &req_insert_cnt) ||
      !ReadPrefixInt(data, &off, 7, &delta_base)) {
    return false;
  }
  if (req_insert_cnt != 0) {
    // SETTINGS_QPACK_MAX_TABLE_CAPACITY 已协商为 0，禁止引用动态表项。
    return false;
  }

  while (off < data.size()) {
    const uint8_t first = data[off];
    if ((first & 0x80u) != 0) {
      // 静态表索引字段行：1 | T(1) | Index(6+)
      const bool is_static = (first & 0x40u) != 0;
      uint64_t idx = 0;
      if (!is_static || !ReadPrefixInt(data, &off, 6, &idx) || idx >= 99) {
        return false;
      }
      out_headers->push_back(HttpHeaderField{kQpackStaticTable[idx].name,
                                             kQpackStaticTable[idx].value});
    } else if ((first & 0xC0u) == 0x40u) {
      // 引用静态表字段名的字面量行：01 | N(1) | T(1) | NameIndex(4+)
      const bool is_static = (first & 0x10u) != 0;
      uint64_t name_idx = 0;
      std::string val;
      if (!is_static || !ReadPrefixInt(data, &off, 4, &name_idx) ||
          name_idx >= 99 || !ReadQpackString(data, &off, 7, 0x80u, &val)) {
        return false;
      }
      out_headers->push_back(
          HttpHeaderField{kQpackStaticTable[name_idx].name, std::move(val)});
    } else if ((first & 0xE0u) == 0x20u) {
      // 字面量字段名与字面量字段值行：001 | N(1) | H(1) | NameLen(3+)
      std::string name;
      std::string val;
      if (!ReadQpackString(data, &off, 3, 0x08u, &name) ||
          !ReadQpackString(data, &off, 7, 0x80u, &val)) {
        return false;
      }
      out_headers->push_back(
          HttpHeaderField{ToLowerAscii(name), std::move(val)});
    } else {
      return false;
    }
  }
  return true;
}

// ======================= Http3Frame 与 Http3Settings 实现 =======================

void Http3Frame::Append(uint64_t type,
                        ArrayView<const uint8_t> payload,
                        std::vector<uint8_t>* out) {
  QuicVarInt::Append(type, out);
  QuicVarInt::Append(payload.size(), out);
  out->insert(out->end(), payload.begin(), payload.end());
}

std::optional<Http3Frame> Http3Frame::Decode(ArrayView<const uint8_t> data,
                                             size_t* consumed) {
  size_t off = 0;
  uint64_t ftype = 0;
  uint64_t flen = 0;
  if (!QuicVarInt::Read(data, &off, &ftype) ||
      !QuicVarInt::Read(data, &off, &flen) || off + flen > data.size()) {
    return std::nullopt;
  }
  Http3Frame f;
  f.type = ftype;
  f.payload.assign(data.data() + off,
                   data.data() + off + static_cast<size_t>(flen));
  *consumed = off + static_cast<size_t>(flen);
  return f;
}

std::vector<uint8_t> Http3Settings::EncodeFrame() const {
  std::vector<uint8_t> body;
  body.reserve(64);
  auto put = [&body](uint64_t id, uint64_t val) {
    QuicVarInt::Append(id, &body);
    QuicVarInt::Append(val, &body);
  };
  put(kH3SettingsQpackMaxTableCapacity, qpack_max_table_capacity);
  put(kH3SettingsMaxFieldSectionSize, max_field_section_size);
  put(kH3SettingsQpackBlockedStreams, qpack_blocked_streams);
  if (enable_connect_protocol) {
    put(kH3SettingsEnableConnectProtocol, 1);
  }
  if (h3_datagram) {
    put(kH3SettingsH3Datagram, 1);
    put(kH3SettingsH3DatagramDraft00, 1);
  }
  if (wt_max_sessions > 0) {
    put(kH3SettingsWtMaxSessions, wt_max_sessions);
    put(kH3SettingsWtMaxSessionsDraft07, wt_max_sessions);
    put(kH3SettingsEnableWebTransportLegacy, 1);
    put(kH3SettingsWtInitialMaxData, wt_initial_max_data);
    put(kH3SettingsWtInitialMaxStreamsUni, wt_initial_max_streams_uni);
    put(kH3SettingsWtInitialMaxStreamsBidi, wt_initial_max_streams_bidi);
  }

  std::vector<uint8_t> frame;
  Http3Frame::Append(kH3FrameSettings, body, &frame);
  return frame;
}

std::optional<Http3Settings> Http3Settings::DecodePayload(
    ArrayView<const uint8_t> payload) {
  Http3Settings s;
  s.enable_connect_protocol = false;
  s.h3_datagram = false;
  s.wt_max_sessions = 0;
  s.wt_initial_max_data = 0;
  s.wt_initial_max_streams_uni = 0;
  s.wt_initial_max_streams_bidi = 0;

  size_t off = 0;
  while (off < payload.size()) {
    uint64_t id = 0;
    uint64_t val = 0;
    if (!QuicVarInt::Read(payload, &off, &id) ||
        !QuicVarInt::Read(payload, &off, &val)) {
      return std::nullopt;
    }
    switch (id) {
      case kH3SettingsQpackMaxTableCapacity:
        s.qpack_max_table_capacity = val;
        break;
      case kH3SettingsMaxFieldSectionSize:
        s.max_field_section_size = val;
        break;
      case kH3SettingsQpackBlockedStreams:
        s.qpack_blocked_streams = val;
        break;
      case kH3SettingsEnableConnectProtocol:
        if (val > 1) {
          return std::nullopt;
        }
        s.enable_connect_protocol = (val == 1);
        break;
      case kH3SettingsH3Datagram:
      case kH3SettingsH3DatagramDraft00:
        if (val > 1) {
          return std::nullopt;
        }
        if (val == 1) {
          s.h3_datagram = true;
        }
        break;
      case kH3SettingsWtMaxSessions:
      case kH3SettingsWtMaxSessionsDraft07:
        s.wt_max_sessions = std::max(s.wt_max_sessions, val);
        break;
      case kH3SettingsEnableWebTransportLegacy:
        if (val == 1 && s.wt_max_sessions == 0) {
          s.wt_max_sessions = 1;
        }
        break;
      case kH3SettingsWtInitialMaxData:
        s.wt_initial_max_data = val;
        break;
      case kH3SettingsWtInitialMaxStreamsUni:
        s.wt_initial_max_streams_uni = val;
        break;
      case kH3SettingsWtInitialMaxStreamsBidi:
        s.wt_initial_max_streams_bidi = val;
        break;
      default:
        break;
    }
  }
  return s;
}

// ======================= WebTransportCapsule 与辅助函数实现 =======================

std::vector<uint8_t> WebTransportCapsule::Encode(
    uint64_t type,
    ArrayView<const uint8_t> value) {
  std::vector<uint8_t> out;
  out.reserve(16 + value.size());
  QuicVarInt::Append(type, &out);
  QuicVarInt::Append(value.size(), &out);
  out.insert(out.end(), value.begin(), value.end());
  return out;
}

std::optional<WebTransportCapsule> WebTransportCapsule::Decode(
    ArrayView<const uint8_t> data,
    size_t* consumed) {
  size_t off = 0;
  uint64_t ctype = 0;
  uint64_t clen = 0;
  if (!QuicVarInt::Read(data, &off, &ctype) ||
      !QuicVarInt::Read(data, &off, &clen) || off + clen > data.size()) {
    return std::nullopt;
  }
  WebTransportCapsule cap;
  cap.type = ctype;
  cap.value.assign(data.data() + off,
                   data.data() + off + static_cast<size_t>(clen));
  *consumed = off + static_cast<size_t>(clen);
  return cap;
}

std::vector<uint8_t> WebTransportCapsule::EncodeCloseSession(
    uint32_t app_error_code,
    std::string_view error_msg) {
  const size_t msg_len = std::min<size_t>(error_msg.size(), 1024);
  std::vector<uint8_t> val(4 + msg_len);
  WriteBigEndian32(val.data(), app_error_code);
  if (msg_len > 0) {
    std::memcpy(val.data() + 4, error_msg.data(), msg_len);
  }
  return Encode(kWtCapsuleCloseSession, val);
}

bool WebTransportCapsule::DecodeCloseSession(ArrayView<const uint8_t> value,
                                             uint32_t* out_error_code,
                                             std::string* out_error_msg) {
  if (value.size() < 4 || value.size() > 4 + 1024) {
    return false;
  }
  *out_error_code = ReadBigEndian32(value.data());
  out_error_msg->assign(reinterpret_cast<const char*>(value.data() + 4),
                        value.size() - 4);
  return true;
}

uint64_t WebTransportCodeToHttp3Code(uint32_t app_code) {
  constexpr uint64_t kFirst = 0x52E4A40FA8DBULL;
  const uint64_t n = static_cast<uint64_t>(app_code);
  return kFirst + n + (n / 0x1EULL);
}

std::optional<uint32_t> Http3CodeToWebTransportCode(uint64_t http3_code) {
  constexpr uint64_t kFirst = 0x52E4A40FA8DBULL;
  constexpr uint64_t kLast = 0x52E5AC983162ULL;
  if (http3_code < kFirst || http3_code > kLast) {
    return std::nullopt;
  }
  if ((http3_code - 0x21ULL) % 0x1FULL == 0) {
    return std::nullopt;
  }
  const uint64_t shifted = http3_code - kFirst;
  return static_cast<uint32_t>(shifted - (shifted / 0x1FULL));
}

std::string FormatWtAvailableProtocols(const std::vector<std::string>& protos) {
  std::string out;
  for (size_t i = 0; i < protos.size(); ++i) {
    if (i > 0) {
      out += ", ";
    }
    out += FormatWtProtocol(protos[i]);
  }
  return out;
}

std::vector<std::string> ParseWtAvailableProtocols(std::string_view field_val) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < field_val.size()) {
    while (i < field_val.size() &&
           (field_val[i] == ' ' || field_val[i] == '\t' ||
            field_val[i] == ',')) {
      ++i;
    }
    if (i >= field_val.size()) {
      break;
    }
    if (field_val[i] == '"') {
      ++i;
      std::string item;
      bool closed = false;
      while (i < field_val.size()) {
        if (field_val[i] == '\\' && i + 1 < field_val.size()) {
          item.push_back(field_val[i + 1]);
          i += 2;
        } else if (field_val[i] == '"') {
          ++i;
          closed = true;
          break;
        } else {
          item.push_back(field_val[i++]);
        }
      }
      if (!closed) {
        return {};
      }
      // 跳过 RFC 9651 结构化字段参数（如 ;param=val）。
      while (i < field_val.size() && field_val[i] != ',') {
        ++i;
      }
      if (!item.empty()) {
        out.push_back(std::move(item));
      }
    } else {
      // 兼容裸 token 写法。
      const size_t start = i;
      while (i < field_val.size() && field_val[i] != ',' &&
             field_val[i] != ';' && field_val[i] != ' ') {
        ++i;
      }
      if (i > start) {
        out.emplace_back(field_val.substr(start, i - start));
      }
      while (i < field_val.size() && field_val[i] != ',') {
        ++i;
      }
    }
  }
  return out;
}

std::string FormatWtProtocol(std::string_view proto) {
  std::string out;
  out.reserve(proto.size() + 2);
  out.push_back('"');
  for (char c : proto) {
    if (c == '"' || c == '\\') {
      out.push_back('\\');
    }
    out.push_back(c);
  }
  out.push_back('"');
  return out;
}

std::optional<std::string> ParseWtProtocol(std::string_view field_val) {
  const auto list = ParseWtAvailableProtocols(field_val);
  if (list.empty()) {
    return std::nullopt;
  }
  return list.front();
}

std::vector<uint8_t> EncodeHttp3Datagram(uint64_t connect_stream_id,
                                         ArrayView<const uint8_t> payload) {
  std::vector<uint8_t> out;
  out.reserve(8 + payload.size());
  QuicVarInt::Append(connect_stream_id >> 2, &out);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

bool DecodeHttp3Datagram(ArrayView<const uint8_t> wire,
                         uint64_t* out_connect_stream_id,
                         ArrayView<const uint8_t>* out_payload) {
  size_t off = 0;
  uint64_t quarter_id = 0;
  if (!QuicVarInt::Read(wire, &off, &quarter_id) ||
      quarter_id > (uint64_t{1} << 60)) {
    return false;
  }
  *out_connect_stream_id = quarter_id << 2;
  *out_payload = wire.subview(off);
  return true;
}

// ======================= WebTransportClientEngine 客户端实现 =======================

WebTransportClientEngine::WebTransportClientEngine(
    std::shared_ptr<IMoqQuicEngine> inner_quic,
    std::string authority,
    std::string path,
    std::vector<std::string> available_protocols)
    : inner_quic_(std::move(inner_quic)),
      authority_(std::move(authority)),
      path_(path.empty() ? "/moq" : std::move(path)),
      available_protocols_(std::move(available_protocols)) {
  if (inner_quic_) {
    inner_quic_->SetObserver(this);
  }
}

WebTransportClientEngine::~WebTransportClientEngine() { Close(0); }

void WebTransportClientEngine::SetEndpointConfig(
    std::string authority,
    std::string path,
    std::vector<std::string> available_protocols) {
  std::lock_guard<std::mutex> lock(mu_);
  authority_ = std::move(authority);
  path_ = path.empty() ? "/moq" : std::move(path);
  available_protocols_ = std::move(available_protocols);
}

std::string WebTransportClientEngine::negotiated_wt_protocol() const {
  std::lock_guard<std::mutex> lock(mu_);
  return negotiated_wt_protocol_;
}

void WebTransportClientEngine::SetObserver(IMoqQuicEngineObserver* observer) {
  std::lock_guard<std::mutex> lock(mu_);
  observer_ = observer;
}

int WebTransportClientEngine::Connect(const std::string& host,
                                      uint16_t port,
                                      const std::string& /*alpn*/) {
  if (!inner_quic_) {
    return RTC_ERR_NOT_INITIALIZED;
  }
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (authority_.empty()) {
      authority_ = host + ":" + std::to_string(port);
    }
    closed_ = false;
  }
  return inner_quic_->Connect(host, port, "h3");
}

void WebTransportClientEngine::Close(uint64_t app_error_code) {
  bool should_send_close_capsule = false;
  uint64_t conn_sid = 0;
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (closed_) {
      return;
    }
    closed_ = true;
    should_send_close_capsule = wt_established_;
    conn_sid = connect_stream_id_;
    wt_established_ = false;
  }
  if (inner_quic_) {
    if (should_send_close_capsule) {
      const auto cap = WebTransportCapsule::EncodeCloseSession(
          static_cast<uint32_t>(app_error_code), "");
      std::vector<uint8_t> data_frame;
      Http3Frame::Append(kH3FrameData, cap, &data_frame);
      inner_quic_->WriteStream(conn_sid, data_frame, /*fin=*/true);
    }
    inner_quic_->Close(kH3NoError);
  }
}

int WebTransportClientEngine::SendHttp3Request(const Http3Request& req,
                                               Http3ResponseCallback on_resp) {
  if (!inner_quic_) {
    return RTC_ERR_NOT_INITIALIZED;
  }
  uint64_t req_sid = 0;
  std::vector<uint8_t> wire_bytes;
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (closed_) {
      return RTC_ERR_NOT_CONNECTED;
    }
    if (!quic_connected_) {
      pending_h3_requests_.emplace_back(req, std::move(on_resp));
      return RTC_OK;
    }
    req_sid = inner_quic_->OpenBidirectionalStream();
    std::vector<HttpHeaderField> hdrs = {
        {":method", req.method},
        {":scheme", req.scheme.empty() ? "https" : req.scheme},
        {":authority", req.authority.empty() ? authority_ : req.authority},
        {":path", req.path.empty() ? "/" : req.path},
    };
    if (!req.protocol.empty()) {
      hdrs.push_back({":protocol", req.protocol});
    }
    hdrs.insert(hdrs.end(), req.headers.begin(), req.headers.end());
    wire_bytes = BuildHttp3HeadersFrameFromMap(hdrs);
    if (!req.body.empty()) {
      Http3Frame::Append(kH3FrameData, req.body, &wire_bytes);
    }
    InboundH3RequestState st;
    st.callback = std::move(on_resp);
    h3_responses_.emplace(req_sid, std::move(st));
  }
  inner_quic_->WriteStream(req_sid, wire_bytes, /*fin=*/true);
  return RTC_OK;
}

uint64_t WebTransportClientEngine::OpenBidirectionalStream() {
  const uint64_t sid = inner_quic_->OpenBidirectionalStream();
  std::vector<uint8_t> prefix;
  bool write_now = false;
  {
    std::lock_guard<std::mutex> lock(mu_);
    wt_local_streams_[sid] = LocalWtStreamState{false, false, false};
    if (wt_established_) {
      QuicVarInt::Append(kWtStreamSignalBidi, &prefix);
      QuicVarInt::Append(connect_stream_id_, &prefix);
      wt_prefix_written_.insert(sid);
      write_now = true;
    }
  }
  if (write_now) {
    inner_quic_->WriteStream(sid, prefix, /*fin=*/false);
  }
  return sid;
}

uint64_t WebTransportClientEngine::OpenUnidirectionalStream(
    uint8_t publisher_priority,
    int64_t send_order) {
  const uint64_t sid =
      inner_quic_->OpenUnidirectionalStream(publisher_priority, send_order);
  std::vector<uint8_t> prefix;
  bool write_now = false;
  {
    std::lock_guard<std::mutex> lock(mu_);
    wt_local_streams_[sid] = LocalWtStreamState{true, false, false};
    if (wt_established_) {
      QuicVarInt::Append(kH3StreamTypeWebTransportUni, &prefix);
      QuicVarInt::Append(connect_stream_id_, &prefix);
      wt_prefix_written_.insert(sid);
      write_now = true;
    }
  }
  if (write_now) {
    inner_quic_->WriteStream(sid, prefix, /*fin=*/false);
  }
  return sid;
}

int WebTransportClientEngine::WriteStream(uint64_t stream_id,
                                          ArrayView<const uint8_t> data,
                                          bool fin) {
  std::vector<uint8_t> out_bytes;
  {
    std::lock_guard<std::mutex> lock(mu_);
    const auto local_it = wt_local_streams_.find(stream_id);
    if (local_it != wt_local_streams_.end() && !wt_established_) {
      local_it->second.local_fin = local_it->second.local_fin || fin;
      pending_wt_writes_[stream_id].push_back(
          PendingOutboundChunk{std::vector<uint8_t>(data.begin(), data.end()),
                               fin});
      return static_cast<int>(data.size());
    }
    if (local_it != wt_local_streams_.end()) {
      if (wt_prefix_written_.insert(stream_id).second) {
        QuicVarInt::Append(local_it->second.is_uni ? kH3StreamTypeWebTransportUni
                                                   : kWtStreamSignalBidi,
                           &out_bytes);
        QuicVarInt::Append(connect_stream_id_, &out_bytes);
      }
      if (fin) {
        local_it->second.local_fin = true;
        if (local_it->second.is_uni || local_it->second.remote_fin) {
          wt_local_streams_.erase(local_it);
          wt_prefix_written_.erase(stream_id);
        }
      }
    }
  }
  out_bytes.insert(out_bytes.end(), data.begin(), data.end());
  inner_quic_->WriteStream(stream_id, out_bytes, fin);
  return static_cast<int>(data.size());
}

void WebTransportClientEngine::ResetStream(uint64_t stream_id,
                                           uint64_t app_error_code) {
  {
    std::lock_guard<std::mutex> lock(mu_);
    wt_local_streams_.erase(stream_id);
    wt_prefix_written_.erase(stream_id);
    pending_wt_writes_.erase(stream_id);
  }
  const uint64_t h3_err =
      WebTransportCodeToHttp3Code(static_cast<uint32_t>(app_error_code));
  inner_quic_->ResetStream(stream_id, h3_err);
}

void WebTransportClientEngine::StopSending(uint64_t stream_id,
                                           uint64_t app_error_code) {
  const uint64_t h3_err =
      WebTransportCodeToHttp3Code(static_cast<uint32_t>(app_error_code));
  inner_quic_->StopSending(stream_id, h3_err);
}

int WebTransportClientEngine::SendDatagram(ArrayView<const uint8_t> data) {
  uint64_t conn_sid = 0;
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (closed_) {
      return RTC_ERR_NOT_CONNECTED;
    }
    if (!wt_established_) {
      if (pending_wt_datagrams_.size() < 128) {
        pending_wt_datagrams_.emplace_back(data.begin(), data.end());
      }
      return RTC_OK;
    }
    conn_sid = connect_stream_id_;
  }
  const auto h3_dgram = EncodeHttp3Datagram(conn_sid, data);
  return inner_quic_->SendDatagram(h3_dgram);
}

size_t WebTransportClientEngine::max_datagram_size() const {
  const size_t base = inner_quic_ ? inner_quic_->max_datagram_size() : 0;
  return base > 8 ? (base - 8) : 0;
}

std::string WebTransportClientEngine::negotiated_alpn() const {
  return inner_quic_ ? inner_quic_->negotiated_alpn() : "h3";
}

QuicCongestionSnapshot WebTransportClientEngine::GetCongestionSnapshot() const {
  return inner_quic_ ? inner_quic_->GetCongestionSnapshot()
                     : QuicCongestionSnapshot{};
}

int WebTransportClientEngine::SetCongestionController(
    std::unique_ptr<IQuicCongestionController> controller) {
  return inner_quic_ ? inner_quic_->SetCongestionController(std::move(controller))
                     : RTC_ERR_NOT_INITIALIZED;
}

void WebTransportClientEngine::OnQuicConnected() {
  uint64_t ctrl_sid =
      inner_quic_->OpenUnidirectionalStream(0, std::numeric_limits<int64_t>::max());
  std::vector<uint8_t> ctrl_init;
  QuicVarInt::Append(kH3StreamTypeControl, &ctrl_init);
  Http3Settings local_settings;
  const auto settings_frame = local_settings.EncodeFrame();
  ctrl_init.insert(ctrl_init.end(), settings_frame.begin(),
                   settings_frame.end());

  std::vector<std::pair<Http3Request, Http3ResponseCallback>> queued_reqs;
  std::vector<std::pair<uint64_t, std::vector<uint8_t>>> connect_write;
  {
    std::lock_guard<std::mutex> lock(mu_);
    quic_connected_ = true;
    local_ctrl_stream_id_ = ctrl_sid;
    queued_reqs.swap(pending_h3_requests_);
    if (peer_settings_received_ && !connect_sent_) {
      TrySendExtendedConnectLocked();
      if (connect_sent_) {
        std::vector<HttpHeaderField> hdrs = {
            {":method", "CONNECT"},
            {":scheme", "https"},
            {":authority", authority_},
            {":path", path_},
            {":protocol", "webtransport"},
        };
        if (!available_protocols_.empty()) {
          hdrs.push_back({"wt-available-protocols",
                          FormatWtAvailableProtocols(available_protocols_)});
        }
        hdrs.push_back({"sec-webtransport-http3-draft02", "1"});
        connect_write.emplace_back(connect_stream_id_,
                                   BuildHttp3HeadersFrameFromMap(hdrs));
      }
    }
  }

  inner_quic_->WriteStream(ctrl_sid, ctrl_init, /*fin=*/false);
  for (const auto& [sid, bytes] : connect_write) {
    inner_quic_->WriteStream(sid, bytes, /*fin=*/false);
  }
  for (auto& [req, cb] : queued_reqs) {
    SendHttp3Request(req, std::move(cb));
  }
}

void WebTransportClientEngine::OnQuicDisconnected(int error_code) {
  IMoqQuicEngineObserver* obs = nullptr;
  {
    std::lock_guard<std::mutex> lock(mu_);
    quic_connected_ = false;
    wt_established_ = false;
    obs = observer_;
  }
  if (obs != nullptr) {
    obs->OnQuicDisconnected(error_code);
  }
}

void WebTransportClientEngine::OnStreamOpened(uint64_t stream_id,
                                              bool unidirectional) {
  std::lock_guard<std::mutex> lock(mu_);
  if (unidirectional) {
    inbound_uni_.try_emplace(stream_id);
  } else {
    inbound_bidi_.try_emplace(stream_id);
  }
}

void WebTransportClientEngine::OnStreamData(uint64_t stream_id,
                                            ArrayView<const uint8_t> data,
                                            bool fin) {
  std::vector<std::function<void()>> actions;
  {
    std::lock_guard<std::mutex> lock(mu_);
    const bool is_uni = (stream_id & 0x02u) != 0;
    if (is_uni) {
      auto& st = inbound_uni_[stream_id];
      st.buf.insert(st.buf.end(), data.begin(), data.end());
      if (!st.type_parsed) {
        size_t off = 0;
        if (!QuicVarInt::Read(st.buf, &off, &st.stream_type)) {
          return;
        }
        st.type_parsed = true;
        st.buf.erase(st.buf.begin(),
                     st.buf.begin() + static_cast<ptrdiff_t>(off));
      }

      if (st.stream_type == kH3StreamTypeControl) {
        const bool had_connect = connect_sent_;
        HandleControlStreamFramesLocked(&st.buf);
        if (!had_connect && connect_sent_) {
          std::vector<HttpHeaderField> hdrs = {
              {":method", "CONNECT"},
              {":scheme", "https"},
              {":authority", authority_},
              {":path", path_},
              {":protocol", "webtransport"},
          };
          if (!available_protocols_.empty()) {
            hdrs.push_back({"wt-available-protocols",
                            FormatWtAvailableProtocols(available_protocols_)});
          }
          hdrs.push_back({"sec-webtransport-http3-draft02", "1"});
          const uint64_t csid = connect_stream_id_;
          auto wire = BuildHttp3HeadersFrameFromMap(hdrs);
          actions.push_back([this, csid, w = std::move(wire)]() {
            inner_quic_->WriteStream(csid, w, /*fin=*/false);
          });
        }
      } else if (st.stream_type == kH3StreamTypeWebTransportUni) {
        if (!st.wt_session_parsed) {
          size_t off = 0;
          if (!QuicVarInt::Read(st.buf, &off, &st.wt_session_id)) {
            return;
          }
          st.wt_session_parsed = true;
          st.buf.erase(st.buf.begin(),
                       st.buf.begin() + static_cast<ptrdiff_t>(off));
        }
        if (wt_established_ && st.wt_session_id == connect_stream_id_) {
          IMoqQuicEngineObserver* obs = observer_;
          const bool need_open = !st.opened_notified;
          st.opened_notified = true;
          std::vector<uint8_t> payload;
          payload.swap(st.buf);
          if (obs != nullptr) {
            actions.push_back([obs, stream_id, need_open,
                               p = std::move(payload), fin]() {
              if (need_open) {
                obs->OnStreamOpened(stream_id, /*unidirectional=*/true);
              }
              if (!p.empty() || fin) {
                obs->OnStreamData(stream_id, p, fin);
              }
            });
          }
          if (fin) {
            inbound_uni_.erase(stream_id);
          }
        }
      } else {
        // 忽略未知或 QPACK 单向流（RFC 9114 第 6.2.3 节）。
        st.buf.clear();
      }
    } else if (connect_sent_ && stream_id == connect_stream_id_) {
      const bool was_est = wt_established_;
      HandleConnectStreamBytesLocked(data, fin);
      if (!was_est && wt_established_) {
        IMoqQuicEngineObserver* obs = observer_;
        if (obs != nullptr) {
          actions.push_back([obs]() { obs->OnQuicConnected(); });
        }
        // 冲刷握手完成前缓存的出站流、出站数据报以及提前到达的对端流/数据报。
        for (auto it = wt_local_streams_.begin();
             it != wt_local_streams_.end();) {
          const uint64_t sid = it->first;
          const bool is_uni_local = it->second.is_uni;
          const bool fin_already = it->second.local_fin;
          std::vector<uint8_t> pfx;
          if (wt_prefix_written_.insert(sid).second) {
            QuicVarInt::Append(
                is_uni_local ? kH3StreamTypeWebTransportUni : kWtStreamSignalBidi,
                &pfx);
            QuicVarInt::Append(connect_stream_id_, &pfx);
          }
          auto pend_it = pending_wt_writes_.find(sid);
          if (pend_it == pending_wt_writes_.end()) {
            if (!pfx.empty()) {
              actions.push_back([this, sid, b = std::move(pfx)]() {
                inner_quic_->WriteStream(sid, b, /*fin=*/false);
              });
            }
          } else {
            auto chunks = std::move(pend_it->second);
            pending_wt_writes_.erase(pend_it);
            actions.push_back(
                [this, sid, p = std::move(pfx), chs = std::move(chunks)]() {
                  if (!p.empty()) {
                    inner_quic_->WriteStream(sid, p, /*fin=*/false);
                  }
                  for (const auto& c : chs) {
                    inner_quic_->WriteStream(sid, c.data, c.fin);
                  }
                });
          }
          if (fin_already && (is_uni_local || it->second.remote_fin)) {
            wt_prefix_written_.erase(sid);
            it = wt_local_streams_.erase(it);
          } else {
            ++it;
          }
        }
        for (auto& dg : pending_wt_datagrams_) {
          auto wire = EncodeHttp3Datagram(connect_stream_id_, dg);
          actions.push_back([this, w = std::move(wire)]() {
            inner_quic_->SendDatagram(w);
          });
        }
        pending_wt_datagrams_.clear();

        for (auto& [usid, ust] : inbound_uni_) {
          if (ust.wt_session_parsed && ust.wt_session_id == connect_stream_id_ &&
              !ust.opened_notified && obs != nullptr) {
            ust.opened_notified = true;
            std::vector<uint8_t> p;
            p.swap(ust.buf);
            actions.push_back([obs, usid, b = std::move(p)]() {
              obs->OnStreamOpened(usid, /*unidirectional=*/true);
              if (!b.empty()) {
                obs->OnStreamData(usid, b, /*fin=*/false);
              }
            });
          }
        }
        for (auto& [bsid, bst] : inbound_bidi_) {
          if (bst.prefix_parsed && bst.wt_session_id == connect_stream_id_ &&
              !bst.opened_notified && obs != nullptr) {
            bst.opened_notified = true;
            std::vector<uint8_t> p;
            p.swap(bst.buf);
            actions.push_back([obs, bsid, b = std::move(p)]() {
              obs->OnStreamOpened(bsid, /*unidirectional=*/false);
              if (!b.empty()) {
                obs->OnStreamData(bsid, b, /*fin=*/false);
              }
            });
          }
        }
        for (auto& edg : early_rx_datagrams_) {
          if (obs != nullptr) {
            actions.push_back(
                [obs, d = std::move(edg)]() { obs->OnDatagramReceived(d); });
          }
        }
        early_rx_datagrams_.clear();
      }
      if (closed_ && observer_ != nullptr) {
        IMoqQuicEngineObserver* obs = observer_;
        actions.push_back([obs]() { obs->OnQuicDisconnected(0); });
      }
    } else if (h3_responses_.find(stream_id) != h3_responses_.end()) {
      auto& rst = h3_responses_[stream_id];
      rst.rx_buf.insert(rst.rx_buf.end(), data.begin(), data.end());
      while (!rst.rx_buf.empty()) {
        size_t consumed = 0;
        auto frame = Http3Frame::Decode(rst.rx_buf, &consumed);
        if (!frame.has_value()) {
          break;
        }
        rst.rx_buf.erase(rst.rx_buf.begin(),
                         rst.rx_buf.begin() + static_cast<ptrdiff_t>(consumed));
        if (frame->type == kH3FrameHeaders) {
          std::vector<HttpHeaderField> decoded;
          if (QpackCodec::DecodeFieldSection(frame->payload, &decoded)) {
            rst.headers_parsed = true;
            for (auto& h : decoded) {
              if (h.name == ":status") {
                rst.resp.status = std::atoi(h.value.c_str());
              } else {
                rst.resp.headers.push_back(std::move(h));
              }
            }
          }
        } else if (frame->type == kH3FrameData) {
          rst.resp.body.insert(rst.resp.body.end(), frame->payload.begin(),
                               frame->payload.end());
        }
      }
      if (fin) {
        auto cb = std::move(rst.callback);
        Http3Response final_resp = std::move(rst.resp);
        h3_responses_.erase(stream_id);
        if (cb) {
          actions.push_back([c = std::move(cb), r = std::move(final_resp)]() {
            c(r);
          });
        }
      }
    } else if (wt_local_streams_.find(stream_id) != wt_local_streams_.end()) {
      // 本端发起的 WebTransport 双向流的响应方向数据直接透传给上层。
      const auto local_it = wt_local_streams_.find(stream_id);
      if (fin) {
        local_it->second.remote_fin = true;
        if (local_it->second.local_fin) {
          wt_local_streams_.erase(local_it);
          wt_prefix_written_.erase(stream_id);
        }
      }
      IMoqQuicEngineObserver* obs = observer_;
      if (obs != nullptr) {
        std::vector<uint8_t> copy(data.begin(), data.end());
        actions.push_back([obs, stream_id, b = std::move(copy), fin]() {
          obs->OnStreamData(stream_id, b, fin);
        });
      }
    } else {
      // 服务端主动发起的 WebTransport 双向流（首部为 0x41 + SessionID）。
      auto& bst = inbound_bidi_[stream_id];
      bst.buf.insert(bst.buf.end(), data.begin(), data.end());
      if (!bst.prefix_parsed) {
        size_t off = 0;
        uint64_t sig = 0;
        uint64_t sess_id = 0;
        if (!QuicVarInt::Read(bst.buf, &off, &sig) ||
            !QuicVarInt::Read(bst.buf, &off, &sess_id)) {
          return;
        }
        if (sig != kWtStreamSignalBidi) {
          return;
        }
        bst.prefix_parsed = true;
        bst.wt_session_id = sess_id;
        bst.buf.erase(bst.buf.begin(),
                      bst.buf.begin() + static_cast<ptrdiff_t>(off));
      }
      if (wt_established_ && bst.wt_session_id == connect_stream_id_) {
        IMoqQuicEngineObserver* obs = observer_;
        const bool need_open = !bst.opened_notified;
        bst.opened_notified = true;
        std::vector<uint8_t> payload;
        payload.swap(bst.buf);
        if (obs != nullptr) {
          actions.push_back(
              [obs, stream_id, need_open, p = std::move(payload), fin]() {
                if (need_open) {
                  obs->OnStreamOpened(stream_id, /*unidirectional=*/false);
                }
                if (!p.empty() || fin) {
                  obs->OnStreamData(stream_id, p, fin);
                }
              });
        }
        if (fin) {
          inbound_bidi_.erase(stream_id);
        }
      }
    }
  }

  for (auto& act : actions) {
    act();
  }
}

void WebTransportClientEngine::OnStreamReset(uint64_t stream_id,
                                             uint64_t app_error_code) {
  IMoqQuicEngineObserver* obs = nullptr;
  bool is_connect = false;
  {
    std::lock_guard<std::mutex> lock(mu_);
    obs = observer_;
    is_connect = (connect_sent_ && stream_id == connect_stream_id_);
    if (is_connect) {
      wt_established_ = false;
      closed_ = true;
    }
    inbound_uni_.erase(stream_id);
    inbound_bidi_.erase(stream_id);
    wt_local_streams_.erase(stream_id);
    wt_prefix_written_.erase(stream_id);
    pending_wt_writes_.erase(stream_id);
  }
  if (obs == nullptr) {
    return;
  }
  if (is_connect) {
    obs->OnQuicDisconnected(static_cast<int>(app_error_code));
    return;
  }
  const auto mapped = Http3CodeToWebTransportCode(app_error_code);
  obs->OnStreamReset(stream_id, mapped.value_or(app_error_code));
}

void WebTransportClientEngine::OnStreamStopSending(uint64_t stream_id,
                                                   uint64_t app_error_code) {
  IMoqQuicEngineObserver* obs = nullptr;
  {
    std::lock_guard<std::mutex> lock(mu_);
    obs = observer_;
  }
  if (obs != nullptr) {
    const auto mapped = Http3CodeToWebTransportCode(app_error_code);
    obs->OnStreamStopSending(stream_id, mapped.value_or(app_error_code));
  }
}

void WebTransportClientEngine::OnDatagramReceived(
    ArrayView<const uint8_t> data) {
  uint64_t target_conn_sid = 0;
  ArrayView<const uint8_t> wt_payload;
  if (!DecodeHttp3Datagram(data, &target_conn_sid, &wt_payload)) {
    return;
  }
  IMoqQuicEngineObserver* obs = nullptr;
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (!wt_established_) {
      if (connect_sent_ && target_conn_sid == connect_stream_id_ &&
          early_rx_datagrams_.size() < 64) {
        early_rx_datagrams_.emplace_back(wt_payload.begin(), wt_payload.end());
      }
      return;
    }
    if (target_conn_sid != connect_stream_id_) {
      return;
    }
    obs = observer_;
  }
  if (obs != nullptr) {
    obs->OnDatagramReceived(wt_payload);
  }
}

void WebTransportClientEngine::TrySendExtendedConnectLocked() {
  if (!quic_connected_ || !peer_settings_received_ || connect_sent_ ||
      closed_) {
    return;
  }
  if (peer_settings_.wt_max_sessions == 0 ||
      !peer_settings_.enable_connect_protocol) {
    RTC_LOG(kError)
        << "HTTP/3 server SETTINGS did not advertise WebTransport support";
    return;
  }
  connect_stream_id_ = inner_quic_->OpenBidirectionalStream();
  connect_sent_ = true;
}

void WebTransportClientEngine::HandleControlStreamFramesLocked(
    std::vector<uint8_t>* buf) {
  while (!buf->empty()) {
    size_t consumed = 0;
    auto frame = Http3Frame::Decode(*buf, &consumed);
    if (!frame.has_value()) {
      break;
    }
    buf->erase(buf->begin(), buf->begin() + static_cast<ptrdiff_t>(consumed));
    if (frame->type == kH3FrameSettings && !peer_settings_received_) {
      auto parsed = Http3Settings::DecodePayload(frame->payload);
      if (parsed.has_value()) {
        peer_settings_ = *parsed;
        peer_settings_received_ = true;
        TrySendExtendedConnectLocked();
      }
    }
  }
}

void WebTransportClientEngine::HandleConnectStreamBytesLocked(
    ArrayView<const uint8_t> data,
    bool fin) {
  connect_rx_buf_.insert(connect_rx_buf_.end(), data.begin(), data.end());
  while (!connect_rx_buf_.empty()) {
    size_t consumed = 0;
    auto frame = Http3Frame::Decode(connect_rx_buf_, &consumed);
    if (!frame.has_value()) {
      break;
    }
    connect_rx_buf_.erase(
        connect_rx_buf_.begin(),
        connect_rx_buf_.begin() + static_cast<ptrdiff_t>(consumed));

    if (frame->type == kH3FrameHeaders && !wt_established_) {
      std::vector<HttpHeaderField> hdrs;
      if (!QpackCodec::DecodeFieldSection(frame->payload, &hdrs)) {
        closed_ = true;
        return;
      }
      int status = 0;
      for (const auto& h : hdrs) {
        if (h.name == ":status") {
          status = std::atoi(h.value.c_str());
        } else if (h.name == "wt-protocol") {
          auto parsed_p = ParseWtProtocol(h.value);
          if (parsed_p.has_value()) {
            negotiated_wt_protocol_ = *parsed_p;
          }
        }
      }
      if (status >= 200 && status < 300) {
        wt_established_ = true;
        RTC_LOG(kInfo) << "WebTransport over HTTP/3 session="
                       << connect_stream_id_ << " established (WT-Protocol="
                       << negotiated_wt_protocol_ << ")";
      } else {
        RTC_LOG(kError) << "WebTransport CONNECT rejected with HTTP status="
                        << status;
        closed_ = true;
      }
    } else if (frame->type == kH3FrameData) {
      capsule_rx_buf_.insert(capsule_rx_buf_.end(), frame->payload.begin(),
                             frame->payload.end());
      while (!capsule_rx_buf_.empty()) {
        size_t cap_consumed = 0;
        auto cap = WebTransportCapsule::Decode(capsule_rx_buf_, &cap_consumed);
        if (!cap.has_value()) {
          break;
        }
        capsule_rx_buf_.erase(
            capsule_rx_buf_.begin(),
            capsule_rx_buf_.begin() + static_cast<ptrdiff_t>(cap_consumed));
        if (cap->type == kWtCapsuleCloseSession) {
          wt_established_ = false;
          closed_ = true;
        }
      }
    }
  }
  if (fin) {
    wt_established_ = false;
    closed_ = true;
  }
}

// ======================= Http3ServerConnection 服务端实现 =======================

class Http3ServerConnection::WtSessionHandle final
    : public QuicServerSessionHandle {
 public:
  WtSessionHandle(uint64_t virtual_id,
                  uint64_t connect_stream_id,
                  std::string negotiated_proto,
                  std::weak_ptr<Http3ServerConnection> owner,
                  std::shared_ptr<QuicServerSessionHandle> raw_quic)
      : virtual_id_(virtual_id),
        connect_stream_id_(connect_stream_id),
        negotiated_proto_(std::move(negotiated_proto)),
        owner_(std::move(owner)),
        raw_quic_(std::move(raw_quic)) {}

  uint64_t session_id() const override { return virtual_id_; }
  uint64_t connect_stream_id() const { return connect_stream_id_; }
  std::string negotiated_alpn() const override { return negotiated_proto_; }

  uint64_t OpenBidirectionalStream() override {
    if (!raw_quic_) {
      return 0;
    }
    const uint64_t sid = raw_quic_->OpenBidirectionalStream();
    if (auto p = owner_.lock()) {
      p->server_stream_to_connect_sid_[sid] = connect_stream_id_;
    }
    std::vector<uint8_t> prefix;
    QuicVarInt::Append(kWtStreamSignalBidi, &prefix);
    QuicVarInt::Append(connect_stream_id_, &prefix);
    raw_quic_->WriteStream(sid, prefix, /*fin=*/false);
    return sid;
  }

  uint64_t OpenUnidirectionalStream(uint8_t publisher_priority,
                                    int64_t send_order) override {
    if (!raw_quic_) {
      return 0;
    }
    const uint64_t sid =
        raw_quic_->OpenUnidirectionalStream(publisher_priority, send_order);
    if (auto p = owner_.lock()) {
      p->server_stream_to_connect_sid_[sid] = connect_stream_id_;
    }
    std::vector<uint8_t> prefix;
    QuicVarInt::Append(kH3StreamTypeWebTransportUni, &prefix);
    QuicVarInt::Append(connect_stream_id_, &prefix);
    raw_quic_->WriteStream(sid, prefix, /*fin=*/false);
    return sid;
  }

  int WriteStream(uint64_t stream_id,
                  ArrayView<const uint8_t> data,
                  bool fin) override {
    if (!raw_quic_) {
      return -1;
    }
    const int rc = raw_quic_->WriteStream(stream_id, data, fin);
    if (fin && (stream_id & 0x02u) != 0) {
      if (auto p = owner_.lock()) {
        p->server_stream_to_connect_sid_.erase(stream_id);
      }
    }
    return rc;
  }

  void ResetStream(uint64_t stream_id, uint64_t app_error_code) override {
    if (auto p = owner_.lock()) {
      p->server_stream_to_connect_sid_.erase(stream_id);
    }
    if (raw_quic_) {
      raw_quic_->ResetStream(
          stream_id,
          WebTransportCodeToHttp3Code(static_cast<uint32_t>(app_error_code)));
    }
  }

  void StopSending(uint64_t stream_id, uint64_t app_error_code) override {
    if (raw_quic_) {
      raw_quic_->StopSending(
          stream_id,
          WebTransportCodeToHttp3Code(static_cast<uint32_t>(app_error_code)));
    }
  }

  int SendDatagram(ArrayView<const uint8_t> data) override {
    if (!raw_quic_) {
      return RTC_ERR_NOT_CONNECTED;
    }
    const auto wire = EncodeHttp3Datagram(connect_stream_id_, data);
    return raw_quic_->SendDatagram(wire);
  }

  size_t max_datagram_size() const override {
    const size_t base = raw_quic_ ? raw_quic_->max_datagram_size() : 0;
    return base > 8 ? (base - 8) : 0;
  }

  void Close(uint64_t app_error_code) override {
    if (closed_ || !raw_quic_) {
      return;
    }
    closed_ = true;
    const auto cap = WebTransportCapsule::EncodeCloseSession(
        static_cast<uint32_t>(app_error_code), "");
    std::vector<uint8_t> data_frame;
    Http3Frame::Append(kH3FrameData, cap, &data_frame);
    raw_quic_->WriteStream(connect_stream_id_, data_frame, /*fin=*/true);
  }

  QuicCongestionSnapshot GetCongestionSnapshot() const override {
    return raw_quic_ ? raw_quic_->GetCongestionSnapshot()
                     : QuicCongestionSnapshot{};
  }

 private:
  const uint64_t virtual_id_;
  const uint64_t connect_stream_id_;
  const std::string negotiated_proto_;
  std::weak_ptr<Http3ServerConnection> owner_;
  std::shared_ptr<QuicServerSessionHandle> raw_quic_;
  bool closed_ = false;
};

Http3ServerConnection::Http3ServerConnection(
    std::shared_ptr<QuicServerSessionHandle> raw_quic,
    IQuicServerVisitor* wt_visitor,
    std::vector<std::string> supported_wt_protocols,
    Http3RequestHandler http_handler,
    uint64_t virtual_session_id_base)
    : raw_quic_(std::move(raw_quic)),
      wt_visitor_(wt_visitor),
      supported_wt_protocols_(std::move(supported_wt_protocols)),
      http_handler_(std::move(http_handler)),
      next_virtual_session_id_(virtual_session_id_base) {}

Http3ServerConnection::~Http3ServerConnection() = default;

void Http3ServerConnection::Start() {
  if (!raw_quic_) {
    return;
  }
  local_ctrl_stream_id_ = raw_quic_->OpenUnidirectionalStream(
      0, std::numeric_limits<int64_t>::max());
  std::vector<uint8_t> ctrl_init;
  QuicVarInt::Append(kH3StreamTypeControl, &ctrl_init);
  Http3Settings s;
  const auto sf = s.EncodeFrame();
  ctrl_init.insert(ctrl_init.end(), sf.begin(), sf.end());
  raw_quic_->WriteStream(local_ctrl_stream_id_, ctrl_init, /*fin=*/false);
}

void Http3ServerConnection::OnQuicDisconnected(int error_code) {
  if (wt_visitor_ != nullptr) {
    for (const auto& [csid, wt_sess] : wt_sessions_) {
      (void)csid;
      wt_visitor_->OnServerSessionDisconnected(wt_sess->session_id(),
                                               error_code);
    }
  }
  wt_sessions_.clear();
}

void Http3ServerConnection::OnQuicStreamOpened(uint64_t stream_id,
                                               bool unidirectional) {
  if (unidirectional) {
    client_uni_streams_.try_emplace(stream_id);
  } else {
    client_bidi_streams_.try_emplace(stream_id);
  }
}

void Http3ServerConnection::OnQuicStreamData(uint64_t stream_id,
                                             ArrayView<const uint8_t> data,
                                             bool fin) {
  const bool is_uni = (stream_id & 0x02u) != 0;
  if (is_uni) {
    auto& ust = client_uni_streams_[stream_id];
    ust.rx_buf.insert(ust.rx_buf.end(), data.begin(), data.end());
    if (!ust.type_parsed) {
      size_t off = 0;
      if (!QuicVarInt::Read(ust.rx_buf, &off, &ust.stream_type)) {
        return;
      }
      ust.type_parsed = true;
      ust.rx_buf.erase(ust.rx_buf.begin(),
                       ust.rx_buf.begin() + static_cast<ptrdiff_t>(off));
    }

    if (ust.stream_type == kH3StreamTypeControl) {
      ProcessControlFrames(&ust.rx_buf);
    } else if (ust.stream_type == kH3StreamTypeWebTransportUni) {
      if (!ust.wt_session_parsed) {
        size_t off = 0;
        if (!QuicVarInt::Read(ust.rx_buf, &off, &ust.wt_connect_stream_id)) {
          return;
        }
        ust.wt_session_parsed = true;
        ust.rx_buf.erase(ust.rx_buf.begin(),
                         ust.rx_buf.begin() + static_cast<ptrdiff_t>(off));
      }
      const auto sit = wt_sessions_.find(ust.wt_connect_stream_id);
      if (sit != wt_sessions_.end() && wt_visitor_ != nullptr) {
        const uint64_t vsid = sit->second->session_id();
        if (!ust.opened_notified) {
          ust.opened_notified = true;
          wt_visitor_->OnServerStreamOpened(vsid, stream_id,
                                            /*unidirectional=*/true);
        }
        if (!ust.rx_buf.empty() || fin) {
          const std::vector<uint8_t> tmp = std::move(ust.rx_buf);
          ust.rx_buf.clear();
          wt_visitor_->OnServerStreamData(vsid, stream_id, tmp, fin);
        }
        if (fin) {
          client_uni_streams_.erase(stream_id);
        }
      }
    } else {
      ust.rx_buf.clear();
    }
    return;
  }

  // 检查是否为服务端主动创建的 WebTransport 双向流的客户端回复方向。
  const auto srv_it = server_stream_to_connect_sid_.find(stream_id);
  if (srv_it != server_stream_to_connect_sid_.end()) {
    const auto sit = wt_sessions_.find(srv_it->second);
    if (sit != wt_sessions_.end() && wt_visitor_ != nullptr) {
      wt_visitor_->OnServerStreamData(sit->second->session_id(), stream_id,
                                      data, fin);
    }
    if (fin) {
      server_stream_to_connect_sid_.erase(srv_it);
    }
    return;
  }

  auto& bst = client_bidi_streams_[stream_id];
  bst.rx_buf.insert(bst.rx_buf.end(), data.begin(), data.end());

  if (bst.kind == ClientBidiStream::Kind::kUndecided) {
    size_t peek_off = 0;
    uint64_t first_varint = 0;
    if (!QuicVarInt::Read(bst.rx_buf, &peek_off, &first_varint)) {
      return;
    }
    if (first_varint == kWtStreamSignalBidi) {
      uint64_t target_csid = 0;
      if (!QuicVarInt::Read(bst.rx_buf, &peek_off, &target_csid)) {
        return;
      }
      bst.kind = ClientBidiStream::Kind::kWebTransportBidiData;
      bst.wt_connect_stream_id = target_csid;
      bst.rx_buf.erase(bst.rx_buf.begin(),
                       bst.rx_buf.begin() + static_cast<ptrdiff_t>(peek_off));
    } else {
      bst.kind = ClientBidiStream::Kind::kHttp3Request;
    }
  }

  if (bst.kind == ClientBidiStream::Kind::kWebTransportBidiData) {
    const auto sit = wt_sessions_.find(bst.wt_connect_stream_id);
    if (sit != wt_sessions_.end() && wt_visitor_ != nullptr) {
      const uint64_t vsid = sit->second->session_id();
      if (!bst.opened_notified) {
        bst.opened_notified = true;
        wt_visitor_->OnServerStreamOpened(vsid, stream_id,
                                          /*unidirectional=*/false);
      }
      if (!bst.rx_buf.empty() || fin) {
        const std::vector<uint8_t> tmp = std::move(bst.rx_buf);
        bst.rx_buf.clear();
        wt_visitor_->OnServerStreamData(vsid, stream_id, tmp, fin);
      }
      if (fin) {
        client_bidi_streams_.erase(stream_id);
      }
    }
    return;
  }

  ProcessHttpOrConnectFrames(stream_id, &bst, fin);
}

void Http3ServerConnection::OnQuicStreamReset(uint64_t stream_id,
                                              uint64_t app_error_code) {
  const auto wt_it = wt_sessions_.find(stream_id);
  if (wt_it != wt_sessions_.end()) {
    TerminateWtSession(stream_id, static_cast<int>(app_error_code));
    return;
  }

  const bool is_uni = (stream_id & 0x02u) != 0;
  const auto mapped = Http3CodeToWebTransportCode(app_error_code);
  const uint64_t clean_err = mapped.value_or(app_error_code);

  if (is_uni) {
    const auto uit = client_uni_streams_.find(stream_id);
    if (uit != client_uni_streams_.end()) {
      const auto sit = wt_sessions_.find(uit->second.wt_connect_stream_id);
      if (sit != wt_sessions_.end() && wt_visitor_ != nullptr) {
        wt_visitor_->OnServerStreamReset(sit->second->session_id(), stream_id,
                                         clean_err);
      }
      client_uni_streams_.erase(uit);
    }
  } else {
    const auto bit = client_bidi_streams_.find(stream_id);
    if (bit != client_bidi_streams_.end()) {
      if (bit->second.kind == ClientBidiStream::Kind::kWebTransportBidiData) {
        const auto sit = wt_sessions_.find(bit->second.wt_connect_stream_id);
        if (sit != wt_sessions_.end() && wt_visitor_ != nullptr) {
          wt_visitor_->OnServerStreamReset(sit->second->session_id(), stream_id,
                                           clean_err);
        }
      }
      client_bidi_streams_.erase(bit);
    }
    server_stream_to_connect_sid_.erase(stream_id);
  }
}

void Http3ServerConnection::OnQuicStreamStopSending(uint64_t stream_id,
                                                    uint64_t app_error_code) {
  const auto mapped = Http3CodeToWebTransportCode(app_error_code);
  const uint64_t clean_err = mapped.value_or(app_error_code);

  const auto srv_it = server_stream_to_connect_sid_.find(stream_id);
  if (srv_it != server_stream_to_connect_sid_.end()) {
    const auto sit = wt_sessions_.find(srv_it->second);
    if (sit != wt_sessions_.end() && wt_visitor_ != nullptr) {
      wt_visitor_->OnServerStreamStopSending(sit->second->session_id(),
                                             stream_id, clean_err);
    }
    return;
  }

  const auto bit = client_bidi_streams_.find(stream_id);
  if (bit != client_bidi_streams_.end() &&
      bit->second.kind == ClientBidiStream::Kind::kWebTransportBidiData) {
    const auto sit = wt_sessions_.find(bit->second.wt_connect_stream_id);
    if (sit != wt_sessions_.end() && wt_visitor_ != nullptr) {
      wt_visitor_->OnServerStreamStopSending(sit->second->session_id(),
                                             stream_id, clean_err);
    }
  }
}

void Http3ServerConnection::OnQuicDatagramReceived(
    ArrayView<const uint8_t> data) {
  uint64_t csid = 0;
  ArrayView<const uint8_t> wt_payload;
  if (!DecodeHttp3Datagram(data, &csid, &wt_payload)) {
    return;
  }
  const auto sit = wt_sessions_.find(csid);
  if (sit != wt_sessions_.end()) {
    if (wt_visitor_ != nullptr) {
      wt_visitor_->OnServerDatagramReceived(sit->second->session_id(),
                                            wt_payload);
    }
  } else if (early_datagrams_[csid].size() < 64) {
    early_datagrams_[csid].emplace_back(wt_payload.begin(), wt_payload.end());
  }
}

void Http3ServerConnection::ProcessControlFrames(std::vector<uint8_t>* buf) {
  while (!buf->empty()) {
    size_t consumed = 0;
    auto frame = Http3Frame::Decode(*buf, &consumed);
    if (!frame.has_value()) {
      break;
    }
    buf->erase(buf->begin(), buf->begin() + static_cast<ptrdiff_t>(consumed));
    if (frame->type == kH3FrameSettings && !peer_settings_received_) {
      auto parsed = Http3Settings::DecodePayload(frame->payload);
      if (parsed.has_value()) {
        peer_settings_ = *parsed;
        peer_settings_received_ = true;
      }
    }
  }
}

void Http3ServerConnection::ProcessHttpOrConnectFrames(uint64_t stream_id,
                                                       ClientBidiStream* st,
                                                       bool fin) {
  while (!st->rx_buf.empty()) {
    size_t consumed = 0;
    auto frame = Http3Frame::Decode(st->rx_buf, &consumed);
    if (!frame.has_value()) {
      break;
    }
    st->rx_buf.erase(st->rx_buf.begin(),
                     st->rx_buf.begin() + static_cast<ptrdiff_t>(consumed));

    if (frame->type == kH3FrameHeaders && !st->headers_received) {
      std::vector<HttpHeaderField> decoded;
      if (!QpackCodec::DecodeFieldSection(frame->payload, &decoded)) {
        raw_quic_->ResetStream(stream_id, kH3MessageError);
        return;
      }
      st->headers_received = true;
      std::vector<std::string> offered_wt_protos;
      for (auto& h : decoded) {
        if (h.name == ":method") {
          st->h3_req.method = std::move(h.value);
        } else if (h.name == ":scheme") {
          st->h3_req.scheme = std::move(h.value);
        } else if (h.name == ":authority") {
          st->h3_req.authority = std::move(h.value);
        } else if (h.name == ":path") {
          st->h3_req.path = std::move(h.value);
        } else if (h.name == ":protocol") {
          st->h3_req.protocol = std::move(h.value);
        } else {
          if (h.name == "wt-available-protocols") {
            offered_wt_protos = ParseWtAvailableProtocols(h.value);
          }
          st->h3_req.headers.push_back(std::move(h));
        }
      }

      if (st->h3_req.method == "CONNECT" &&
          st->h3_req.protocol == "webtransport") {
        st->kind = ClientBidiStream::Kind::kWebTransportConnect;
        std::string chosen_proto;
        bool emit_wt_proto_hdr = false;
        if (!offered_wt_protos.empty()) {
          if (supported_wt_protocols_.empty()) {
            chosen_proto = offered_wt_protos.front();
            emit_wt_proto_hdr = true;
          } else {
            for (const auto& offer : offered_wt_protos) {
              if (std::find(supported_wt_protocols_.begin(),
                            supported_wt_protocols_.end(),
                            offer) != supported_wt_protocols_.end()) {
                chosen_proto = offer;
                emit_wt_proto_hdr = true;
                break;
              }
            }
          }
        } else if (!supported_wt_protocols_.empty()) {
          // 当浏览器未携带 WT-Available-Protocols 时，会话内部默认绑定至首选子协议，但不向浏览器回写未请求的头部。
          chosen_proto = supported_wt_protocols_.front();
        }

        std::vector<HttpHeaderField> resp_hdrs = {
            {":status", "200"},
            {"sec-webtransport-http3-draft", "draft02"},
        };
        if (emit_wt_proto_hdr && !chosen_proto.empty()) {
          resp_hdrs.push_back({"wt-protocol", FormatWtProtocol(chosen_proto)});
        }
        const auto resp_wire = BuildHttp3HeadersFrameFromMap(resp_hdrs);
        raw_quic_->WriteStream(stream_id, resp_wire, /*fin=*/false);

        const uint64_t vsid = ++next_virtual_session_id_;
        auto wt_sess = std::make_shared<WtSessionHandle>(
            vsid, stream_id, chosen_proto, weak_from_this(), raw_quic_);
        wt_sessions_.emplace(stream_id, wt_sess);

        RTC_LOG(kInfo) << "HTTP/3 server upgraded CONNECT stream=" << stream_id
                       << " to WebTransport session=" << vsid
                       << " path=" << st->h3_req.path
                       << " WT-Protocol=" << chosen_proto;
        if (wt_visitor_ != nullptr) {
          wt_visitor_->OnServerSessionConnected(wt_sess);
        }
        FlushEarlyBufferedSessionTraffic(stream_id, wt_sess.get());
      }
    } else if (frame->type == kH3FrameData) {
      if (st->kind == ClientBidiStream::Kind::kWebTransportConnect) {
        st->capsule_buf.insert(st->capsule_buf.end(), frame->payload.begin(),
                               frame->payload.end());
        while (!st->capsule_buf.empty()) {
          size_t cap_consumed = 0;
          auto cap =
              WebTransportCapsule::Decode(st->capsule_buf, &cap_consumed);
          if (!cap.has_value()) {
            break;
          }
          st->capsule_buf.erase(
              st->capsule_buf.begin(),
              st->capsule_buf.begin() + static_cast<ptrdiff_t>(cap_consumed));
          if (cap->type == kWtCapsuleCloseSession) {
            uint32_t err = 0;
            std::string reason;
            WebTransportCapsule::DecodeCloseSession(cap->value, &err, &reason);
            raw_quic_->WriteStream(stream_id, ArrayView<const uint8_t>(),
                                   /*fin=*/true);
            TerminateWtSession(stream_id, static_cast<int>(err));
            return;
          }
        }
      } else {
        st->h3_req.body.insert(st->h3_req.body.end(), frame->payload.begin(),
                               frame->payload.end());
      }
    }
  }

  if (fin) {
    if (st->kind == ClientBidiStream::Kind::kWebTransportConnect) {
      raw_quic_->WriteStream(stream_id, ArrayView<const uint8_t>(),
                             /*fin=*/true);
      TerminateWtSession(stream_id, 0);
      client_bidi_streams_.erase(stream_id);
    } else if (st->kind == ClientBidiStream::Kind::kHttp3Request &&
               st->headers_received) {
      Http3Response resp;
      if (http_handler_) {
        resp = http_handler_(st->h3_req);
      } else {
        resp.status = 200;
        resp.headers.push_back({"content-type", "application/json"});
        const std::string body = R"({"protocol":"h3","webtransport":true})";
        resp.body.assign(body.begin(), body.end());
      }
      std::vector<HttpHeaderField> hdrs = {
          {":status", std::to_string(resp.status)},
      };
      hdrs.insert(hdrs.end(), resp.headers.begin(), resp.headers.end());
      std::vector<uint8_t> wire = BuildHttp3HeadersFrameFromMap(hdrs);
      if (!resp.body.empty()) {
        Http3Frame::Append(kH3FrameData, resp.body, &wire);
      }
      raw_quic_->WriteStream(stream_id, wire, /*fin=*/true);
      client_bidi_streams_.erase(stream_id);
    }
  }
}

void Http3ServerConnection::FlushEarlyBufferedSessionTraffic(
    uint64_t connect_sid,
    WtSessionHandle* wt_sess) {
  if (wt_visitor_ == nullptr || wt_sess == nullptr) {
    return;
  }
  const uint64_t vsid = wt_sess->session_id();
  for (auto& [usid, ust] : client_uni_streams_) {
    if (ust.wt_session_parsed && ust.wt_connect_stream_id == connect_sid &&
        !ust.opened_notified) {
      ust.opened_notified = true;
      wt_visitor_->OnServerStreamOpened(vsid, usid, /*unidirectional=*/true);
      if (!ust.rx_buf.empty()) {
        const std::vector<uint8_t> tmp = std::move(ust.rx_buf);
        ust.rx_buf.clear();
        wt_visitor_->OnServerStreamData(vsid, usid, tmp, /*fin=*/false);
      }
    }
  }
  for (auto& [bsid, bst] : client_bidi_streams_) {
    if (bst.kind == ClientBidiStream::Kind::kWebTransportBidiData &&
        bst.wt_connect_stream_id == connect_sid && !bst.opened_notified) {
      bst.opened_notified = true;
      wt_visitor_->OnServerStreamOpened(vsid, bsid, /*unidirectional=*/false);
      if (!bst.rx_buf.empty()) {
        const std::vector<uint8_t> tmp = std::move(bst.rx_buf);
        bst.rx_buf.clear();
        wt_visitor_->OnServerStreamData(vsid, bsid, tmp, /*fin=*/false);
      }
    }
  }
  const auto dit = early_datagrams_.find(connect_sid);
  if (dit != early_datagrams_.end()) {
    for (const auto& dg : dit->second) {
      wt_visitor_->OnServerDatagramReceived(vsid, dg);
    }
    early_datagrams_.erase(dit);
  }
}

void Http3ServerConnection::TerminateWtSession(uint64_t connect_sid,
                                               int error_code) {
  const auto it = wt_sessions_.find(connect_sid);
  if (it == wt_sessions_.end()) {
    return;
  }
  const uint64_t vsid = it->second->session_id();
  wt_sessions_.erase(it);
  early_datagrams_.erase(connect_sid);
  for (auto sit = server_stream_to_connect_sid_.begin();
       sit != server_stream_to_connect_sid_.end();) {
    if (sit->second == connect_sid) {
      sit = server_stream_to_connect_sid_.erase(sit);
    } else {
      ++sit;
    }
  }
  for (auto uit = client_uni_streams_.begin();
       uit != client_uni_streams_.end();) {
    if (uit->second.wt_session_parsed &&
        uit->second.wt_connect_stream_id == connect_sid) {
      uit = client_uni_streams_.erase(uit);
    } else {
      ++uit;
    }
  }
  for (auto bit = client_bidi_streams_.begin();
       bit != client_bidi_streams_.end();) {
    if (bit->second.kind == ClientBidiStream::Kind::kWebTransportBidiData &&
        bit->second.wt_connect_stream_id == connect_sid) {
      bit = client_bidi_streams_.erase(bit);
    } else {
      ++bit;
    }
  }
  if (wt_visitor_ != nullptr) {
    wt_visitor_->OnServerSessionDisconnected(vsid, error_code);
  }
}

// ======================= AsioHttp3WebTransportServer 实现 =======================

AsioHttp3WebTransportServer::AsioHttp3WebTransportServer(
    Clock* clock,
    TaskQueueBoost* network_queue,
    IQuicServerVisitor* wt_visitor,
    std::string bind_ip,
    std::vector<std::string> supported_wt_protocols,
    Http3ServerConnection::Http3RequestHandler http_handler)
    : wt_visitor_(wt_visitor),
      supported_wt_protocols_(std::move(supported_wt_protocols)),
      http_handler_(std::move(http_handler)),
      quic_server_(clock,
                   network_queue,
                   this,
                   std::move(bind_ip),
                   std::vector<std::string>{"h3"}) {}

AsioHttp3WebTransportServer::~AsioHttp3WebTransportServer() { Stop(); }

bool AsioHttp3WebTransportServer::Start(uint16_t udp_port) {
  return quic_server_.Start(udp_port);
}

void AsioHttp3WebTransportServer::Stop() {
  quic_server_.Stop();
  h3_conns_.clear();
}

void AsioHttp3WebTransportServer::OnServerSessionConnected(
    std::shared_ptr<QuicServerSessionHandle> session) {
  const uint64_t sid = session->session_id();
  const uint64_t vbase = next_virtual_id_base_;
  next_virtual_id_base_ += 1024;
  auto conn = std::make_shared<Http3ServerConnection>(
      std::move(session), wt_visitor_, supported_wt_protocols_, http_handler_,
      vbase);
  h3_conns_[sid] = conn;
  conn->Start();
}

void AsioHttp3WebTransportServer::OnServerSessionDisconnected(
    uint64_t session_id,
    int error_code) {
  const auto it = h3_conns_.find(session_id);
  if (it != h3_conns_.end()) {
    it->second->OnQuicDisconnected(error_code);
    h3_conns_.erase(it);
  }
}

void AsioHttp3WebTransportServer::OnServerStreamOpened(uint64_t session_id,
                                                       uint64_t stream_id,
                                                       bool unidirectional) {
  const auto it = h3_conns_.find(session_id);
  if (it != h3_conns_.end()) {
    it->second->OnQuicStreamOpened(stream_id, unidirectional);
  }
}

void AsioHttp3WebTransportServer::OnServerStreamData(
    uint64_t session_id,
    uint64_t stream_id,
    ArrayView<const uint8_t> data,
    bool fin) {
  const auto it = h3_conns_.find(session_id);
  if (it != h3_conns_.end()) {
    it->second->OnQuicStreamData(stream_id, data, fin);
  }
}

void AsioHttp3WebTransportServer::OnServerStreamReset(uint64_t session_id,
                                                      uint64_t stream_id,
                                                      uint64_t app_error_code) {
  const auto it = h3_conns_.find(session_id);
  if (it != h3_conns_.end()) {
    it->second->OnQuicStreamReset(stream_id, app_error_code);
  }
}

void AsioHttp3WebTransportServer::OnServerStreamStopSending(
    uint64_t session_id,
    uint64_t stream_id,
    uint64_t app_error_code) {
  const auto it = h3_conns_.find(session_id);
  if (it != h3_conns_.end()) {
    it->second->OnQuicStreamStopSending(stream_id, app_error_code);
  }
}

void AsioHttp3WebTransportServer::OnServerDatagramReceived(
    uint64_t session_id,
    ArrayView<const uint8_t> data) {
  const auto it = h3_conns_.find(session_id);
  if (it != h3_conns_.end()) {
    it->second->OnQuicDatagramReceived(data);
  }
}

}  // namespace rtc
