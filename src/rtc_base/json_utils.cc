#include "rtc_base/json_utils.h"

#include <cctype>
#include <charconv>
#include <cstdio>

namespace rtc {

namespace {

constexpr size_t kMaxJsonInputBytes = 256 * 1024;
constexpr size_t kMaxJsonObjectFields = 256;

void AppendEscapedJsonString(std::string_view input, std::string* out) {
  out->push_back('"');
  for (const unsigned char ch : input) {
    switch (ch) {
      case '"':
        out->append("\\\"");
        break;
      case '\\':
        out->append("\\\\");
        break;
      case '\b':
        out->append("\\b");
        break;
      case '\f':
        out->append("\\f");
        break;
      case '\n':
        out->append("\\n");
        break;
      case '\r':
        out->append("\\r");
        break;
      case '\t':
        out->append("\\t");
        break;
      default:
        if (ch < 0x20) {
          char hex[8];
          std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned>(ch));
          out->append(hex);
        } else {
          out->push_back(static_cast<char>(ch));
        }
        break;
    }
  }
  out->push_back('"');
}

void AppendUtf8Codepoint(uint32_t cp, std::string* out) {
  if (cp <= 0x7Fu) {
    out->push_back(static_cast<char>(cp));
  } else if (cp <= 0x7FFu) {
    out->push_back(static_cast<char>(0xC0u | ((cp >> 6) & 0x1Fu)));
    out->push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
  } else if (cp <= 0xFFFFu) {
    out->push_back(static_cast<char>(0xE0u | ((cp >> 12) & 0x0Fu)));
    out->push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
    out->push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
  } else if (cp <= 0x10FFFFu) {
    out->push_back(static_cast<char>(0xF0u | ((cp >> 18) & 0x07u)));
    out->push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
    out->push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
    out->push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
  }
}

void SkipWhitespace(std::string_view text, size_t* pos) {
  while (*pos < text.size() &&
         std::isspace(static_cast<unsigned char>(text[*pos]))) {
    ++(*pos);
  }
}

bool ParseHex4(std::string_view text, size_t pos, uint32_t* out_code) {
  if (pos + 4 > text.size()) {
    return false;
  }
  for (size_t i = 0; i < 4; ++i) {
    if (!std::isxdigit(static_cast<unsigned char>(text[pos + i]))) {
      return false;
    }
  }
  uint32_t code = 0;
  const auto res =
      std::from_chars(text.data() + pos, text.data() + pos + 4, code, 16);
  if (res.ec != std::errc{} || res.ptr != text.data() + pos + 4) {
    return false;
  }
  *out_code = code;
  return true;
}

bool IsValidJsonPrimitiveLiteral(std::string_view token) {
  if (token == "true" || token == "false" || token == "null") {
    return true;
  }
  if (token.empty()) {
    return false;
  }
  size_t i = 0;
  if (token[i] == '-') {
    ++i;
  }
  if (i >= token.size()) {
    return false;
  }
  if (token[i] == '0') {
    ++i;
  } else if (std::isdigit(static_cast<unsigned char>(token[i]))) {
    while (i < token.size() &&
           std::isdigit(static_cast<unsigned char>(token[i]))) {
      ++i;
    }
  } else {
    return false;
  }
  if (i < token.size() && token[i] == '.') {
    ++i;
    if (i >= token.size() ||
        !std::isdigit(static_cast<unsigned char>(token[i]))) {
      return false;
    }
    while (i < token.size() &&
           std::isdigit(static_cast<unsigned char>(token[i]))) {
      ++i;
    }
  }
  if (i < token.size() && (token[i] == 'e' || token[i] == 'E')) {
    ++i;
    if (i < token.size() && (token[i] == '+' || token[i] == '-')) {
      ++i;
    }
    if (i >= token.size() ||
        !std::isdigit(static_cast<unsigned char>(token[i]))) {
      return false;
    }
    while (i < token.size() &&
           std::isdigit(static_cast<unsigned char>(token[i]))) {
      ++i;
    }
  }
  return i == token.size();
}

bool ParseJsonStringLiteral(std::string_view text,
                            size_t* pos,
                            std::string* out) {
  if (*pos >= text.size() || text[*pos] != '"') {
    return false;
  }
  ++(*pos);
  out->clear();
  while (*pos < text.size()) {
    const unsigned char uc = static_cast<unsigned char>(text[(*pos)++]);
    if (uc == '"') {
      return true;
    }
    if (uc < 0x20u) {
      return false;
    }
    if (uc == '\\') {
      if (*pos >= text.size()) {
        return false;
      }
      const char esc = text[(*pos)++];
      switch (esc) {
        case '"':
        case '\\':
        case '/':
          out->push_back(esc);
          break;
        case 'b':
          out->push_back('\b');
          break;
        case 'f':
          out->push_back('\f');
          break;
        case 'n':
          out->push_back('\n');
          break;
        case 'r':
          out->push_back('\r');
          break;
        case 't':
          out->push_back('\t');
          break;
        case 'u': {
          uint32_t code = 0;
          if (!ParseHex4(text, *pos, &code)) {
            return false;
          }
          *pos += 4;
          if (code >= 0xD800u && code <= 0xDBFFu) {
            if (*pos + 6 <= text.size() && text[*pos] == '\\' &&
                text[*pos + 1] == 'u') {
              uint32_t low = 0;
              if (!ParseHex4(text, *pos + 2, &low) || low < 0xDC00u ||
                  low > 0xDFFFu) {
                return false;
              }
              *pos += 6;
              code = 0x10000u + (((code - 0xD800u) << 10) | (low - 0xDC00u));
            } else {
              return false;
            }
          } else if (code >= 0xDC00u && code <= 0xDFFFu) {
            return false;
          }
          AppendUtf8Codepoint(code, out);
          break;
        }
        default:
          return false;
      }
    } else {
      out->push_back(static_cast<char>(uc));
    }
  }
  return false;
}

}  // namespace

void JsonObject::SetString(std::string_view key, std::string_view value) {
  fields_[std::string(key)] = FieldValue{std::string(value), true};
}

void JsonObject::SetUint32(std::string_view key, uint32_t value) {
  fields_[std::string(key)] = FieldValue{std::to_string(value), false};
}

std::string JsonObject::GetString(std::string_view key,
                                  std::string_view default_value) const {
  const auto it = fields_.find(key);
  if (it == fields_.end()) {
    return std::string(default_value);
  }
  return it->second.raw_value;
}

uint32_t JsonObject::GetUint32(std::string_view key,
                               uint32_t default_value) const {
  const auto it = fields_.find(key);
  if (it == fields_.end()) {
    return default_value;
  }
  uint32_t parsed = default_value;
  if (!ParseUint32(it->second.raw_value, &parsed)) {
    return default_value;
  }
  return parsed;
}

std::string JsonObject::Serialize() const {
  std::string out;
  out.reserve(128);
  out.push_back('{');
  bool first = true;
  for (const auto& [key, field] : fields_) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    AppendEscapedJsonString(key, &out);
    out.push_back(':');
    if (field.is_string) {
      AppendEscapedJsonString(field.raw_value, &out);
    } else {
      out.append(field.raw_value);
    }
  }
  out.push_back('}');
  return out;
}

std::optional<JsonObject> JsonObject::Parse(std::string_view json_text) {
  if (json_text.size() > kMaxJsonInputBytes) {
    return std::nullopt;
  }
  size_t pos = 0;
  SkipWhitespace(json_text, &pos);
  if (pos >= json_text.size() || json_text[pos] != '{') {
    return std::nullopt;
  }
  ++pos;

  JsonObject obj;
  SkipWhitespace(json_text, &pos);
  if (pos < json_text.size() && json_text[pos] == '}') {
    ++pos;
    SkipWhitespace(json_text, &pos);
    return (pos == json_text.size()) ? std::optional<JsonObject>(std::move(obj))
                                     : std::nullopt;
  }

  while (pos < json_text.size()) {
    if (obj.fields_.size() >= kMaxJsonObjectFields) {
      return std::nullopt;
    }
    SkipWhitespace(json_text, &pos);
    std::string key;
    if (!ParseJsonStringLiteral(json_text, &pos, &key)) {
      return std::nullopt;
    }

    SkipWhitespace(json_text, &pos);
    if (pos >= json_text.size() || json_text[pos] != ':') {
      return std::nullopt;
    }
    ++pos;
    SkipWhitespace(json_text, &pos);
    if (pos >= json_text.size()) {
      return std::nullopt;
    }

    if (json_text[pos] == '"') {
      std::string val;
      if (!ParseJsonStringLiteral(json_text, &pos, &val)) {
        return std::nullopt;
      }
      obj.SetString(key, val);
    } else {
      const size_t start = pos;
      while (pos < json_text.size() && json_text[pos] != ',' &&
             json_text[pos] != '}' &&
             !std::isspace(static_cast<unsigned char>(json_text[pos]))) {
        ++pos;
      }
      const std::string_view raw_tok = json_text.substr(start, pos - start);
      if (!IsValidJsonPrimitiveLiteral(raw_tok)) {
        return std::nullopt;
      }
      obj.fields_[key] = FieldValue{std::string(raw_tok), false};
    }

    SkipWhitespace(json_text, &pos);
    if (pos < json_text.size() && json_text[pos] == ',') {
      ++pos;
      continue;
    }
    if (pos < json_text.size() && json_text[pos] == '}') {
      ++pos;
      SkipWhitespace(json_text, &pos);
      return (pos == json_text.size())
                 ? std::optional<JsonObject>(std::move(obj))
                 : std::nullopt;
    }
    return std::nullopt;
  }
  return std::nullopt;
}

bool ParseUint16(std::string_view text, uint16_t* out_value) {
  if (text.empty() || out_value == nullptr) {
    return false;
  }
  uint16_t value = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), value);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size()) {
    return false;
  }
  *out_value = value;
  return true;
}

bool ParseUint32(std::string_view text, uint32_t* out_value) {
  if (text.empty() || out_value == nullptr) {
    return false;
  }
  uint32_t value = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), value);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size()) {
    return false;
  }
  *out_value = value;
  return true;
}

}  // namespace rtc
