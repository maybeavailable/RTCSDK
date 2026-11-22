#ifndef SRC_RTC_BASE_JSON_UTILS_H_
#define SRC_RTC_BASE_JSON_UTILS_H_

// 零异常、轻量级的 RFC 8259 扁平 JSON 对象序列化与解析器。
// 替代信令消息中基于异常的 Boost.PropertyTree，以严格遵循
// Google C++ 编程规范（禁用 C++ 异常）。

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace rtc {

class JsonObject {
 public:
  JsonObject() = default;

  void SetString(std::string_view key, std::string_view value);
  void SetUint32(std::string_view key, uint32_t value);

  std::string GetString(std::string_view key,
                        std::string_view default_value = "") const;
  uint32_t GetUint32(std::string_view key, uint32_t default_value = 0) const;

  std::string Serialize() const;
  static std::optional<JsonObject> Parse(std::string_view json_text);

 private:
  struct FieldValue {
    std::string raw_value;
    bool is_string = true;
  };

  std::map<std::string, FieldValue, std::less<>> fields_;
};

// 基于 C++17 std::from_chars 封装的零异常整数解析器。
bool ParseUint16(std::string_view text, uint16_t* out_value);
bool ParseUint32(std::string_view text, uint32_t* out_value);

}  // namespace rtc

#endif  // SRC_RTC_BASE_JSON_UTILS_H_
