#ifndef SRC_MODULES_RTP_RTCP_BYTE_IO_H_
#define SRC_MODULES_RTP_RTCP_BYTE_IO_H_

#include <cstdint>

namespace rtc {

constexpr uint16_t ReadBigEndian16(const uint8_t* data) {
  return (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
}

constexpr uint32_t ReadBigEndian24(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 16) |
         (static_cast<uint32_t>(data[1]) << 8) | static_cast<uint32_t>(data[2]);
}

constexpr uint32_t ReadBigEndian32(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
}

constexpr int16_t ReadBigEndianSigned16(const uint8_t* data) {
  return static_cast<int16_t>(ReadBigEndian16(data));
}

inline void WriteBigEndian16(uint8_t* data, uint16_t val) {
  data[0] = static_cast<uint8_t>(val >> 8);
  data[1] = static_cast<uint8_t>(val & 0xFF);
}

inline void WriteBigEndian24(uint8_t* data, uint32_t val) {
  data[0] = static_cast<uint8_t>((val >> 16) & 0xFF);
  data[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
  data[2] = static_cast<uint8_t>(val & 0xFF);
}

inline void WriteBigEndian32(uint8_t* data, uint32_t val) {
  data[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
  data[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
  data[2] = static_cast<uint8_t>((val >> 8) & 0xFF);
  data[3] = static_cast<uint8_t>(val & 0xFF);
}

}  // namespace rtc

#endif  // SRC_MODULES_RTP_RTCP_BYTE_IO_H_
