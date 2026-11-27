#ifndef SRC_RTC_BASE_PACKET_SLAB_POOL_H_
#define SRC_RTC_BASE_PACKET_SLAB_POOL_H_

// 基于 Boost.Intrusive slist 的预分配定长 MTU Slab 内存池。
// 防止嵌入式设备在 7x24 小时连续视频推流期间产生堆内存碎片。

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

#include <boost/intrusive/slist.hpp>

#include "api/array_view.h"

namespace rtc {

constexpr size_t kMaxSlabPacketCapacity = 2048;
constexpr size_t kDefaultSlabHeadroomBytes = 16;

struct SlabPacketBuffer : public boost::intrusive::slist_base_hook<> {
  std::array<uint8_t, kMaxSlabPacketCapacity> storage;
  size_t size = 0;
  size_t head_offset = kDefaultSlabHeadroomBytes;

  uint8_t* MutableData() { return storage.data() + head_offset; }
  const uint8_t* Data() const { return storage.data() + head_offset; }
  size_t Tailroom() const { return kMaxSlabPacketCapacity - head_offset; }

  void Reset() {
    size = 0;
    head_offset = kDefaultSlabHeadroomBytes;
  }

  bool Assign(ArrayView<const uint8_t> src) {
    Reset();
    const bool fits = (src.size() <= Tailroom());
    const size_t copy_len = fits ? src.size() : Tailroom();
    if (copy_len > 0 && src.data() != nullptr) {
      std::memcpy(MutableData(), src.data(), copy_len);
    }
    size = copy_len;
    return fits;
  }
};

class PacketSlabPool : public std::enable_shared_from_this<PacketSlabPool> {
 public:
  struct Deleter {
    std::shared_ptr<PacketSlabPool> pool;
    bool from_arena = true;

    void operator()(SlabPacketBuffer* buf) const noexcept;
  };

  using PacketPtr = std::unique_ptr<SlabPacketBuffer, Deleter>;

  static std::shared_ptr<PacketSlabPool> Create(
      size_t preallocated_slots = 2048);

  ~PacketSlabPool() = default;

  PacketSlabPool(const PacketSlabPool&) = delete;
  PacketSlabPool& operator=(const PacketSlabPool&) = delete;

  PacketPtr Acquire();
  size_t FreeSlots() const;
  size_t total_capacity() const { return arena_.size(); }

 private:
  explicit PacketSlabPool(size_t preallocated_slots);
  void ReleaseToFreeList(SlabPacketBuffer* buf) noexcept;

  mutable std::mutex mutex_;
  std::vector<SlabPacketBuffer> arena_;
  boost::intrusive::slist<SlabPacketBuffer, boost::intrusive::cache_last<false>>
      free_list_;
  size_t free_count_ = 0;
};

}  // namespace rtc

#endif  // SRC_RTC_BASE_PACKET_SLAB_POOL_H_
