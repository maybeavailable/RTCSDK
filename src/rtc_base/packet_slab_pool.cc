#include "rtc_base/packet_slab_pool.h"

#include "rtc_base/logging.h"

namespace rtc {

void PacketSlabPool::Deleter::operator()(SlabPacketBuffer* buf) const noexcept {
  if (buf == nullptr) {
    return;
  }
  if (!from_arena) {
    delete buf;
    return;
  }
  if (auto locked = pool.lock()) {
    locked->ReleaseToFreeList(buf);
  }
}

std::shared_ptr<PacketSlabPool> PacketSlabPool::Create(
    size_t preallocated_slots) {
  return std::shared_ptr<PacketSlabPool>(
      new PacketSlabPool(preallocated_slots));
}

PacketSlabPool::PacketSlabPool(size_t preallocated_slots)
    : arena_(preallocated_slots), free_count_(preallocated_slots) {
  for (auto& slot : arena_) {
    slot.Reset();
    free_list_.push_front(slot);
  }
  RTC_LOG(kVerbose) << "PacketSlabPool initialized with " << preallocated_slots
                    << " MTU slots ("
                    << (preallocated_slots * sizeof(SlabPacketBuffer)) / 1024
                    << " KiB)";
}

PacketSlabPool::PacketPtr PacketSlabPool::Acquire() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!free_list_.empty()) {
    SlabPacketBuffer& front = free_list_.front();
    free_list_.pop_front();
    --free_count_;
    front.Reset();
    return PacketPtr(&front, Deleter{weak_from_this(), true});
  }
  RTC_LOG(kWarning) << "PacketSlabPool exhausted (" << arena_.size()
                    << " slots), allocating overflow buffer";
  auto* fallback = new SlabPacketBuffer();
  fallback->Reset();
  return PacketPtr(fallback, Deleter{weak_from_this(), false});
}

void PacketSlabPool::ReleaseToFreeList(SlabPacketBuffer* buf) noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  buf->Reset();
  free_list_.push_front(*buf);
  ++free_count_;
}

size_t PacketSlabPool::FreeSlots() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return free_count_;
}

}  // namespace rtc
