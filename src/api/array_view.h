#ifndef SRC_API_ARRAY_VIEW_H_
#define SRC_API_ARRAY_VIEW_H_

// 参照 libwebrtc/api/array_view.h 设计（C++17 零拷贝非拥有型连续内存视图）。
// 遵循 Google C++ 代码风格规范，用于替代裸 `(const T*, size_t)` 参数对。

#include <array>
#include <cstddef>
#include <type_traits>
#include <vector>

namespace rtc {

template <typename T>
class ArrayView {
 public:
  using value_type = T;
  using const_iterator = const T*;

  constexpr ArrayView() noexcept : data_(nullptr), size_(0) {}
  constexpr ArrayView(T* data, size_t size) noexcept
      : data_(size == 0 ? nullptr : data), size_(size) {}

  template <typename U,
            size_t N,
            std::enable_if_t<std::is_convertible_v<U (*)[], T (*)[]>, int> = 0>
  constexpr ArrayView(U (&arr)[N]) noexcept  // NOLINT(runtime/explicit)
      : data_(arr), size_(N) {}

  template <typename U,
            size_t N,
            std::enable_if_t<std::is_convertible_v<U*, T*>, int> = 0>
  constexpr ArrayView(std::array<U, N>& arr) noexcept  // NOLINT(runtime/explicit)
      : data_(N == 0 ? nullptr : arr.data()), size_(N) {}

  template <typename U,
            size_t N,
            std::enable_if_t<std::is_convertible_v<const U*, T*>, int> = 0>
  constexpr ArrayView(
      const std::array<U, N>& arr) noexcept  // NOLINT(runtime/explicit)
      : data_(N == 0 ? nullptr : arr.data()), size_(N) {}

  template <typename U,
            std::enable_if_t<std::is_same_v<const U, T>, int> = 0>
  constexpr ArrayView(const ArrayView<U>& mutable_view) noexcept
      : data_(mutable_view.data()), size_(mutable_view.size()) {}

  template <typename U,
            typename Alloc,
            std::enable_if_t<std::is_convertible_v<U*, T*>, int> = 0>
  ArrayView(std::vector<U, Alloc>& vec) noexcept  // NOLINT(runtime/explicit)
      : data_(vec.empty() ? nullptr : vec.data()), size_(vec.size()) {}

  template <typename U,
            typename Alloc,
            std::enable_if_t<std::is_convertible_v<const U*, T*>, int> = 0>
  ArrayView(const std::vector<U, Alloc>& vec) noexcept  // NOLINT(runtime/explicit)
      : data_(vec.empty() ? nullptr : vec.data()), size_(vec.size()) {}

  constexpr T* data() const noexcept { return data_; }
  constexpr size_t size() const noexcept { return size_; }
  constexpr bool empty() const noexcept { return size_ == 0; }

  constexpr T& operator[](size_t idx) const noexcept { return data_[idx]; }
  constexpr T* begin() const noexcept { return data_; }
  constexpr T* end() const noexcept { return data_ + size_; }

  constexpr ArrayView<T> subview(size_t offset, size_t count) const noexcept {
    if (offset >= size_) {
      return ArrayView<T>();
    }
    const size_t avail = size_ - offset;
    return ArrayView<T>(data_ + offset, count < avail ? count : avail);
  }

  constexpr ArrayView<T> subview(size_t offset) const noexcept {
    if (offset >= size_) {
      return ArrayView<T>();
    }
    return ArrayView<T>(data_ + offset, size_ - offset);
  }

 private:
  T* data_;
  size_t size_;
};

template <typename T>
constexpr ArrayView<T> MakeArrayView(T* data, size_t size) noexcept {
  return ArrayView<T>(data, size);
}

}  // namespace rtc

#endif  // SRC_API_ARRAY_VIEW_H_
