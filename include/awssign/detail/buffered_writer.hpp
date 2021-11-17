#pragma once

#include <algorithm>
#include <iterator>

namespace awssign::detail {

// a Writer that may buffer up to Size bytes to minimize the number of writes
// to the wrapped Writer. on destruction, any buffered data is flushed
template <std::size_t Size, typename Writer>
class buffered_writer {
  using array_type = std::array<char, Size>;
  using iterator_type = typename array_type::iterator;

  Writer& next;
  array_type buffer;
  iterator_type buffer_pos;
 public:
  explicit buffered_writer(Writer& next) noexcept
      : next(next), buffer_pos(buffer.begin())
  {}
  ~buffered_writer() {
    if (buffer.begin() != buffer_pos) { // flush any buffered data
      next(buffer.begin(), buffer_pos);
    }
  }

  template <typename Iterator>
  void operator()(Iterator begin, Iterator end) {
    auto input_pos = begin;
    std::size_t input_remaining = std::distance(begin, end);
    std::size_t buffer_remaining = std::distance(buffer_pos, buffer.end());
    if (input_remaining < buffer_remaining) {
      // write input to buffer
      buffer_pos = std::copy_n(input_pos, input_remaining, buffer_pos);
    } else {
      // flush any buffered data
      if (buffer_remaining < Size) {
        next(buffer.begin(), buffer_pos);
        buffer_pos = buffer.begin();
      }
      // pass remaining input directly
      next(input_pos, end);
    }
  }
};

template <std::size_t Size, typename Writer>
auto buffered(Writer&& writer) {
  return buffered_writer<Size, Writer>(std::forward<Writer>(writer));
}

} // namespace awssign::detail
