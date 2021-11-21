#pragma once

#include <algorithm>
#include <iterator>

namespace awssign::detail {

// a stream that may buffer up to Size bytes to minimize the number of writes
// to the wrapped OutputStream. on destruction, any buffered data is flushed
template <std::size_t Size, typename OutputStream>
class buffered_stream {
  using array_type = std::array<char, Size>;
  using iterator_type = typename array_type::iterator;

  OutputStream& out;
  array_type buffer;
  iterator_type buffer_pos;
 public:
  buffered_stream(OutputStream& out) noexcept
      : out(out), buffer_pos(buffer.begin())
  {}
  ~buffered_stream() {
    if (buffer.begin() != buffer_pos) { // flush any buffered data
      out(buffer.begin(), buffer_pos);
    }
  }
  buffered_stream(const buffered_stream&) = delete;
  buffered_stream& operator=(const buffered_stream&) = delete;

  buffered_stream(buffered_stream&& o) noexcept
      : out(o.out), buffer_pos(buffer.begin())
  {}

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
        out(buffer.begin(), buffer_pos);
        buffer_pos = buffer.begin();
      }
      // pass remaining input directly
      out(input_pos, end);
    }
  }
};

template <std::size_t Size, typename OutputStream>
auto buffered(OutputStream&& out)
  -> buffered_stream<Size, OutputStream>
{
  return {std::forward<OutputStream>(out)};
}

} // namespace awssign::detail
