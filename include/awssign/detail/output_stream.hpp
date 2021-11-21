#pragma once

#include <algorithm>

namespace awssign::detail {

template <typename OutputIterator>
class output_stream {
  OutputIterator& pos;
 public:
  explicit output_stream(OutputIterator& pos) noexcept : pos(pos) {}
  void operator()(const char* begin, const char* end) {
    pos = std::copy(begin, end, pos);
  }
};

} // namespace awssign::detail
