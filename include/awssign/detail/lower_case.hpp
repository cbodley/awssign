#pragma once

#include <algorithm>
#include <cctype>
#include <iterator>
#include <awssign/detail/fast_tolower.h>

namespace awssign::detail {

template <typename Writer>
class lower_case_writer {
  static constexpr std::size_t buffer_size = 128;
  Writer& next;
 public:
  explicit lower_case_writer(Writer& next) : next(next) {}

  void operator()(const char* begin, const char* end) {
    char buffer[buffer_size];
    std::size_t input_remaining = std::distance(begin, end);
    while (input_remaining > buffer_size) {
      constexpr auto count = buffer_size;
      ::fast_tolower(buffer, begin, count);
      next(buffer, buffer + count);

      input_remaining -= count;
      begin += count;
    }
    std::size_t count = std::min(input_remaining, buffer_size);
    fast_tolower(buffer, begin, count);
    next(buffer, buffer + count);
  }
};

struct lower_case_less {
  bool operator()(unsigned char l, unsigned char r) const {
    return std::tolower(l) < std::tolower(r);
  }
  bool operator()(std::string_view l, std::string_view r) const {
    return std::lexicographical_compare(l.begin(), l.end(),
                                        r.begin(), r.end(), *this);
  }
};

} // namespace awssign::detail
