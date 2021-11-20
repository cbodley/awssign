#pragma once

#include <algorithm>
#include <awssign/detail/percent_decode.hpp>
#include <awssign/detail/emit.hpp>

namespace awssign::detail {

template <typename Writer> // void(const char*, const char*)
struct percent_decode_writer {
  Writer& out;
  enum class state : uint8_t {
    normal,
    at_percent,
    after_percent,
  };
  state s = state::normal;
  char first_half = 0;

  void operator()(const char* begin, const char* end)
  {
    const char* pos = begin;
    while (pos != end) {
      if (s == state::normal) {
        auto next = std::find(pos, end, '%');
        if (pos != next) { // unencoded bytes before %
          out(pos, next);
          pos = next;
        }
        if (pos != end) { // found a %
          s = state::at_percent;
          ++pos;
        }
      } else if (s == state::at_percent) {
        s = state::after_percent;
        first_half = percent_decode(*pos);
        ++pos;
      } else if (s == state::after_percent) {
        s = state::normal;
        char second_half = percent_decode(*pos);
        emit(percent_decode(first_half, second_half), out);
        first_half = 0;
        ++pos;
      }
    }
  }
};

template <typename Writer> // void(const char*, const char*)
percent_decode_writer<Writer> percent_decoded(Writer&& out)
{
  return {out};
}

} // namespace awssign::detail
