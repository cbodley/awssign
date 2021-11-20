#pragma once

#include <algorithm>
#include <stdexcept>
#include <awssign/detail/emit.hpp>

namespace awssign::detail {

// return the 4-bit value of the given percent-escaped character, or -1 if the
// escaped character is invalid
inline char percent_decode(char c)
{
  static constexpr char table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, //   0- 15
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  16- 31
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  32- 47
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1, //  48- 63
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  64- 79
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  80- 95
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  96-111
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 112-127
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 128-143
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 144-159
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 160-175
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 176-191
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 192-207
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 208-223
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 224-239
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 240-255
  };
  return table[c];
}

struct percent_decode_error : std::runtime_error {
  explicit percent_decode_error(const char* message)
      : std::runtime_error(message) {}
};

struct percent_decoder {
  enum class state : uint8_t {
    normal,
    at_percent,
    after_percent,
  };
  state s = state::normal;
  unsigned char decoded = 0;

  template <typename Writer> // void(const char*, const char*)
  void decode(const char* begin, const char* end, Writer&& out)
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
        char c = percent_decode(*pos);
        if (c == -1) {
          throw percent_decode_error("percent decoder expected hex character");
        }
        decoded = static_cast<unsigned char>(c) << 4;
        s = state::after_percent;
        ++pos;
      } else if (s == state::after_percent) {
        char c = percent_decode(*pos);
        if (c == -1) {
          throw percent_decode_error("percent decoder expected hex character");
        }
        decoded |= static_cast<unsigned char>(c);
        emit(static_cast<char>(decoded), out);
        s = state::normal;
        ++pos;
      }
    }
  }

  void eof() {
    if (s != state::normal) {
      throw percent_decode_error("percent decoder hit unexpected eof");
    }
  }
};

} // namespace awssign::detail
