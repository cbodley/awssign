#pragma once

#include <cstdio>
#include <awssign/detail/emit.hpp>

namespace awssign::detail {

inline bool need_percent_encode(unsigned char c)
{
  switch (c) {
    case '_':
    case '-':
    case '~':
    case '.':
      return false;
    default:
      return !std::isalnum(c);
  }
}

template <typename Writer> // void(const char*, const char*)
std::size_t percent_encode(unsigned char c, Writer&& out)
{
  constexpr auto table = std::string_view{"0123456789ABCDEF"};
  return emit('%', out)
      + emit(table[c >> 4], out) // high 4 bits
      + emit(table[c & 0xf], out); // low 4 bits
}

// the only difference with double-encoding is that the % is encoded as %25
template <typename Writer> // void(const char*, const char*)
std::size_t percent_encode_twice(unsigned char c, Writer&& out)
{
  constexpr auto table = std::string_view{"0123456789ABCDEF"};
  return emit("%25", out)
      + emit(table[c >> 4], out) // high 4 bits
      + emit(table[c & 0xf], out); // low 4 bits
}

} // namespace awssign::detail
