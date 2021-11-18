#pragma once

#include <cstdio>
#include <numeric>
#include <awssign/detail/emit.hpp>

namespace awssign::detail {

// lowercase base16 character encoding
template <typename Writer> // void(const char*, const char*)
std::size_t hex_encode(unsigned char c, Writer&& out)
{
  constexpr auto table = std::string_view{"0123456789abcdef"};
  return emit(table[c >> 4], out) // high 4 bits
      + emit(table[c & 0xf], out); // low 4 bits
}

template <typename Writer> // void(const char*, const char*)
std::size_t hex_encode(const unsigned char* begin,
                       const unsigned char* end, Writer&& out)
{
  return std::accumulate(begin, end, static_cast<std::size_t>(0),
    [&out] (std::size_t bytes, unsigned char c) {
      return bytes + hex_encode(c, out);
    });
}

} // namespace awssign::detail
