#pragma once

#include <cstdio>
#include <numeric>
#include <awssign/detail/emit.hpp>

namespace awssign::detail {

// lowercase base16 character encoding
// TODO: consider simd for hex_encode
template <typename Writer> // void(const char*, const char*)
std::size_t hex_encode(unsigned char c, Writer&& out)
{
  char buffer[10]; // longest string for int is "%FFFFFFFF\0"
  const auto count = std::snprintf(buffer, sizeof(buffer),
                                   "%.2x", static_cast<int>(c));
  return emit(buffer, buffer + count, out);
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
