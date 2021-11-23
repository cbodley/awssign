#pragma once

#include <cstdio>
#include <numeric>
#include <awssign/detail/write.hpp>
#include <awssign/detail/transform.hpp>

namespace awssign::detail {

// lowercase base16 character encoding
template <typename OutputStream>
void hex_encode(unsigned char c, OutputStream&& out)
{
  constexpr auto table = std::string_view{"0123456789abcdef"};
  write(table[c >> 4], out); // high 4 bits
  write(table[c & 0xf], out); // low 4 bits
}

// write the sequence to the stream in hex-encoded form
template <typename OutputStream>
void hex_encode(const unsigned char* begin, const unsigned char* end,
                OutputStream&& out)
{
  transform(begin, end, [] (unsigned char c, auto out) {
      return hex_encode(c, out);
    }, out);
}

} // namespace awssign::detail
