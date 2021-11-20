#pragma once

#include <cstdio>
#include <awssign/detail/emit.hpp>

namespace awssign::detail {

inline bool need_percent_encode(unsigned char c)
{
  static constexpr char unreserved[256] = {
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, //   0- 15
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, //  16- 31
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,'-','.',  0, //  32- 47
    '0','1','2','3','4','5','6','7','8','9',  0,  0,  0,  0,  0,  0, //  48- 63
      0,'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O', //  64- 79
    'P','Q','R','S','T','U','V','W','X','Y','Z',  0,  0,  0,  0,'_', //  80- 95
      0,'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o', //  96-111
    'p','q','r','s','t','u','v','w','x','y','z',  0,  0,  0,'~',  0, // 112-127
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 128-143
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 144-159
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 160-175
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 176-191
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 192-207
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 208-223
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 224-239
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 240-255
  };
  return !unreserved[c];
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
