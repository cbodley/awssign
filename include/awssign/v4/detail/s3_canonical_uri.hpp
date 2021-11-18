#pragma once

#include <cctype>
#include <awssign/detail/emit.hpp>
#include <awssign/detail/percent_encode.hpp>
#include <awssign/detail/transform.hpp>

namespace awssign::v4::detail {

using awssign::detail::emit;
using awssign::detail::percent_encode;
using awssign::detail::transform_if;

// s3 does not encode slashes in the path
inline bool need_percent_encode_no_slash(unsigned char c)
{
  constexpr char unreserved[256] = {
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, //   0- 15
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, //  16- 31
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,'-','.','/', //  32- 47
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

/// output an absolute uri path in s3-canonical form, which percent-encodes the
/// path without any normalization
template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t s3_canonical_uri(Iterator begin, Iterator end, Writer&& out)
{
  if (begin == end) {
    return emit('/', out);
  }
  constexpr auto escape = [] (char c, Writer& out) {
    // spaces must be encoded as ' ', not '+'
    return percent_encode(c == '+' ? ' ' : c, out);
  };
  return transform_if(begin, end, need_percent_encode_no_slash, escape, out);
}

} // namespace awssign::v4::detail
