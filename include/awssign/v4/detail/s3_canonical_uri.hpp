#pragma once

#include <cctype>
#include <awssign/detail/emit.hpp>
#include <awssign/detail/percent_encode.hpp>
#include <awssign/detail/transform_if.hpp>

namespace awssign::v4::detail {

using awssign::detail::emit;
using awssign::detail::percent_encode;
using awssign::detail::transform_if;

/// output an absolute uri path in s3-canonical form, which percent-encodes the
/// path without any normalization
template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t s3_canonical_uri(Iterator begin, Iterator end, Writer&& out)
{
  if (begin == end) {
    return emit('/', out);
  }
  constexpr auto need_escape = [] (unsigned char c) {
    switch (c) {
      case '_':
      case '-':
      case '~':
      case '.':
      case '/': // s3 does not encode slashes in the path
        return false;
      default:
        return !std::isalnum(c);
    }
  };
  constexpr auto escape = [] (char c, Writer& out) {
    // spaces must be encoded as ' ', not '+'
    return percent_encode(c == '+' ? ' ' : c, out);
  };
  return transform_if(begin, end, need_escape, escape, out);
}

} // namespace awssign::v4::detail
