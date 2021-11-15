#pragma once

#include <algorithm>
#include <cstddef>
#include <awssign/detail/emit.hpp>
#include <awssign/detail/percent_encode.hpp>
#include <awssign/detail/transform_if.hpp>

namespace awssign::v4::detail {

using awssign::detail::emit;
using awssign::detail::need_percent_encode;
using awssign::detail::percent_encode;
using awssign::detail::percent_encode_twice;
using awssign::detail::transform_if;

template <typename InputIterator, // forward iterator with value_type=char
          typename OutputIterator> // forward parameter iterator
OutputIterator parse_query_parameters(InputIterator begin, InputIterator end,
                                      OutputIterator out)
{
  auto i = begin;
  for (;;) {
    auto next = std::find(i, end, '&');
    out->begin = i;
    out->end = next;
    ++out;
    if (next == end) {
      break;
    }
    i = std::next(next);
  }
  return out;
}

template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t canonical_parameter_name(Iterator begin, Iterator end,
                                     Writer&& out)
{
  constexpr auto escape = [] (char c, Writer& out) {
    // spaces must be encoded as ' ', not '+'
    return percent_encode(c == '+' ? ' ' : c, out);
  };
  return transform_if(begin, end, need_percent_encode, escape, out);
}

template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t canonical_parameter_value(Iterator begin, Iterator end,
                                      Writer&& out)
{
  constexpr auto escape = [] (char c, Writer& out) {
    if (c == '=') { // = in the value gets double-encoded
      return percent_encode_twice(c, out);
    } else {
      // spaces must be encoded as ' ', not '+'
      return percent_encode(c == '+' ? ' ' : c, out);
    }
  };
  return transform_if(begin, end, need_percent_encode, escape, out);
}

template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t canonical_parameter(Iterator begin, Iterator end,
                                Writer&& out)
{
  std::size_t bytes = 0;
  auto delim = std::find(begin, end, '=');
  bytes += canonical_parameter_name(begin, delim, out);
  bytes += emit('=', out);
  if (delim != end) {
    bytes += canonical_parameter_value(std::next(delim), end, out);
  }
  return bytes;
}

} // namespace awssign::v4::detail
