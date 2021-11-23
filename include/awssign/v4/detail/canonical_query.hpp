#pragma once

#include <algorithm>
#include <cstddef>
#include <awssign/detail/percent_encode.hpp>
#include <awssign/detail/percent_decoded_iterator.hpp>
#include <awssign/detail/percent_decoded_stream.hpp>
#include <awssign/detail/transform.hpp>
#include <awssign/detail/transform_stream.hpp>
#include <awssign/detail/write.hpp>

namespace awssign::v4::detail {

using awssign::detail::need_percent_encode;
using awssign::detail::percent_decoded;
using awssign::detail::percent_decoded_iterator;
using awssign::detail::percent_encode;
using awssign::detail::percent_encode_twice;
using awssign::detail::transform_if;
using awssign::detail::transformed_if;
using awssign::detail::write;

template <typename OutputIterator> // forward parameter iterator
OutputIterator parse_query_parameters(const char* begin, const char* end,
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

template <typename OutputStream>
void write_canonical_parameter_name(const char* begin, const char* end,
                                    OutputStream&& out)
{
  constexpr auto escape = [] (char c, OutputStream& out) {
    // spaces must be encoded as ' ', not '+'
    return percent_encode(c == '+' ? ' ' : c, out);
  };
  auto encoder = transformed_if(need_percent_encode, escape, out);
  auto decoder = percent_decoded(encoder);
  return write(begin, end, decoder);
}

template <typename OutputStream>
void write_canonical_parameter_value(const char* begin, const char* end,
                                     OutputStream&& out)
{
  constexpr auto escape = [] (char c, OutputStream& out) {
    if (c == '=') { // = in the value gets double-encoded
      percent_encode_twice(c, out);
    } else {
      // spaces must be encoded as ' ', not '+'
      percent_encode(c == '+' ? ' ' : c, out);
    }
  };
  auto encoder = transformed_if(need_percent_encode, escape, out);
  auto decoder = percent_decoded(encoder);
  write(begin, end, decoder);
}

template <typename OutputStream>
void write_canonical_parameter(const char* begin, const char* end,
                               OutputStream&& out)
{
  auto delim = std::find(begin, end, '=');
  write_canonical_parameter_name(begin, delim, out);
  write('=', out);
  if (delim != end) {
    write_canonical_parameter_value(std::next(delim), end, out);
  }
}

// write the query string to output in canonical form
template <typename OutputStream>
void write_canonical_query(const char* begin, const char* end,
                           OutputStream&& out)
{
  if (begin == end) {
    return;
  }
  if (*begin == '?') {
    ++begin;
    if (begin == end) {
      return;
    }
  }
  const auto count = 1 + std::count(begin, end, '&');
  struct parameter {
    const char* begin;
    const char* end;
  };
  const auto params = static_cast<parameter*>(
      ::alloca(count * sizeof(parameter)));

  const auto params_end = parse_query_parameters(begin, end, params);

  // sort parameters by canonical query name and value
  struct parameter_less {
    char transform(char c) const {
      return c == '+' ? ' ' : c;
    }
    bool operator()(char l, char r) const {
      return transform(l) < transform(r);
    }
    bool operator()(const parameter& l, const parameter& r) const {
      // sort in percent-decoded form
      using iterator = percent_decoded_iterator<const char*>;
      return std::lexicographical_compare(
          iterator{l.begin, l.end}, iterator{},
          iterator{r.begin, r.end}, iterator{}, *this);
    }
  };
  std::sort(params, params_end, parameter_less{});

  // write the sorted parameters in canonical form
  bool first = true;
  for (auto param = params; param != params_end; ++param) {
    if (first) {
      first = false;
    } else {
      write('&', out);
    }
    write_canonical_parameter(param->begin, param->end, out);
  }
}

} // namespace awssign::v4::detail
