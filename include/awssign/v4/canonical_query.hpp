#pragma once

#include <algorithm>
#include <cstddef>
#include <awssign/v4/detail/canonical_query.hpp>

namespace awssign::v4 {

template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t canonical_query(Iterator begin, Iterator end, Writer&& out)
{
  if (begin == end) {
    return 0;
  }
  const auto count = 1 + std::count(begin, end, '&');
  struct parameter {
    Iterator begin;
    Iterator end;
  };
  const auto params = static_cast<parameter*>(
      ::alloca(count * sizeof(parameter)));

  const auto params_end = detail::parse_query_parameters(begin, end, params);

  // sort parameters by 'encoded' query name and value
  struct parameter_less {
    char transform(char c) const {
      return c == '+' ? ' ' : c;
    }
    bool operator()(char l, char r) const {
      return transform(l) < transform(r);
    }
    bool operator()(const parameter& l, const parameter& r) const {
      return std::lexicographical_compare(l.begin, l.end,
                                          r.begin, r.end, *this);
    }
  };
  std::sort(params, params_end, parameter_less{});

  // write the sorted parameters in canonical form
  std::size_t bytes = 0;
  bool first = true;
  for (auto param = params; param != params_end; ++param) {
    if (first) {
      first = false;
    } else {
      bytes += detail::emit('&', out);
    }
    bytes += detail::canonical_parameter(param->begin, param->end, out);
  }
  return bytes;
}

} // namespace awssign::v4
