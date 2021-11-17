#pragma once

#include <algorithm>
#include <iterator>
#include <string_view>
#include <awssign/detail/emit.hpp>

namespace awssign::detail {

template <typename Iterator, // forward iterator with value_type=char
          typename BinaryOperation, // size_t(char, Writer&)
          typename Writer> // void(Iterator, Iterator)
std::size_t transform(Iterator begin, Iterator end,
                      BinaryOperation&& op,
                      Writer&& out)
{
  std::size_t bytes = 0;
  for (auto i = begin; i != end; ++i) {
    bytes += op(*i, out); // write the transformed output
  }
  return bytes;
}

template <typename Iterator, // forward iterator with value_type=char
          typename UnaryPredicate, // bool(char)
          typename BinaryOperation, // size_t(char, Writer&)
          typename Writer> // void(Iterator, Iterator)
std::size_t transform_if(Iterator begin, Iterator end,
                         UnaryPredicate&& p,
                         BinaryOperation&& op,
                         Writer&& out)
{
  std::size_t bytes = 0;
  auto i = begin;
  for (;;) {
    auto next = std::find_if(i, end, p);
    if (i != next) { // write earlier characters that didn't match
      bytes += emit(i, next, out);
    }
    if (next == end) {
      break;
    }
    bytes += op(*next, out); // write the transformed output
    i = std::next(next);
  }
  return bytes;
}

} // namespace awssign::detail
