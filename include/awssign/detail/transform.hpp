#pragma once

#include <algorithm>
#include <iterator>
#include <string_view>
#include <awssign/detail/emit.hpp>

namespace awssign::detail {

template <typename Iterator,
          typename BinaryOperation, // void(*Iterator, OutputStream&)
          typename OutputStream> // void(const char*, const char*)
void transform(Iterator begin, Iterator end,
               BinaryOperation&& op,
               OutputStream&& out)
{
  for (auto i = begin; i != end; ++i) {
    op(*i, out); // write the transformed output
  }
}

template <typename Iterator,
          typename UnaryPredicate, // bool(*Iterator)
          typename BinaryOperation, // void(*Iterator, OutputStream&)
          typename OutputStream> // void(const char*, const char*)
void transform_if(Iterator begin, Iterator end,
                  UnaryPredicate&& p,
                  BinaryOperation&& op,
                  OutputStream&& out)
{
  auto i = begin;
  for (;;) {
    auto next = std::find_if(i, end, p);
    if (i != next) { // write earlier characters that didn't match
      emit(i, next, out);
    }
    if (next == end) {
      break;
    }
    op(*next, out); // write the transformed output
    i = std::next(next);
  }
}

} // namespace awssign::detail
