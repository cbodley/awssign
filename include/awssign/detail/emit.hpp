#pragma once

#include <cstddef>
#include <iterator>

namespace awssign::detail {

// write a character sequence to the output
template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t emit(Iterator begin, Iterator end, Writer&& out)
{
  out(begin, end);
  return std::distance(begin, end);
}

// write a single character to the output
template <typename Writer> // void(const char*, const char*)
std::size_t emit(char c, Writer&& out)
{
  out(&c, &c + 1);
  return 1;
}

} // namespace awssign::detail
