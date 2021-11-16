#pragma once

#include <cstddef>
#include <iterator>
#include <string_view>

namespace awssign::detail {

// write a character sequence to the output
template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t emit(Iterator begin, Iterator end, Writer&& out)
{
  out(begin, end);
  return std::distance(begin, end);
}

// write a string_view to the output
template <typename Writer> // void(Iterator, Iterator)
std::size_t emit(std::string_view str, Writer&& out)
{
  out(str.begin(), str.end());
  return str.size();
}

// write a single character to the output
template <typename Writer> // void(const char*, const char*)
std::size_t emit(char c, Writer&& out)
{
  out(&c, &c + 1);
  return 1;
}

} // namespace awssign::detail
