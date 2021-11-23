#pragma once

#include <cstddef>
#include <string_view>

namespace awssign::detail {

// write a single character to the output stream
template <typename OutputStream>
void write(char c, OutputStream&& out)
{
  out(&c, &c + 1);
}

// write a character sequence to the output stream
template <typename OutputStream>
void write(const char* begin, const char* end, OutputStream&& out)
{
  out(begin, end);
}

// write a string_view to the output stream
template <typename OutputStream>
void write(std::string_view str, OutputStream&& out)
{
  out(str.begin(), str.end());
}

} // namespace awssign::detail
