#pragma once

#include <cstddef>
#include <string_view>

namespace awssign::detail {

// write a character sequence to the output
template <typename OutputStream> // void(const char*, const char*)
void emit(const char* begin, const char* end, OutputStream&& out)
{
  out(begin, end);
}

// write a string_view to the output
template <typename OutputStream> // void(const char*, const char*)
void emit(std::string_view str, OutputStream&& out)
{
  out(str.begin(), str.end());
}

// write a single character to the output
template <typename OutputStream> // void(const char*, const char*)
void emit(char c, OutputStream&& out)
{
  out(&c, &c + 1);
}

} // namespace awssign::detail
