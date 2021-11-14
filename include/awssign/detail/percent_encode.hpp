#pragma once

#include <cstdio>
#include <awssign/detail/emit.hpp>

namespace awssign::detail {

template <typename Writer> // void(const char*, const char*)
std::size_t percent_encode(unsigned char c, Writer&& out)
{
  char buffer[10]; // longest string for int is "%FFFFFFFF\0"
  const auto count = std::snprintf(buffer, sizeof(buffer),
                                   "%%%.2X", static_cast<int>(c));
  return emit(buffer, buffer + count, out);
}

} // namespace awssign::detail
