#pragma once

#include <awssign/v4/detail/canonical_headers.hpp>

namespace awssign::v4 {

/// output the list of headers in canonical form
template <typename HeaderIterator, // forward iterator with i->name()/i->value()
          typename Writer> // void(const char*, const char*)
std::size_t canonical_headers(HeaderIterator header0,
                              HeaderIterator headerN,
                              Writer&& out)
{
  const std::size_t count = std::distance(header0, headerN);
  // stack-allocate an array of canonical_header[count]
  auto headers = static_cast<detail::canonical_header*>(
      ::alloca(count * sizeof(detail::canonical_header)));
  auto headers_end = headers + count;

  auto o = headers;
  for (auto i = header0; i != headerN; ++o, ++i) {
    o->name = detail::trim(i->name());
    o->value = i->value();
  }

  // stable sort headers by canonical name
  constexpr auto iless = detail::canonical_name_less{};
  std::stable_sort(headers, headers_end, iless);

  // write out the headers in canonical format
  std::size_t bytes = 0;
  std::string_view last_name;
  for (o = headers; o != headers_end; ++o) {
    const bool iequal = !iless(last_name, o->name);
    if (iequal) {
      // comma-separate values with the same header name
      bytes += detail::emit(',', out);
      bytes += detail::canonical_header_value(o->value.begin(),
                                              o->value.end(), out);
    } else {
      if (!last_name.empty()) {
        // finish the previous line
        bytes += detail::emit('\n', out);
      }
      last_name = o->name;
      // write name:value
      bytes += detail::canonical_header_name(o->name.begin(),
                                             o->name.end(), out);
      bytes += detail::emit(':', out);
      bytes += detail::canonical_header_value(o->value.begin(),
                                              o->value.end(), out);
    }
  }
  if (!last_name.empty()) {
    // finish the last line
    bytes += detail::emit('\n', out);
  }
  return bytes;
}

} // namespace awssign::v4
