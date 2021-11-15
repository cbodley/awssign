#pragma once

#include <awssign/v4/detail/canonical_headers.hpp>

namespace awssign::v4 {

/// output the CanonicalHeaders and SignedHeaders components of the canonical
/// request
template <typename HeaderIterator, // forward iterator with i->name()/i->value()
          typename Writer> // void(const char*, const char*)
std::size_t canonical_signed_headers(HeaderIterator header0,
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
  std::stable_sort(headers, headers_end, detail::canonical_name_less{});

  std::size_t bytes = 0;

  // write out the sorted headers in canonical format for CanonicalHeaders
  bytes += detail::canonical_headers(headers, headers_end, out);
  // an extra \n separates the CanonicalHeaders and SignedHeaders sections of
  // the CanonicalRequest
  bytes += detail::emit('\n', out);
  // write out the sorted header names for SignedHeaders
  bytes += detail::signed_headers(headers, headers_end, out);

  return bytes;
}

} // namespace awssign::v4
