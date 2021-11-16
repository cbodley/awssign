#pragma once

#include <string_view>
#include <awssign/detail/emit.hpp>
#include <awssign/v4/detail/canonical_headers.hpp>
#include <awssign/v4/detail/canonical_query.hpp>
#include <awssign/v4/detail/canonical_uri.hpp>

namespace awssign::v4::detail {

/// write the canonical request to output
template <typename HeaderIterator,
          typename Writer> // void(const char*, const char*)
std::size_t canonical_request(std::string_view method,
                              std::string_view uri_path,
                              std::string_view query,
                              HeaderIterator header0,
                              HeaderIterator headerN,
                              std::string_view payload_hash,
                              Writer&& out)
{
  using awssign::detail::emit;
  std::size_t bytes = 0;
  // CanonicalRequest =
  //   HTTPRequestMethod + '\n' +
  bytes += emit(method, out);
  bytes += emit('\n', out);
  //   CanonicalURI + '\n' +
  bytes += canonical_uri(uri_path.begin(), uri_path.end(), out);
  bytes += emit('\n', out);
  //   CanonicalQueryString + '\n' +
  bytes += canonical_query(query.begin(), query.end(), out);
  bytes += emit('\n', out);
  //   CanonicalHeaders + '\n' +
  bytes += canonical_headers(header0, headerN, out);
  bytes += emit('\n', out);
  //   SignedHeaders + '\n' +
  bytes += signed_headers(header0, headerN, out);
  bytes += emit('\n', out);
  //   HexEncode(Hash(RequestPayload))
  bytes += emit(payload_hash, out);
  return bytes;
}

} // namespace awssign::v4::detail
