#pragma once

#include <string_view>
#include <awssign/detail/emit.hpp>
#include <awssign/v4/detail/canonical_headers.hpp>
#include <awssign/v4/detail/canonical_query.hpp>
#include <awssign/v4/detail/canonical_uri.hpp>
#include <awssign/v4/detail/s3_canonical_uri.hpp>

namespace awssign::v4::detail {

/// write the canonical request to output
template <typename HeaderIterator,
          typename OutputStream> // void(const char*, const char*)
void canonical_request(std::string_view service,
                       std::string_view method,
                       std::string_view uri_path,
                       std::string_view query,
                       HeaderIterator header0,
                       HeaderIterator headerN,
                       std::string_view payload_hash,
                       OutputStream&& out)
{
  using awssign::detail::emit;
  // CanonicalRequest =
  //   HTTPRequestMethod + '\n' +
  emit(method, out);
  emit('\n', out);
  //   CanonicalURI + '\n' +
  if (service == "s3") {
    s3_canonical_uri(uri_path.begin(), uri_path.end(), out);
  } else {
    canonical_uri(uri_path.begin(), uri_path.end(), out);
  }
  emit('\n', out);
  //   CanonicalQueryString + '\n' +
  canonical_query(query.begin(), query.end(), out);
  emit('\n', out);
  //   CanonicalHeaders + '\n' +
  canonical_headers(header0, headerN, out);
  emit('\n', out);
  //   SignedHeaders + '\n' +
  signed_headers(header0, headerN, out);
  emit('\n', out);
  //   HexEncode(Hash(RequestPayload))
  emit(payload_hash, out);
}

} // namespace awssign::v4::detail
