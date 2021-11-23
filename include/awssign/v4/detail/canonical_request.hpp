#pragma once

#include <string_view>
#include <awssign/detail/write.hpp>
#include <awssign/v4/detail/canonical_headers.hpp>
#include <awssign/v4/detail/canonical_query.hpp>
#include <awssign/v4/detail/canonical_uri.hpp>
#include <awssign/v4/detail/s3_canonical_uri.hpp>

namespace awssign::v4::detail {

/// write the canonical request to output
template <typename HeaderIterator,
          typename OutputStream>
void write_canonical_request(std::string_view service,
                             std::string_view method,
                             std::string_view uri_path,
                             std::string_view query,
                             HeaderIterator header0,
                             HeaderIterator headerN,
                             std::string_view payload_hash,
                             OutputStream&& out)
{
  using awssign::detail::write;
  // CanonicalRequest =
  //   HTTPRequestMethod + '\n' +
  write(method, out);
  write('\n', out);
  //   CanonicalURI + '\n' +
  if (service == "s3") {
    write_s3_canonical_uri(uri_path.begin(), uri_path.end(), out);
  } else {
    write_canonical_uri(uri_path.begin(), uri_path.end(), out);
  }
  write('\n', out);
  //   CanonicalQueryString + '\n' +
  write_canonical_query(query.begin(), query.end(), out);
  write('\n', out);
  //   CanonicalHeaders + '\n' +
  write_canonical_headers(header0, headerN, out);
  write('\n', out);
  //   SignedHeaders + '\n' +
  write_signed_headers(header0, headerN, out);
  write('\n', out);
  //   HexEncode(Hash(RequestPayload))
  write(payload_hash, out);
}

} // namespace awssign::v4::detail
