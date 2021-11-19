#pragma once

#include <awssign/detail/buffered_writer.hpp>
#include <awssign/detail/digest.hpp>
#include <awssign/detail/digest_writer.hpp>
#include <awssign/detail/hex_encode.hpp>
#include <awssign/v4/detail/canonical_headers.hpp>
#include <awssign/v4/detail/canonical_request.hpp>
#include <awssign/v4/detail/signed_header_iterator.hpp>
#include <awssign/v4/detail/signing_key.hpp>
#include <awssign/v4/detail/string_to_sign.hpp>

namespace awssign::v4 {

namespace detail {

using awssign::detail::buffered;
using awssign::detail::digest;
using awssign::detail::digest_writer;
using awssign::detail::hex_encode;
using awssign::detail::hmac;

} // namespace detail

// verify that the signature matches what we generate for the given request
template <typename HeaderIterator>
bool verify(const char* hash_algorithm,
            std::string_view date_iso8601,
            std::string_view region,
            std::string_view service,
            std::string_view signed_headers,
            std::string_view method,
            std::string_view uri_path,
            std::string_view query,
            HeaderIterator header0,
            HeaderIterator headerN,
            std::string_view payload_hash,
            std::string_view secret_access_key,
            std::string_view signature)
{
  // stack-allocate an array of canonical_header[]
  const std::size_t header_count = std::distance(header0, headerN);
  auto canonical_header0 = static_cast<detail::canonical_header*>(
      ::alloca(header_count * sizeof(detail::canonical_header)));
  // stable sort headers by canonical name
  const auto canonical_headerN = detail::sorted_canonical_headers(
      header0, headerN, canonical_header0);

  // use a special header iterator for canonical_request() that filters
  // out headers whose names aren't in signed_headers
  auto filtered_header0 = detail::make_signed_header_iterator(
      signed_headers, canonical_header0, canonical_headerN);
  auto filtered_headerN = detail::signed_header_iterator<
      detail::canonical_header*>{}; // end iterator

  // generate the canonical request hash
  char canonical_buffer[detail::digest::max_size * 2]; // hex encoded
  std::string_view canonical_request_hash;
  {
    detail::digest hash{hash_algorithm};
    detail::digest_writer hash_writer{hash};
    detail::canonical_request(service, method, uri_path, query,
                              filtered_header0, filtered_headerN,
                              payload_hash, detail::buffered<256>(hash_writer));
    unsigned char buffer[detail::digest::max_size];
    const auto size = hash.finish(buffer);
    char* pos = canonical_buffer;
    auto len = detail::hex_encode(buffer, buffer + size,
      [&pos] (const char* begin, const char* end) {
        pos = std::copy(begin, end, pos);
      });
    canonical_request_hash = std::string_view{canonical_buffer, len};
  }

  const auto date_YYYYMMDD = date_iso8601.substr(0, 8);

  // generate the signing key
  unsigned char signing_key[detail::hmac::max_size];
  const int signing_key_size = detail::build_signing_key(
      hash_algorithm, secret_access_key,
      date_YYYYMMDD, region, service,
      signing_key);

  // sign the string-to-sign
  char signature_buffer[detail::hmac::max_size * 2]; // hex encoded
  detail::hmac hash{hash_algorithm, signing_key, signing_key_size};
  detail::digest_writer writer{hash};
  detail::string_to_sign(hash_algorithm, date_iso8601, region, service,
                         canonical_request_hash, detail::buffered<256>(writer));
  unsigned char buffer[detail::hmac::max_size];
  const auto size = hash.finish(buffer);
  char* pos = signature_buffer;
  auto len = detail::hex_encode(buffer, buffer + size,
    [&pos] (const char* begin, const char* end) {
      pos = std::copy(begin, end, pos);
    });

  return signature == std::string_view{signature_buffer, len};
}

} // namespace awssign::v4