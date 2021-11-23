#pragma once

#include <awssign/detail/digest.hpp>
#include <awssign/detail/digest_stream.hpp>
#include <awssign/detail/hex_encode.hpp>
#include <awssign/detail/output_stream.hpp>
#include <awssign/v4/detail/canonical_headers.hpp>
#include <awssign/v4/detail/canonical_request.hpp>
#include <awssign/v4/detail/signing_key.hpp>
#include <awssign/v4/detail/string_to_sign.hpp>

namespace awssign::v4 {

namespace detail {

using awssign::detail::buffered_digest_stream;
using awssign::detail::digest;
using awssign::detail::hex_encode;
using awssign::detail::hmac;
using awssign::detail::output_stream;

// write the Authorization header value
template <typename HeaderIterator,
          typename OutputStream>
void write_authorization_header_value(std::string_view hash_algorithm,
                                      std::string_view access_key_id,
                                      std::string_view date,
                                      std::string_view region,
                                      std::string_view service,
                                      HeaderIterator canonical_header0,
                                      HeaderIterator canonical_headerN,
                                      std::string_view signature,
                                      OutputStream&& out)
{
  write("AWS4-HMAC-", out);
  write(hash_algorithm, out);
  write(" Credential=", out);
  write(access_key_id, out);
  write('/', out);
  write_scope(date, region, service, out);
  write(", SignedHeaders=", out);
  write_signed_headers(canonical_header0, canonical_headerN, out);
  write(", Signature=", out);
  write(signature, out);
}

} // namespace detail

// generate a signature for the given request, and write the Authorization
// header's value to output
template <typename HeaderIterator,
          typename OutputStream>
void sign(const char* hash_algorithm,
          std::string_view access_key_id,
          std::string_view secret_access_key,
          std::string_view method,
          std::string_view uri_path,
          std::string_view query,
          HeaderIterator header0,
          HeaderIterator headerN,
          std::string_view payload_hash,
          std::string_view date,
          std::string_view region,
          std::string_view service,
          OutputStream&& out)
{
  // stack-allocate an array of canonical_header[]
  const std::size_t header_count = std::distance(header0, headerN);
  auto canonical_header0 = static_cast<detail::canonical_header*>(
      ::alloca(header_count * sizeof(detail::canonical_header)));
  // stable sort headers by canonical name
  const auto canonical_headerN = detail::sorted_canonical_headers(
      header0, headerN, canonical_header0);

  // generate the canonical request hash
  char canonical_buffer[detail::digest::max_size * 2]; // hex encoded
  std::string_view canonical_request_hash;
  {
    auto hash = detail::digest{hash_algorithm};
    detail::write_canonical_request(service, method, uri_path, query,
                                    canonical_header0, canonical_headerN,
                                    payload_hash,
                                    detail::buffered_digest_stream(hash));
    unsigned char buffer[detail::digest::max_size];
    const auto size = hash.finish(buffer);
    char* pos = canonical_buffer;
    detail::hex_encode(buffer, buffer + size, detail::output_stream{pos});
    const std::size_t len = std::distance(canonical_buffer, pos);
    canonical_request_hash = std::string_view{canonical_buffer, len};
  }

  // generate the signing key
  unsigned char signing_key[detail::hmac::max_size];
  const int signing_key_size = detail::build_signing_key(
      hash_algorithm, secret_access_key,
      date, region, service,
      signing_key);

  // sign the string-to-sign
  char signature_buffer[detail::hmac::max_size * 2]; // hex encoded
  std::string_view signature;
  {
    auto hash = detail::hmac{hash_algorithm, signing_key, signing_key_size};
    detail::write_string_to_sign(hash_algorithm, date, region, service,
                                 canonical_request_hash,
                                 detail::buffered_digest_stream(hash));
    unsigned char buffer[detail::hmac::max_size];
    const auto size = hash.finish(buffer);
    char* pos = signature_buffer;
    detail::hex_encode(buffer, buffer + size, detail::output_stream{pos});
    const std::size_t len = std::distance(signature_buffer, pos);
    signature = std::string_view{signature_buffer, len};
  }

  // write the Authorization header value
  return detail::write_authorization_header_value(
      hash_algorithm, access_key_id, date, region, service,
      canonical_header0, canonical_headerN, signature, out);
}

} // namespace awssign::v4
