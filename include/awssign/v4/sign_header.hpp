#pragma once

#include <awssign/detail/hex_encode.hpp>
#include <awssign/detail/digest.hpp>
#include <awssign/detail/digest_writer.hpp>
#include <awssign/v4/detail/canonical_headers.hpp>
#include <awssign/v4/detail/canonical_request.hpp>
#include <awssign/v4/detail/signing_key.hpp>
#include <awssign/v4/detail/string_to_sign.hpp>

namespace awssign::v4 {

namespace detail {

using awssign::detail::digest;
using awssign::detail::digest_writer;
using awssign::detail::hmac;
using awssign::detail::hex_encode;

// write the Authorization header value
template <typename HeaderIterator,
          typename Writer> // void(const char*, const char*)
std::size_t authorization_header_value(std::string_view hash_algorithm,
                                       std::string_view access_key_id,
                                       std::string_view date_YYYYMMDD,
                                       std::string_view region,
                                       std::string_view service,
                                       HeaderIterator canonical_header0,
                                       HeaderIterator canonical_headerN,
                                       std::string_view signature,
                                       Writer&& out)
{
  std::size_t bytes = 0;
  bytes += emit("AWS4-HMAC-", out);
  bytes += emit(hash_algorithm, out);
  bytes += emit(" Credential=", out);
  bytes += emit(access_key_id, out);
  bytes += emit('/', out);
  bytes += emit(date_YYYYMMDD, out);
  bytes += emit('/', out);
  bytes += emit(region, out);
  bytes += emit('/', out);
  bytes += emit(service, out);
  bytes += emit("/aws4_request, SignedHeaders=", out);
  bytes += signed_headers(canonical_header0, canonical_headerN, out);
  bytes += emit(", Signature=", out);
  bytes += emit(signature, out);
  return bytes;
}

} // namespace detail

// generate a signature for the given request, and write the Authorization
// header's value to output
template <typename HeaderIterator,
          typename Writer> // void(const char*, const char*)
std::size_t sign_header(const char* hash_algorithm,
                        std::string_view access_key_id,
                        std::string_view secret_access_key,
                        std::string_view method,
                        std::string_view uri_path,
                        std::string_view query,
                        HeaderIterator header0,
                        HeaderIterator headerN,
                        std::string_view payload_hash,
                        std::string_view date_iso8601,
                        std::string_view region,
                        std::string_view service,
                        Writer&& out)
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
    detail::digest hash{hash_algorithm};
    detail::canonical_request(service, method, uri_path, query,
                              canonical_header0, canonical_headerN,
                              payload_hash, detail::digest_writer{hash});
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
  std::string_view signature;
  {
    detail::hmac hash{hash_algorithm, signing_key, signing_key_size};
    detail::string_to_sign(hash_algorithm, date_iso8601, region, service,
                           canonical_request_hash, detail::digest_writer{hash});
    unsigned char buffer[detail::hmac::max_size];
    const auto size = hash.finish(buffer);
    char* pos = signature_buffer;
    auto len = detail::hex_encode(buffer, buffer + size,
      [&pos] (const char* begin, const char* end) {
        pos = std::copy(begin, end, pos);
      });
    signature = std::string_view{signature_buffer, len};
  }

  // write the Authorization header value
  return detail::authorization_header_value(
      hash_algorithm, access_key_id, date_YYYYMMDD, region, service,
      canonical_header0, canonical_headerN, signature, out);
}

} // namespace awssign::v4
