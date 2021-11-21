#pragma once

#include <chrono>
#include <awssign/detail/buffered_stream.hpp>
#include <awssign/detail/digest.hpp>
#include <awssign/detail/digest_stream.hpp>
#include <awssign/detail/hex_encode.hpp>
#include <awssign/detail/output_stream.hpp>
#include <awssign/detail/transform_stream.hpp>
#include <awssign/v4/detail/canonical_headers.hpp>
#include <awssign/v4/detail/canonical_request.hpp>
#include <awssign/v4/detail/signing_key.hpp>
#include <awssign/v4/detail/string_to_sign.hpp>

namespace awssign::v4 {

namespace detail {

using awssign::detail::buffered;
using awssign::detail::digest;
using awssign::detail::digest_stream;
using awssign::detail::hmac;
using awssign::detail::hex_encode;
using awssign::detail::output_stream;
using awssign::detail::transformed_if;

// encode the value of the X-Amz-Credential param
template <typename OutputStream> // void(const char*, const char*)
void emit_credential(std::string_view access_key_id,
                     std::string_view date,
                     std::string_view region,
                     std::string_view service,
                     OutputStream&& out)
{
  emit(access_key_id, out);
  emit('/', out);
  scope(date, region, service, out);
}

template <typename HeaderIterator, // forward canonical_header iterator
          typename OutputStream> // void(const char*, const char*)
void emit_signed_params(const char* hash_algorithm,
                        std::string_view access_key_id,
                        std::string_view region,
                        std::string_view service,
                        std::string_view date,
                        std::string_view expiration,
                        HeaderIterator header0,
                        HeaderIterator headerN,
                        OutputStream&& out)
{
  constexpr auto escape = [] (char c, OutputStream& out) {
    // spaces must be encoded as ' ', not '+'
    return percent_encode(c == '+' ? ' ' : c, out);
  };

  // querystring += &X-Amz-Algorithm=algorithm
  emit("X-Amz-Algorithm=AWS4-HMAC-", out);
  emit(hash_algorithm, out);
  // querystring += &X-Amz-Credential= urlencode(access_key_ID + '/' + credential_scope)
  emit("&X-Amz-Credential=", out);
  emit_credential(access_key_id, date, region, service,
                  transformed_if(need_percent_encode, escape, out));
  // querystring += &X-Amz-Date=date
  emit("&X-Amz-Date=", out);
  emit(date, out);
  // querystring += &X-Amz-Expires=timeout interval
  emit("&X-Amz-Expires=", out);
  emit(expiration, out);
  // querystring += &X-Amz-SignedHeaders=signed_headers
  emit("&X-Amz-SignedHeaders=", out);
  signed_headers(header0, headerN, transformed_if(need_percent_encode,
                                                  escape, out));
}

struct query_stream {
  char* pos;
  std::size_t bytes;
  std::size_t capacity;

  constexpr query_stream(char* begin, char* end) noexcept
      : pos(begin), bytes(0),
        capacity(std::distance(begin, end))
  {}

  void operator()(const char* begin, const char* end) {
    bytes += std::distance(begin, end);
    // once we reach capacity, stop copying the bytes but keep counting them so
    // we can return an error to the caller with the required capacity
    if (bytes <= capacity) {
      pos = std::copy(begin, end, pos);
    }
  }
};

} // namespace detail

class query_length_error : public std::length_error {
  std::size_t capacity;
 public:
  query_length_error(std::size_t capacity)
     : std::length_error("insufficient query string capacity"),
       capacity(capacity)
  {}

  constexpr std::size_t required_capacity() const { return capacity; }
};

// add query parameters to presign the given request. the caller must provide
// additional capacity at the end of the query string. returns a pointer past
// the last byte written, or throws a query_length_error exception that contains
// the number of bytes of extra query string capacity required
template <typename HeaderIterator> // forward canonical_header iterator
char* presign(const char* hash_algorithm,
              std::string_view access_key_id,
              std::string_view secret_access_key,
              std::string_view region,
              std::string_view service,
              std::string_view date,
              std::string_view expiration,
              std::string_view method,
              std::string_view uri_path,
              HeaderIterator header0,
              HeaderIterator headerN,
              std::string_view payload_hash,
              char* query_begin,
              char* query_end,
              char* query_capacity)
{
  // stack-allocate an array of canonical_header[]
  const std::size_t header_count = std::distance(header0, headerN);
  auto canonical_header0 = static_cast<detail::canonical_header*>(
      ::alloca(header_count * sizeof(detail::canonical_header)));
  // stable sort headers by canonical name
  const auto canonical_headerN = detail::sorted_canonical_headers(
      header0, headerN, canonical_header0);

  // append the presigned query params that are part of the canonical request
  auto query_stream = detail::query_stream(query_end, query_capacity);
  if (query_begin == query_end) {
    detail::emit('?', query_stream);
  }
  emit_signed_params(hash_algorithm, access_key_id,
                     region, service, date, expiration,
                     canonical_header0, canonical_headerN, query_stream);

  // generate the signing key
  unsigned char signing_key[detail::hmac::max_size];
  const int signing_key_size = detail::build_signing_key(
      hash_algorithm, secret_access_key,
      date, region, service, signing_key);

  // check that we have the capacity to write the signature param
  constexpr auto signature_param = std::string_view{"&X-Amz-Signature="};
  const std::size_t signature_value_size = signing_key_size * 2; // hex encoded
  std::size_t required_capacity = query_stream.bytes +
      signature_param.size() + signature_value_size;
  if (required_capacity > query_stream.capacity) {
    throw query_length_error(required_capacity);
  }

  const std::size_t query_size = std::distance(query_begin, query_stream.pos);
  const auto query = std::string_view{query_begin, query_size};

  // generate the canonical request hash
  char canonical_buffer[detail::digest::max_size * 2]; // hex encoded
  std::string_view canonical_request_hash;
  {
    detail::digest hash{hash_algorithm};
    detail::digest_stream stream{hash};
    detail::canonical_request(service, method, uri_path,
                              query.substr(1), // skip ?
                              canonical_header0, canonical_headerN,
                              payload_hash, detail::buffered<256>(stream));
    unsigned char buffer[detail::digest::max_size];
    const auto size = hash.finish(buffer);
    char* pos = canonical_buffer;
    detail::hex_encode(buffer, buffer + size, detail::output_stream{pos});
    const std::size_t len = std::distance(canonical_buffer, pos);
    canonical_request_hash = std::string_view{canonical_buffer, len};
  }

  // sign the string-to-sign
  char signature_buffer[detail::hmac::max_size * 2]; // hex encoded
  std::string_view signature;
  {
    detail::hmac hash{hash_algorithm, signing_key, signing_key_size};
    detail::digest_stream stream{hash};
    detail::string_to_sign(hash_algorithm, date, region, service,
                           canonical_request_hash,
                           detail::buffered<256>(stream));
    unsigned char buffer[detail::hmac::max_size];
    const auto size = hash.finish(buffer);
    char* pos = signature_buffer;
    detail::hex_encode(buffer, buffer + size, detail::output_stream{pos});
    const std::size_t len = std::distance(signature_buffer, pos);
    signature = std::string_view{signature_buffer, len};
  }

  // append the X-Amz-Signature param
  detail::emit(signature_param, query_stream);
  detail::emit(signature, query_stream);
  return query_stream.pos;
}

} // namespace awssign::v4
