#pragma once

#include <chrono>
#include <awssign/detail/buffered_writer.hpp>
#include <awssign/detail/digest.hpp>
#include <awssign/detail/digest_writer.hpp>
#include <awssign/detail/hex_encode.hpp>
#include <awssign/v4/detail/canonical_headers.hpp>
#include <awssign/v4/detail/canonical_request.hpp>
#include <awssign/v4/detail/signing_key.hpp>
#include <awssign/v4/detail/string_to_sign.hpp>

namespace awssign::v4 {

namespace detail {

using awssign::detail::buffered;
using awssign::detail::digest;
using awssign::detail::digest_writer;
using awssign::detail::hmac;
using awssign::detail::hex_encode;

// encode the value of the X-Amz-Credential param
template <typename Writer> // void(const char*, const char*)
void emit_credential(std::string_view access_key_id,
                     std::string_view date_YYYYMMDD,
                     std::string_view region,
                     std::string_view service,
                     Writer&& out)
{
  emit(access_key_id, out);
  emit('/', out);
  scope(date_YYYYMMDD, region, service, out);
}

// Writer wrapper that percent encodes all input data. note that percent
// encoding may write more output bytes than input, so you can't rely on
// the number of bytes returned by emit()
template <typename Writer> // void(const char*, const char*)
struct percent_encode_writer {
  Writer& out;
  void operator()(const char* begin, const char* end) {
    constexpr auto escape = [] (char c, Writer& out) {
      // spaces must be encoded as ' ', not '+'
      return percent_encode(c == '+' ? ' ' : c, out);
    };
    transform_if(begin, end, need_percent_encode, escape, out);
  }
};

template <typename Writer> // void(const char*, const char*)
percent_encode_writer<Writer> percent_encoder(Writer&& out) {
  return {out};
}

template <typename HeaderIterator, // forward canonical_header iterator
          typename Writer> // void(const char*, const char*)
void emit_signed_params(const char* hash_algorithm,
                        std::string_view access_key_id,
                        std::string_view region,
                        std::string_view service,
                        std::string_view date_iso8601,
                        std::string_view expiration,
                        HeaderIterator header0,
                        HeaderIterator headerN,
                        bool percent_encoded,
                        Writer&& out)
{
  auto date_YYYYMMDD = date_iso8601.substr(0, 8);

  // querystring += &X-Amz-Algorithm=algorithm
  emit("X-Amz-Algorithm=AWS4-HMAC-", out);
  emit(hash_algorithm, out);
  // querystring += &X-Amz-Credential= urlencode(access_key_ID + '/' + credential_scope)
  emit("&X-Amz-Credential=", out);
  if (percent_encoded) {
    emit_credential(access_key_id, date_YYYYMMDD, region, service,
                    percent_encoder(out));
  } else {
    emit_credential(access_key_id, date_YYYYMMDD, region, service, out);
  }
  // querystring += &X-Amz-Date=date
  emit("&X-Amz-Date=", out);
  emit(date_iso8601, out);
  // querystring += &X-Amz-Expires=timeout interval
  emit("&X-Amz-Expires=", out);
  emit(expiration, out);
  // querystring += &X-Amz-SignedHeaders=signed_headers
  emit("&X-Amz-SignedHeaders=", out);
  if (percent_encoded) {
    signed_headers(header0, headerN, percent_encoder(out));
  } else {
    signed_headers(header0, headerN, out);
  }
}

struct query_appender {
  char* pos;
  std::size_t bytes;
  std::size_t capacity;

  constexpr query_appender(char* begin, char* end) noexcept
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
              std::string_view date_iso8601,
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

  // append the presigned query params that are part of the canonical request.
  // note that canonical_request() will percent-encode these parameter values,
  // so we don't add percent encoding here. the final output does need percent-
  // encoding, so we'll have to rewrite them with percent encoding afterwards
  bool percent_encode_params = false;
  auto query_writer = detail::query_appender(query_end, query_capacity);
  if (query_begin == query_end) {
    detail::emit('?', query_writer);
  }
  emit_signed_params(hash_algorithm, access_key_id,
                     region, service, date_iso8601, expiration,
                     canonical_header0, canonical_headerN,
                     percent_encode_params, query_writer);

  const auto date_YYYYMMDD = date_iso8601.substr(0, 8);

  // generate the signing key
  unsigned char signing_key[detail::hmac::max_size];
  const int signing_key_size = detail::build_signing_key(
      hash_algorithm, secret_access_key,
      date_YYYYMMDD, region, service,
      signing_key);

  // check that we have the capacity to write the signature param
  constexpr auto signature_param = std::string_view{"&X-Amz-Signature="};
  const std::size_t signature_value_size = signing_key_size * 2; // hex encoded
  std::size_t required_capacity = query_writer.bytes +
      signature_param.size() + signature_value_size;
  if (required_capacity > query_writer.capacity) {
    // TODO: this required_capacity doesn't take later percent-encoding into
    // account. we should recalculate this with percent-encoding so we can
    // return the right value
    throw query_length_error(required_capacity);
  }

  std::size_t query_size = std::distance(query_begin, query_writer.pos);
  auto query = std::string_view{query_begin, query_size};

  // generate the canonical request hash
  char canonical_buffer[detail::digest::max_size * 2]; // hex encoded
  std::string_view canonical_request_hash;
  {
    detail::digest hash{hash_algorithm};
    detail::digest_writer hash_writer{hash};
    detail::canonical_request(service, method, uri_path,
                              query.substr(1), // skip ?
                              canonical_header0, canonical_headerN,
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

  // sign the string-to-sign
  char signature_buffer[detail::hmac::max_size * 2]; // hex encoded
  std::string_view signature;
  {
    detail::hmac hash{hash_algorithm, signing_key, signing_key_size};
    detail::digest_writer writer{hash};
    detail::string_to_sign(hash_algorithm, date_iso8601, region, service,
                           canonical_request_hash,
                           detail::buffered<256>(writer));
    unsigned char buffer[detail::hmac::max_size];
    const auto size = hash.finish(buffer);
    char* pos = signature_buffer;
    auto len = detail::hex_encode(buffer, buffer + size,
      [&pos] (const char* begin, const char* end) {
        pos = std::copy(begin, end, pos);
      });
    signature = std::string_view{signature_buffer, len};
  }

  // now that we're done with canonical_request(), we need to rewrite the
  // presigned query parameters with percent-encoding
  percent_encode_params = true;
  query_writer = detail::query_appender(query_end, query_capacity);
  if (query_begin == query_end) {
    detail::emit('?', query_writer);
  }
  emit_signed_params(hash_algorithm, access_key_id,
                     region, service, date_iso8601, expiration,
                     canonical_header0, canonical_headerN,
                     percent_encode_params, query_writer);

  // percent-encoding may require more capacity, so check again
  required_capacity = query_writer.bytes +
      signature_param.size() + signature_value_size;
  if (required_capacity > query_writer.capacity) {
    throw query_length_error(required_capacity);
  }

  query_size = std::distance(query_begin, query_writer.pos);
  query = std::string_view{query_begin, query_size};

  // append the X-Amz-Signature param
  detail::emit(signature_param, query_writer);
  detail::emit(signature, query_writer);
  return query_writer.pos;
}

} // namespace awssign::v4
