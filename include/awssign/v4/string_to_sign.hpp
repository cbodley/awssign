#pragma once

#include <string_view>
#include <awssign/detail/emit.hpp>

namespace awssign::v4 {

namespace detail {

using awssign::detail::emit;

template <typename Writer> // void(const char*, const char*)
std::size_t scope(std::string_view date_YYYYMMDD, std::string_view region,
                  std::string_view service, Writer&& out)
{
  std::size_t bytes = 0;
  bytes += emit(date_YYYYMMDD, out);
  bytes += emit('/', out);
  bytes += emit(region, out);
  bytes += emit('/', out);
  bytes += emit(service, out);
  bytes += emit("/aws4_request", out);
  return bytes;
}

} // namespace detail

// write the string to sign
template <typename Writer> // void(const char*, const char*)
std::size_t string_to_sign(std::string_view hash_algorithm,
                           std::string_view date_iso8601,
                           std::string_view region,
                           std::string_view service,
                           std::string_view canonical_request_hash,
                           Writer&& out)
{
  std::size_t bytes = 0;
  constexpr auto aws4_hmac = std::string_view{"AWS4-HMAC-"};
  bytes += detail::emit("AWS4-HMAC-", out);
  bytes += detail::emit(hash_algorithm, out);
  bytes += detail::emit('\n', out);
  bytes += detail::emit(date_iso8601, out);
  bytes += detail::emit('\n', out);
  bytes += detail::scope(date_iso8601.substr(0, 8), // YYYYMMDD
                         region, service, out);
  bytes += detail::emit('\n', out);
  bytes += detail::emit(canonical_request_hash, out);
  return bytes;
}

} // namespace awssign::v4
