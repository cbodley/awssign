#pragma once

#include <string_view>
#include <awssign/detail/emit.hpp>

namespace awssign::v4::detail {

using awssign::detail::emit;

template <typename OutputStream> // void(const char*, const char*)
void scope(std::string_view date, std::string_view region,
           std::string_view service, OutputStream&& out)
{
  emit(date.substr(0, 8), out); // YYYYMMDD
  emit('/', out);
  emit(region, out);
  emit('/', out);
  emit(service, out);
  emit("/aws4_request", out);
}

// write the string to sign
template <typename OutputStream> // void(const char*, const char*)
void string_to_sign(std::string_view hash_algorithm,
                    std::string_view date,
                    std::string_view region,
                    std::string_view service,
                    std::string_view canonical_request_hash,
                    OutputStream&& out)
{
  emit("AWS4-HMAC-", out);
  emit(hash_algorithm, out);
  emit('\n', out);
  emit(date, out);
  emit('\n', out);
  scope(date, region, service, out);
  emit('\n', out);
  emit(canonical_request_hash, out);
}

} // namespace awssign::v4::detail
