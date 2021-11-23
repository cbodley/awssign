#pragma once

#include <string_view>
#include <awssign/detail/write.hpp>

namespace awssign::v4::detail {

using awssign::detail::write;

template <typename OutputStream>
void write_scope(std::string_view date, std::string_view region,
                 std::string_view service, OutputStream&& out)
{
  write(date.substr(0, 8), out); // YYYYMMDD
  write('/', out);
  write(region, out);
  write('/', out);
  write(service, out);
  write("/aws4_request", out);
}

// write the string to sign
template <typename OutputStream>
void write_string_to_sign(std::string_view hash_algorithm,
                          std::string_view date,
                          std::string_view region,
                          std::string_view service,
                          std::string_view canonical_request_hash,
                          OutputStream&& out)
{
  write("AWS4-HMAC-", out);
  write(hash_algorithm, out);
  write('\n', out);
  write(date, out);
  write('\n', out);
  write_scope(date, region, service, out);
  write('\n', out);
  write(canonical_request_hash, out);
}

} // namespace awssign::v4::detail
