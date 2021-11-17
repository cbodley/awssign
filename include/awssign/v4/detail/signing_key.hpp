#pragma once

#include <string_view>
#include <awssign/detail/digest.hpp>

namespace awssign::v4::detail {

using awssign::detail::hmac;

// use the given hash algorithm to derive the signing key
std::size_t build_signing_key(const char* hash_algorithm,
                              std::string_view secret_access_key,
                              std::string_view date_YYYYMMDD,
                              std::string_view region,
                              std::string_view service,
                              unsigned char* signing_key)
{
  // DateKey = HMAC("AWS4"+"<SecretAccessKey>", "<YYYYMMDD>")
  unsigned char aws4_key[256] = {'A','W','S','4'};
  const int aws4_key_len = 4 + secret_access_key.copy(
      reinterpret_cast<char*>(aws4_key) + 4, sizeof(aws4_key) - 4);
  auto hash = hmac{hash_algorithm, aws4_key, aws4_key_len};
  hash.update(date_YYYYMMDD.data(), date_YYYYMMDD.size());
  unsigned char date_key[hmac::max_size];
  const int date_key_len = hash.finish(date_key);

  // DateRegionKey = HMAC(<DateKey>, "<aws-region>")
  hash.init(date_key, date_key_len);
  hash.update(region.data(), region.size());
  unsigned char region_key[hmac::max_size];
  const int region_key_len = hash.finish(region_key);

  // DateRegionServiceKey = HMAC(<DateRegionKey>, "<aws-service>")
  hash.init(region_key, region_key_len);
  hash.update(service.data(), service.size());
  unsigned char service_key[hmac::max_size];
  const int service_key_len = hash.finish(service_key);

  // SigningKey = HMAC(<DateRegionServiceKey>, "aws4_request")
  hash.init(service_key, service_key_len);
  constexpr auto aws4_request = std::string_view{"aws4_request"};
  hash.update(aws4_request.data(), aws4_request.size());
  return hash.finish(signing_key);
}

} // namespace awssign::v4::detail
