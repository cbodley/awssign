#pragma once

#include <string_view>
#include <awssign/v4/credential_scope.hpp>

namespace awssign::v4 {

namespace authorization_header {

struct value_type {
  std::string_view algorithm;
  credential_scope::value_type credential;
  std::string_view signed_headers;
  std::string_view signature;
};

enum class parse_error {
  no_space_after_algorithm,
  empty_algorithm,
  no_credential,
  no_comma_after_credential,
  bad_credential,
  no_signed_headers,
  no_comma_after_signed_headers,
  no_signature,
  empty_signature,
};

struct parse_failure {
  parse_error error;
  std::size_t position;
};

class parse_result {
  bool failed;
  union {
    value_type value; // !failed
    parse_failure failure; // failed
  } u;
 public:
  parse_result(const value_type& value)
      : failed(false), u{value} {}
  parse_result(const parse_failure& failure)
      : failed(true), u{} {
    u.failure = failure;
  }
  operator bool() const noexcept { return !failed; }
  const value_type& value() const { return u.value; }
  const parse_failure& failure() const { return u.failure; }
};

inline parse_result parse(std::string_view value)
{
  value_type auth;

  // 1. 'AWS4-HMAC-SHA256' followed by any whitespace
  const auto begin1 = 0;
  const auto end1 = value.find_first_of(" \t\n", begin1);
  if (end1 == value.npos) {
    return parse_failure{parse_error::no_space_after_algorithm, begin1};
  }
  if (end1 == begin1) {
    return parse_failure{parse_error::empty_algorithm, begin1};
  }
  auth.algorithm = value.substr(begin1, end1 - begin1);

  // 2. 'Credential='
  const auto begin2 = value.find_first_not_of(" \t\n", end1);
  if (begin2 == value.npos) {
    return parse_failure{parse_error::no_credential, end1};
  }
  static constexpr std::string_view credential_prefix = "Credential=";
  if (value.compare(begin2, credential_prefix.size(), credential_prefix) != 0) {
    return parse_failure{parse_error::no_credential, begin2};
  }
  const auto end2 = begin2 + credential_prefix.size();

  // 3. 'AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request'
  const auto begin3 = end2;
  const auto end3 = value.find(',', begin3);
  if (end3 == value.npos) {
    return parse_failure{parse_error::no_comma_after_credential, begin3};
  }
  auto result = credential_scope::parse(value.substr(begin3, end3 - begin3));
  if (!result) {
    auto pos = begin3 + result.failure().position;
    return parse_failure{parse_error::bad_credential, pos};
  }
  auth.credential = result.value();

  // 4. 'SignedHeaders=' after any whitespace
  const auto begin4 = value.find_first_not_of(" \t\n", end3 + sizeof(','));
  if (begin4 == value.npos) {
    return parse_failure{parse_error::no_signed_headers, end3 + sizeof(',')};
  }
  static constexpr std::string_view headers_prefix = "SignedHeaders=";
  if (value.compare(begin4, headers_prefix.size(), headers_prefix) != 0) {
    return parse_failure{parse_error::no_signed_headers, begin4};
  }
  const auto end4 = begin4 + headers_prefix.size();

  // 5. 'host;range;x-amz-date'
  const auto begin5 = end4;
  const auto end5 = value.find(',', begin5);
  if (end5 == value.npos) {
    return parse_failure{parse_error::no_comma_after_signed_headers, begin5};
  }
  auth.signed_headers = value.substr(begin5, end5 - begin5);

  // 6. 'Signature=' after any whitespace
  const auto begin6 = value.find_first_not_of(" \t\n", end5 + sizeof(','));
  if (begin6 == value.npos) {
    return parse_failure{parse_error::no_signature, end5 + sizeof(',')};
  }
  static constexpr std::string_view signature_prefix = "Signature=";
  if (value.compare(begin6, signature_prefix.size(), signature_prefix) != 0) {
    return parse_failure{parse_error::no_signature, begin6};
  }
  const auto end6 = begin6 + signature_prefix.size();

  // 7. 'fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024'
  const auto begin7 = end6;
  auth.signature = value.substr(begin7);
  if (auth.signature.empty()) {
    return parse_failure{parse_error::empty_signature, begin7};
  }

  return auth;
}

} // namespace authorization_header

} // namespace awssign::v4
