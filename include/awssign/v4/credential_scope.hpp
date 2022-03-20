#pragma once

#include <string_view>

namespace awssign::v4::credential_scope {

struct value_type {
  std::string_view access;
  std::string_view date;
  std::string_view region;
  std::string_view service;
  std::string_view request;
};

enum class parse_error {
  no_slash_after_access_key_id,
  empty_access_key_id,
  no_slash_after_date,
  empty_date,
  no_slash_after_region,
  empty_region,
  no_slash_after_service,
  empty_service,
  empty_request
};

struct parse_failure {
  parse_error error;
  std::size_t position;
};

class parse_result {
  bool failed;
  union {
    value_type value; // failed=false
    parse_failure failure; // failed=true
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
  value_type cred;

  // 1. 'AKIAIOSFODNN7EXAMPLE'
  const auto begin1 = 0;
  const auto end1 = value.find('/', begin1);
  if (end1 == value.npos) {
    return parse_failure{parse_error::no_slash_after_access_key_id, begin1};
  }
  if (end1 == begin1) {
    return parse_failure{parse_error::empty_access_key_id, begin1};
  }
  cred.access = value.substr(begin1, end1 - begin1);

  // 2. '20130524'
  const auto begin2 = end1 + sizeof('/');
  const auto end2 = value.find('/', begin2);
  if (end2 == value.npos) {
    return parse_failure{parse_error::no_slash_after_date, begin2};
  }
  if (end2 == begin2) {
    return parse_failure{parse_error::empty_date, begin2};
  }
  cred.date = value.substr(begin2, end2 - begin2);

  // 3. 'us-east-1'
  const auto begin3 = end2 + sizeof('/');
  const auto end3 = value.find('/', begin3);
  if (end3 == value.npos) {
    return parse_failure{parse_error::no_slash_after_region, begin3};
  }
  if (end3 == begin3) {
    return parse_failure{parse_error::empty_region, begin3};
  }
  cred.region = value.substr(begin3, end3 - begin3);

  // 4. 's3'
  const auto begin4 = end3 + sizeof('/');
  const auto end4 = value.find('/', begin4);
  if (end4 == value.npos) {
    return parse_failure{parse_error::no_slash_after_service, begin4};
  }
  if (end4 == begin4) {
    return parse_failure{parse_error::empty_service, begin4};
  }
  cred.service = value.substr(begin4, end4 - begin4);

  // 5. 'aws4_request'
  const auto begin5 = end4 + sizeof('/');
  cred.request = value.substr(begin5);
  if (cred.request.empty()) {
    return parse_failure{parse_error::empty_request, begin5};
  }

  return cred;
}

} // namespace awssign::v4::credential_scope
