#include <awssign/v4/credential_scope.hpp>
#include <gtest/gtest.h>

namespace awssign::v4::credential_scope {

static std::ostream& operator<<(std::ostream& out, const value_type& rhs)
{
  return out << "{access=" << rhs.access
      << ", date=" << rhs.date
      << ", region=" << rhs.region
      << ", service=" << rhs.service
      << ", request=" << rhs.request << '}';
}
static bool operator==(const value_type& lhs, const value_type& rhs)
{
  return lhs.access == rhs.access
      && lhs.date == rhs.date
      && lhs.region == rhs.region
      && lhs.service == rhs.service
      && lhs.request == rhs.request;
}
static bool operator!=(const value_type& lhs, const value_type& rhs)
{
  return !(lhs == rhs);
}

static std::ostream& operator<<(std::ostream& out, const parse_error& rhs)
{
  switch (rhs) {
    case parse_error::no_slash_after_access_key_id:
      return out << "no_slash_after_access_key_id";
    case parse_error::empty_access_key_id:
      return out << "empty_access_key_id";
    case parse_error::no_slash_after_date:
      return out << "no_slash_after_date";
    case parse_error::empty_date:
      return out << "empty_date";
    case parse_error::no_slash_after_region:
      return out << "no_slash_after_region";
    case parse_error::empty_region:
      return out << "empty_region";
    case parse_error::no_slash_after_service:
      return out << "no_slash_after_service";
    case parse_error::empty_service:
      return out << "empty_service";
    case parse_error::empty_request:
      return out << "empty_request";
  }
};

static std::ostream& operator<<(std::ostream& out, const parse_failure& rhs)
{
  return out << "{error=" << rhs.error << ", position=" << rhs.position << '}';
}
static bool operator==(const parse_failure& lhs, const parse_failure& rhs)
{
  return lhs.error == rhs.error && lhs.position == rhs.position;
}
static bool operator!=(const parse_failure& lhs, const parse_failure& rhs)
{
  return !(lhs == rhs);
}

static std::ostream& operator<<(std::ostream& out, const parse_result& rhs)
{
  if (rhs) {
    return out << "{value=" << rhs.value() << '}';
  } else {
    return out << "{failure=" << rhs.failure() << '}';
  }
}
static bool operator==(const parse_result& lhs, const parse_result& rhs)
{
  if (lhs) {
    return rhs && lhs.value() == rhs.value();
  } else {
    return !rhs && lhs.failure() == rhs.failure();
  }
}
static bool operator!=(const parse_result& lhs, const parse_result& rhs)
{
  return !(lhs == rhs);
}

static parse_result make_failure(parse_error error, std::size_t position)
{
  return parse_failure{error, position};
}
static value_type make_value(std::string_view access, std::string_view date,
                             std::string_view region, std::string_view service,
                             std::string_view request)
{
  return {access, date, region, service, request};
}

TEST(credential_scope, parse)
{
  EXPECT_EQ(make_failure(parse_error::no_slash_after_access_key_id, 0),
            parse("ACCESS"));
  EXPECT_EQ(make_failure(parse_error::no_slash_after_date, 7),
            parse("ACCESS/20130524"));
  EXPECT_EQ(make_failure(parse_error::no_slash_after_region, 16),
            parse("ACCESS/20130524/us-east-1"));
  EXPECT_EQ(make_failure(parse_error::no_slash_after_service, 26),
            parse("ACCESS/20130524/us-east-1/s3"));
  EXPECT_EQ(make_failure(parse_error::empty_access_key_id, 0),
            parse("/20130524/us-east-1/s3/aws4_request"));
  EXPECT_EQ(make_failure(parse_error::empty_date, 7),
            parse("ACCESS//us-east-1/s3/aws4_request"));
  EXPECT_EQ(make_failure(parse_error::empty_region, 16),
            parse("ACCESS/20130524//s3/aws4_request"));
  EXPECT_EQ(make_failure(parse_error::empty_service, 26),
            parse("ACCESS/20130524/us-east-1//aws4_request"));
  EXPECT_EQ(make_failure(parse_error::empty_request, 29),
            parse("ACCESS/20130524/us-east-1/s3/"));

  EXPECT_EQ(make_value("ACCESS", "20130524", "us-east-1", "s3", "aws4_request"),
            parse("ACCESS/20130524/us-east-1/s3/aws4_request"));
}

} // namespace awssign::v4::credential_scope
