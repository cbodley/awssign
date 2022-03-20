#include <awssign/v4/authorization_header.hpp>
#include <gtest/gtest.h>

namespace awssign::v4 {

namespace credential_scope {

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

static value_type make_value(std::string_view access,
                             std::string_view date,
                             std::string_view region,
                             std::string_view service,
                             std::string_view request)
{
  return {access, date, region, service, request};
}

} // namespace credential_scope

namespace authorization_header {

static std::ostream& operator<<(std::ostream& out, const value_type& rhs)
{
  return out << "{algorithm=" << rhs.algorithm
      << ", credential=" << rhs.credential
      << ", signed_headers=" << rhs.signed_headers
      << ", signature=" << rhs.signature << '}';
}
static bool operator==(const value_type& lhs, const value_type& rhs)
{
  return lhs.algorithm == rhs.algorithm
      && lhs.credential == rhs.credential
      && lhs.signed_headers == rhs.signed_headers
      && lhs.signature == rhs.signature;
}
static bool operator!=(const value_type& lhs, const value_type& rhs)
{
  return !(lhs == rhs);
}

static std::ostream& operator<<(std::ostream& out, const parse_error& rhs)
{
  switch (rhs) {
    case parse_error::no_space_after_algorithm:
      return out << "no_space_after_algorithm";
    case parse_error::empty_algorithm:
      return out << "empty_algorithm";
    case parse_error::no_credential:
      return out << "no_credential";
    case parse_error::no_comma_after_credential:
      return out << "no_comma_after_credential";
    case parse_error::bad_credential:
      return out << "bad_credential";
    case parse_error::no_signed_headers:
      return out << "no_signed_headers";
    case parse_error::no_comma_after_signed_headers:
      return out << "no_comma_after_signed_headers";
    case parse_error::no_signature:
      return out << "no_signature";
    case parse_error::empty_signature:
      return out << "empty_signature";
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
static value_type make_value(std::string_view algorithm,
                             credential_scope::value_type credential,
                             std::string_view signed_headers,
                             std::string_view signature)
{
  return {algorithm, credential, signed_headers, signature};
}

TEST(authorization_header, parse)
{
  EXPECT_EQ(make_failure(parse_error::no_space_after_algorithm, 0),
            parse(""));
  EXPECT_EQ(make_failure(parse_error::no_space_after_algorithm, 0),
            parse("AWS4-HMAC-SHA256"));

  EXPECT_EQ(make_failure(parse_error::no_credential, 16),
            parse("AWS4-HMAC-SHA256 "));
  EXPECT_EQ(make_failure(parse_error::no_credential, 16),
            parse("AWS4-HMAC-SHA256\t"));
  EXPECT_EQ(make_failure(parse_error::no_credential, 16),
            parse("AWS4-HMAC-SHA256\n"));
  EXPECT_EQ(make_failure(parse_error::no_credential, 16),
            parse("AWS4-HMAC-SHA256  "));
  EXPECT_EQ(make_failure(parse_error::no_comma_after_credential, 28),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS"));
  EXPECT_EQ(make_failure(parse_error::no_comma_after_credential, 28),
            parse("AWS4-HMAC-SHA256\nCredential=ACCESS"));
  EXPECT_EQ(make_failure(parse_error::no_comma_after_credential, 29),
            parse("AWS4-HMAC-SHA256  Credential=ACCESS"));

  EXPECT_EQ(make_failure(parse_error::bad_credential, 28),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS,"));
  EXPECT_EQ(make_failure(parse_error::bad_credential, 35),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524,"));
  EXPECT_EQ(make_failure(parse_error::bad_credential, 44),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1,"));
  EXPECT_EQ(make_failure(parse_error::bad_credential, 54),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3,"));
  EXPECT_EQ(make_failure(parse_error::bad_credential, 28),
            parse("AWS4-HMAC-SHA256 Credential=/20130524/us-east-1/s3/aws4_request,"));
  EXPECT_EQ(make_failure(parse_error::bad_credential, 35),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS//us-east-1/s3/aws4_request,"));
  EXPECT_EQ(make_failure(parse_error::bad_credential, 44),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524//s3/aws4_request,"));
  EXPECT_EQ(make_failure(parse_error::bad_credential, 54),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1//aws4_request,"));
  EXPECT_EQ(make_failure(parse_error::bad_credential, 57),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/,"));

  EXPECT_EQ(make_failure(parse_error::no_signed_headers, 70),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request,"));
  EXPECT_EQ(make_failure(parse_error::no_signed_headers, 70),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request, "));
  EXPECT_EQ(make_failure(parse_error::no_signed_headers, 70),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request,\t"));
  EXPECT_EQ(make_failure(parse_error::no_signed_headers, 70),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request,\n"));
  EXPECT_EQ(make_failure(parse_error::no_signed_headers, 70),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request,  "));

  EXPECT_EQ(make_failure(parse_error::no_comma_after_signed_headers, 85),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date"));

  EXPECT_EQ(make_failure(parse_error::no_signature, 107),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date,"));
  EXPECT_EQ(make_failure(parse_error::no_signature, 107),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, "));
  EXPECT_EQ(make_failure(parse_error::no_signature, 107),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date,\t"));
  EXPECT_EQ(make_failure(parse_error::no_signature, 107),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date,\n"));
  EXPECT_EQ(make_failure(parse_error::no_signature, 107),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date,  "));

  EXPECT_EQ(make_failure(parse_error::empty_signature, 118),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature="));
  EXPECT_EQ(make_failure(parse_error::empty_signature, 118),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date,\nSignature="));
  EXPECT_EQ(make_failure(parse_error::empty_signature, 119),
            parse("AWS4-HMAC-SHA256 Credential=ACCESS/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date,  Signature="));

  auto cred = credential_scope::make_value("ACCESS", "20130524",
                                           "us-east-1", "s3", "aws4_request");
  EXPECT_EQ(make_value("AWS4-HMAC-SHA256", cred, "host;range;x-amz-date",
                       "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"),
            parse("AWS4-HMAC-SHA256 \
Credential=ACCESS/20130524/us-east-1/s3/aws4_request, \
SignedHeaders=host;range;x-amz-date, \
Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"));
}

} // namespace authorization_header

} // namespace awssign::v4
