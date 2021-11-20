#include <awssign/v4/verify.hpp>
#include <gtest/gtest.h>

namespace awssign::v4 {

static constexpr auto access_key_id = "AKIDEXAMPLE";
static constexpr auto secret_access_key =
    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

struct capture {
  std::string& value;

  template <typename Iterator> // forward iterator with value_type=char
  void operator()(Iterator begin, Iterator end) {
    value.append(begin, end);
  }
};

struct header_type {
  header_type(std::string_view name, std::string_view value) noexcept
      : name_(name), value_(value)
  {}
  std::string_view name() const { return name_; }
  std::string_view value() const { return value_; }
 private:
  std::string_view name_;
  std::string_view value_;
};

// sha256sum of empty buffer
static constexpr std::string_view empty_payload_hash =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

TEST(verify, unsigned_headers)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", " value1"},
    {"My-Header2", " \"a   b   c\""},
    {"X-Amz-Date", "20150830T123600Z"},
    {"Authorization", ""},
    {"Forwarded", ""},
  };
  constexpr auto signed_headers = "host;my-header1;my-header2;x-amz-date";
  EXPECT_TRUE(verify("SHA256", "20150830T123600Z", "us-east-1", "service",
                     signed_headers, "GET", "/", "",
                     std::begin(headers), std::end(headers),
                     empty_payload_hash, secret_access_key,
                     "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736"));
}

TEST(verify, aws4_testsuite_get_header_key_duplicate)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value2"},
    {"My-Header1", "value2"},
    {"My-Header1", "value1"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  constexpr auto signed_headers = "host;my-header1;x-amz-date";
  EXPECT_TRUE(verify("SHA256", "20150830T123600Z", "us-east-1", "service",
                     signed_headers, "GET", "/", "",
                     std::begin(headers), std::end(headers),
                     empty_payload_hash, secret_access_key,
                     "c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"));
}

TEST(verify, aws4_testsuite_get_header_value_multiline)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value1\n  value2\n     value3"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  constexpr auto signed_headers = "host;my-header1;x-amz-date";
  EXPECT_TRUE(verify("SHA256", "20150830T123600Z", "us-east-1", "service",
                     signed_headers, "GET", "/", "",
                     std::begin(headers), std::end(headers),
                     empty_payload_hash, secret_access_key,
                     "cfd34249e4b1c8d6b91ef74165d41a32e5fab3306300901bb65a51a73575eefd"));
}

TEST(verify, aws4_testsuite_get_header_value_order)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value4"},
    {"My-Header1", "value1"},
    {"My-Header1", "value3"},
    {"My-Header1", "value2"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  constexpr auto signed_headers = "host;my-header1;x-amz-date";
  EXPECT_TRUE(verify("SHA256", "20150830T123600Z", "us-east-1", "service",
                     signed_headers, "GET", "/", "",
                     std::begin(headers), std::end(headers),
                     empty_payload_hash, secret_access_key,
                     "08c7e5a9acfcfeb3ab6b2185e75ce8b1deb5e634ec47601a50643f830c755c01"));
}

TEST(verify, aws4_testsuite_get_header_value_trim)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", " value1"},
    {"My-Header2", " \"a   b   c\""},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  constexpr auto signed_headers = "host;my-header1;my-header2;x-amz-date";
  EXPECT_TRUE(verify("SHA256", "20150830T123600Z", "us-east-1", "service",
                     signed_headers, "GET", "/", "",
                     std::begin(headers), std::end(headers),
                     empty_payload_hash, secret_access_key,
                     "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736"));
}

TEST(verify, aws4_testsuite_get_vanilla_utf8_query)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  constexpr auto signed_headers = "host;x-amz-date";
  EXPECT_TRUE(verify("SHA256", "20150830T123600Z", "us-east-1", "service",
                     signed_headers, "GET", "/", "?%E1%88%B4=bar",
                     std::begin(headers), std::end(headers),
                     empty_payload_hash, secret_access_key,
                     "2cdec8eed098649ff3a119c94853b13c643bcf08f8b0a1d91e12c9027818dd04"));
}

} // namespace awssign::v4
