#include <awssign/v4/sign.hpp>
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

TEST(signing_key, example)
{
  // generate the signing key
  unsigned char signing_key[detail::hmac::max_size] = {};
  const int signing_key_size = detail::build_signing_key(
      "SHA256", secret_access_key,
      "20150830", "us-east-1", "iam",
      signing_key);

  std::string result;
  detail::hex_encode(signing_key, signing_key + signing_key_size,
                     capture{result});
  EXPECT_EQ(result, "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");
}

TEST(sign, aws4_testsuite_get_header_key_duplicate)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value2"},
    {"My-Header1", "value2"},
    {"My-Header1", "value1"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  std::string result;
  sign("SHA256", access_key_id, secret_access_key, "GET", "/", "",
       std::begin(headers), std::end(headers), empty_payload_hash,
       "20150830T123600Z", "us-east-1", "service", capture{result});
  EXPECT_EQ(result, "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;my-header1;x-amz-date, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea");
}

TEST(sign, aws4_testsuite_get_header_value_multiline)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value1\n  value2\n     value3"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  std::string result;
  sign("SHA256", access_key_id, secret_access_key, "GET", "/", "",
       std::begin(headers), std::end(headers), empty_payload_hash,
       "20150830T123600Z", "us-east-1", "service", capture{result});
  EXPECT_EQ(result, "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;my-header1;x-amz-date, \
Signature=cfd34249e4b1c8d6b91ef74165d41a32e5fab3306300901bb65a51a73575eefd");
}

TEST(sign, aws4_testsuite_get_header_value_order)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value4"},
    {"My-Header1", "value1"},
    {"My-Header1", "value3"},
    {"My-Header1", "value2"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  std::string result;
  sign("SHA256", access_key_id, secret_access_key, "GET", "/", "",
       std::begin(headers), std::end(headers), empty_payload_hash,
       "20150830T123600Z", "us-east-1", "service", capture{result});
  EXPECT_EQ(result, "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;my-header1;x-amz-date, \
Signature=08c7e5a9acfcfeb3ab6b2185e75ce8b1deb5e634ec47601a50643f830c755c01");
}

TEST(sign, aws4_testsuite_get_header_value_trim)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", " value1"},
    {"My-Header2", " \"a   b   c\""},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  std::string result;
  sign("SHA256", access_key_id, secret_access_key, "GET", "/", "",
       std::begin(headers), std::end(headers), empty_payload_hash,
       "20150830T123600Z", "us-east-1", "service", capture{result});
  EXPECT_EQ(result, "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;my-header1;my-header2;x-amz-date, \
Signature=acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736");
}

} // namespace awssign::v4
