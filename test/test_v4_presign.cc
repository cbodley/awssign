#include <awssign/v4/presign.hpp>
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
  std::string_view name_string() const { return name_; }
  std::string_view value() const { return value_; }
 private:
  std::string_view name_;
  std::string_view value_;
};

// sha256sum of empty buffer
static constexpr std::string_view unsigned_payload = "UNSIGNED-PAYLOAD";
static constexpr std::string_view empty_payload_hash =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
TEST(presign, s3_example)
{
  const auto example_access = "AKIAIOSFODNN7EXAMPLE";
  const auto example_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

  const header_type headers[] = {
    {"Host", "examplebucket.s3.amazonaws.com"},
  };
  char query[512];
  char* query_capacity = std::end(query);
  char* query_end = presign("SHA256", example_access, example_secret,
                            "us-east-1", "s3", "20130524T000000Z",
                            "86400", "GET", "/test.txt", std::begin(headers),
                            std::end(headers), unsigned_payload,
                            query, query, query_capacity);
  EXPECT_EQ(std::string_view(query, std::distance(query, query_end)),
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256\
&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
&X-Amz-Date=20130524T000000Z\
&X-Amz-Expires=86400\
&X-Amz-SignedHeaders=host\
&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404");
}

TEST(presign, aws4_testsuite_get_header_key_duplicate)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value2"},
    {"My-Header1", "value2"},
    {"My-Header1", "value1"},
  };
  char query[512];
  char* query_capacity = std::end(query);
  char* query_end = presign("SHA256", access_key_id, secret_access_key,
                            "us-east-1", "service", "20150830T123600Z",
                            "3600", "GET", "/", std::begin(headers),
                            std::end(headers), empty_payload_hash,
                            query, query, query_capacity);
  EXPECT_EQ(std::string_view(query, std::distance(query, query_end)),
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256\
&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice%2Faws4_request\
&X-Amz-Date=20150830T123600Z\
&X-Amz-Expires=3600\
&X-Amz-SignedHeaders=host%3Bmy-header1\
&X-Amz-Signature=3349ee0b81b4b589da0ff28a395c3591e04de515651dd74f298fa992d1507a97");
}

TEST(presign, aws4_testsuite_get_header_value_multiline)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value1\n  value2\n     value3"},
  };
  char query[512];
  char* query_capacity = std::end(query);
  char* query_end = presign("SHA256", access_key_id, secret_access_key,
                            "us-east-1", "service", "20150830T123600Z",
                            "3600", "GET", "/", std::begin(headers),
                            std::end(headers), empty_payload_hash,
                            query, query, query_capacity);
  EXPECT_EQ(std::string_view(query, std::distance(query, query_end)),
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256\
&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice%2Faws4_request\
&X-Amz-Date=20150830T123600Z\
&X-Amz-Expires=3600\
&X-Amz-SignedHeaders=host%3Bmy-header1\
&X-Amz-Signature=e6f5def831211aca02987a44b96826706278c7bc078112ae0263659c5b2f2d56");
}

TEST(presign, aws4_testsuite_get_header_value_order)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value4"},
    {"My-Header1", "value1"},
    {"My-Header1", "value3"},
    {"My-Header1", "value2"},
  };
  char query[512];
  char* query_capacity = std::end(query);
  char* query_end = presign("SHA256", access_key_id, secret_access_key,
                            "us-east-1", "service", "20150830T123600Z",
                            "3600", "GET", "/", std::begin(headers),
                            std::end(headers), empty_payload_hash,
                            query, query, query_capacity);
  EXPECT_EQ(std::string_view(query, std::distance(query, query_end)),
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256\
&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice%2Faws4_request\
&X-Amz-Date=20150830T123600Z\
&X-Amz-Expires=3600\
&X-Amz-SignedHeaders=host%3Bmy-header1\
&X-Amz-Signature=313720e71ca6202fdcfa9b20f88de01a4eb0638a83c833b1c184359a4eda864e");
}

TEST(presign, aws4_testsuite_get_header_value_trim)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", " value1"},
    {"My-Header2", " \"a   b   c\""},
  };
  char query[512];
  char* query_capacity = std::end(query);
  char* query_end = presign("SHA256", access_key_id, secret_access_key,
                            "us-east-1", "service", "20150830T123600Z",
                            "3600", "GET", "/", std::begin(headers),
                            std::end(headers), empty_payload_hash,
                            query, query, query_capacity);
  EXPECT_EQ(std::string_view(query, std::distance(query, query_end)),
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256\
&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice%2Faws4_request\
&X-Amz-Date=20150830T123600Z\
&X-Amz-Expires=3600\
&X-Amz-SignedHeaders=host%3Bmy-header1%3Bmy-header2\
&X-Amz-Signature=e7bb0fd515e125e1aec2ecc4c0c17484fb06f6846b927c35e46005dd3df3acd4");
}

} // namespace awssign::v4
