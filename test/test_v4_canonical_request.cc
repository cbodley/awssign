#include <awssign/v4/detail/canonical_request.hpp>
#include <gtest/gtest.h>

namespace awssign::v4 {

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

TEST(canonical_request, aws4_testsuite_get_header_key_duplicate)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value2"},
    {"My-Header1", "value2"},
    {"My-Header1", "value1"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  detail::canonical_header canonical[sizeof(headers)];
  const auto canonical_end = detail::sorted_canonical_headers(
      std::begin(headers), std::end(headers), canonical);
  std::string result;
  detail::write_canonical_request("iam", "GET", "/", "",
                                  canonical, canonical_end,
                                  empty_payload_hash, capture{result});
  EXPECT_EQ(result, R"(GET
/

host:example.amazonaws.com
my-header1:value2,value2,value1
x-amz-date:20150830T123600Z

host;my-header1;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)");
}

TEST(canonical_request, aws4_testsuite_get_header_value_multiline)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value1\n  value2\n     value3"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  detail::canonical_header canonical[sizeof(headers)];
  const auto canonical_end = detail::sorted_canonical_headers(
      std::begin(headers), std::end(headers), canonical);
  std::string result;
  detail::write_canonical_request("iam", "GET", "/", "",
                                  canonical, canonical_end,
                                  empty_payload_hash, capture{result});
  EXPECT_EQ(result, R"(GET
/

host:example.amazonaws.com
my-header1:value1 value2 value3
x-amz-date:20150830T123600Z

host;my-header1;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)");
}

TEST(canonical_request, aws4_testsuite_get_header_value_order)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value4"},
    {"My-Header1", "value1"},
    {"My-Header1", "value3"},
    {"My-Header1", "value2"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  detail::canonical_header canonical[sizeof(headers)];
  const auto canonical_end = detail::sorted_canonical_headers(
      std::begin(headers), std::end(headers), canonical);
  std::string result;
  detail::write_canonical_request("iam", "GET", "/", "",
                                  canonical, canonical_end,
                                  empty_payload_hash, capture{result});
  EXPECT_EQ(result, R"(GET
/

host:example.amazonaws.com
my-header1:value4,value1,value3,value2
x-amz-date:20150830T123600Z

host;my-header1;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)");
}

TEST(canonical_request, aws4_testsuite_get_header_value_trim)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", " value1"},
    {"My-Header2", " \"a   b   c\""},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  detail::canonical_header canonical[sizeof(headers)];
  const auto canonical_end = detail::sorted_canonical_headers(
      std::begin(headers), std::end(headers), canonical);
  std::string result;
  detail::write_canonical_request("iam", "GET", "/", "",
                                  canonical, canonical_end,
                                  empty_payload_hash, capture{result});
  EXPECT_EQ(result, R"(GET
/

host:example.amazonaws.com
my-header1:value1
my-header2:"a b c"
x-amz-date:20150830T123600Z

host;my-header1;my-header2;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)");
}

} // namespace awssign::v4
