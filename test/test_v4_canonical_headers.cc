#include <awssign/v4/canonical_headers.hpp>
#include <gtest/gtest.h>

namespace awssign {

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

TEST(canonical_headers, name)
{
  const auto canonical_name = [] (std::string_view name) {
    std::string result;
    v4::detail::canonical_header_name(name.begin(), name.end(), capture{result});
    return result;
  };
  EXPECT_EQ("", canonical_name(""));
  EXPECT_EQ("name", canonical_name("name"));
  EXPECT_EQ("name", canonical_name("NAME"));
}

TEST(canonical_headers, value)
{
  const auto canonical_value = [] (std::string_view value) {
    std::string result;
    v4::detail::canonical_header_value(value.begin(), value.end(), capture{result});
    return result;
  };
  EXPECT_EQ("", canonical_value(""));
  EXPECT_EQ("", canonical_value(" \t "));
  EXPECT_EQ("value", canonical_value("value"));
  EXPECT_EQ("VALUE", canonical_value("VALUE"));
  EXPECT_EQ("value", canonical_value("   value   "));
  EXPECT_EQ("two words", canonical_value("   two words   "));
  EXPECT_EQ("two words", canonical_value("   two  words   "));
  EXPECT_EQ("two words", canonical_value("   two\n  \twords   "));
}

TEST(canonical_headers, empty)
{
  const v4::detail::canonical_header* headers = nullptr;
  std::string result;
  v4::detail::canonical_headers(headers, headers, capture{result});
  EXPECT_EQ("", result);
}

TEST(canonical_headers, header)
{
  const auto header = v4::detail::canonical_header{"Name", " value\t"};
  std::string result;
  v4::detail::canonical_headers(&header, &header + 1, capture{result});
  EXPECT_EQ("name:value\n", result);
}

TEST(canonical_headers, multiple_values)
{
  const header_type headers[] = {
    {"name1", "value1"},
    {"name2", "value2"},
    {"NAME1", "VALUE1"},
  };
  v4::detail::canonical_header canonical[sizeof(headers)];
  const auto canonical_end = v4::detail::sorted_canonical_headers(
      std::begin(headers), std::end(headers), canonical);
  std::string result;
  v4::detail::canonical_headers(canonical, canonical_end, capture{result});
  EXPECT_EQ("name1:value1,VALUE1\nname2:value2\n", result);
}

TEST(canonical_headers, aws_example)
{
  const header_type headers[] = {
    {"Host", "iam.amazonaws.com"},
    {"Content-Type", "application/x-www-form-urlencoded; charset=utf-8"},
    {"My-header1", "    a   b   c  "},
    {"X-Amz-Date", "20150830T123600Z"},
    {"My-Header2", "    \"a   b   c\"  "},
  };
  v4::detail::canonical_header canonical[sizeof(headers)];
  const auto canonical_end = v4::detail::sorted_canonical_headers(
      std::begin(headers), std::end(headers), canonical);
  std::string result;
  v4::detail::canonical_headers(canonical, canonical_end, capture{result});
  EXPECT_EQ("content-type:application/x-www-form-urlencoded; charset=utf-8\n"
            "host:iam.amazonaws.com\n"
            "my-header1:a b c\n"
            "my-header2:\"a b c\"\n"
            "x-amz-date:20150830T123600Z\n", result);
}

TEST(canonical_headers, aws4_testsuite_get_header_key_duplicate)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value2"},
    {"My-Header1", "value2"},
    {"My-Header1", "value1"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  v4::detail::canonical_header canonical[sizeof(headers)];
  const auto canonical_end = v4::detail::sorted_canonical_headers(
      std::begin(headers), std::end(headers), canonical);
  std::string result;
  v4::detail::canonical_headers(canonical, canonical_end, capture{result});
  EXPECT_EQ("host:example.amazonaws.com\n"
            "my-header1:value2,value2,value1\n"
            "x-amz-date:20150830T123600Z\n", result);
}

TEST(canonical_headers, aws4_testsuite_get_header_value_multiline)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value1\n  value2\n     value3"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  v4::detail::canonical_header canonical[sizeof(headers)];
  const auto canonical_end = v4::detail::sorted_canonical_headers(
      std::begin(headers), std::end(headers), canonical);
  std::string result;
  v4::detail::canonical_headers(canonical, canonical_end, capture{result});
  EXPECT_EQ("host:example.amazonaws.com\n"
            "my-header1:value1 value2 value3\n"
            "x-amz-date:20150830T123600Z\n", result);
}

TEST(canonical_headers, aws4_testsuite_get_header_value_order)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", "value4"},
    {"My-Header1", "value1"},
    {"My-Header1", "value3"},
    {"My-Header1", "value2"},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  v4::detail::canonical_header canonical[sizeof(headers)];
  const auto canonical_end = v4::detail::sorted_canonical_headers(
      std::begin(headers), std::end(headers), canonical);
  std::string result;
  v4::detail::canonical_headers(canonical, canonical_end, capture{result});
  EXPECT_EQ("host:example.amazonaws.com\n"
            "my-header1:value4,value1,value3,value2\n"
            "x-amz-date:20150830T123600Z\n", result);
}

TEST(canonical_headers, aws4_testsuite_get_header_value_trim)
{
  const header_type headers[] = {
    {"Host", "example.amazonaws.com"},
    {"My-Header1", " value1"},
    {"My-Header2", " \"a   b   c\""},
    {"X-Amz-Date", "20150830T123600Z"},
  };
  v4::detail::canonical_header canonical[sizeof(headers)];
  const auto canonical_end = v4::detail::sorted_canonical_headers(
      std::begin(headers), std::end(headers), canonical);
  std::string result;
  v4::detail::canonical_headers(canonical, canonical_end, capture{result});
  EXPECT_EQ("host:example.amazonaws.com\n"
            "my-header1:value1\n"
            "my-header2:\"a b c\"\n"
            "x-amz-date:20150830T123600Z\n", result);
}

} // namespace awssign
