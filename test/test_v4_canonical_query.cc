#include <awssign/v4/detail/canonical_query.hpp>
#include <gtest/gtest.h>

namespace awssign::v4 {

struct capture {
  std::string& value;

  template <typename Iterator> // forward iterator with value_type=char
  void operator()(Iterator begin, Iterator end) {
    value.append(begin, end);
  }
};

std::string canonicalize(std::string_view name)
{
  std::string result;
  detail::canonical_query(name.begin(), name.end(), capture{result});
  return result;
}

TEST(canonical_query, equal_in_value)
{
  // '=' gets double-encoded, '!' gets single-encoded
  EXPECT_EQ("name=value%253Dvalue%21", canonicalize("name=value=value!"));
}

TEST(canonical_query, sort_value)
{
  EXPECT_EQ("name=value1&name=value2", canonicalize("name=value2&name=value1"));
}

TEST(canonical_query, sort_encoded_name)
{
  EXPECT_EQ("na%2Ame=value1&na%2Ame=value2",
            canonicalize("na*me=value1&na%2Ame=value2"));
}

TEST(canonical_query, sort_name_spaces)
{
  EXPECT_EQ("na%20me=value1&na%20me=value2", canonicalize("na me=value2&na+me=value1"));
}

TEST(canonical_query, aws4_testsuite_vanilla_empty_query_key)
{
  EXPECT_EQ("Param1=value1", canonicalize("Param1=value1"));
}

TEST(canonical_query, aws4_testsuite_vanilla_query)
{
  EXPECT_EQ("", canonicalize(""));
}

TEST(canonical_query, aws4_testsuite_vanilla_query_order_key_case)
{
  EXPECT_EQ("Param1=value1&Param2=value2", canonicalize("Param2=value2&Param1=value1"));
}

TEST(canonical_query, aws4_testsuite_vanilla_query_unreserved)
{
  EXPECT_EQ("-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
            "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            canonicalize("-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
                         "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"));
}

TEST(canonical_query, aws4_testsuite_vanilla_utf8_query)
{
  EXPECT_EQ("%E1%88%B4=bar", canonicalize("ሴ=bar"));
}

} // namespace awssign::v4
