#include <awssign/v4/string_to_sign.hpp>
#include <gtest/gtest.h>

namespace awssign {

struct capture {
  std::string& value;

  template <typename Iterator> // forward iterator with value_type=char
  void operator()(Iterator begin, Iterator end) {
    value.append(begin, end);
  }
};

TEST(string_to_sign, basic)
{
  std::string result;
  v4::string_to_sign("SHA256", "20130524T000000Z", "us-east-1", "s3",
                     "abcdefg", capture{result});
  EXPECT_EQ(result, R"(AWS4-HMAC-SHA256
20130524T000000Z
20130524/us-east-1/s3/aws4_request
abcdefg)");
}

TEST(string_to_sign, empty_timestamp)
{
  std::string result;
  v4::string_to_sign("SHA256", "", "us-east-1", "s3",
                     "abcdefg", capture{result});
  EXPECT_EQ(result, R"(AWS4-HMAC-SHA256

/us-east-1/s3/aws4_request
abcdefg)");
}

} // namespace awssign
