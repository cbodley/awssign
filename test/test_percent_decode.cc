#include <awssign/detail/percent_decoded_stream.hpp>
#include <gtest/gtest.h>

namespace awssign {

struct capture {
  std::string& value;

  template <typename Iterator> // forward iterator with value_type=char
  void operator()(Iterator begin, Iterator end) {
    value.append(begin, end);
  }
};

template <typename ...Args>
std::string decode(Args&& ...args)
{
  std::string result;
  auto writer = capture{result};
  auto decoder = detail::percent_decoded(writer);
  (detail::emit(std::begin(args), std::end(args) - 1, decoder), ...);
  return result;
}

TEST(percent_decoder, unreserved)
{
  EXPECT_EQ("-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=",
            decode("-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="));
  EXPECT_EQ("-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=",
            decode("-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz="));
}

TEST(percent_decoder, escape)
{
  EXPECT_EQ(" %[", decode("%20%25%5B"));
  EXPECT_EQ(" %[", decode("%20", "%25%5B"));
  EXPECT_EQ(" %[", decode("%20%", "25%5B"));
  EXPECT_EQ(" %[", decode("%20%2", "5%5B"));
}

TEST(percent_decoder, invalid_character)
{
  EXPECT_EQ(std::string_view("\0", 1), decode("%!0"));
  EXPECT_EQ(std::string_view("\0", 1), decode("%0!"));
}

TEST(percent_decoder, invalid_eof)
{
  EXPECT_EQ("", decode("%"));
  EXPECT_EQ("", decode("%0"));
}

} // namespace awssign
