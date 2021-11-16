#include <awssign/v4/detail/s3_canonical_uri.hpp>
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
  detail::s3_canonical_uri(name.begin(), name.end(), capture{result});
  return result;
}

TEST(s3_canonical_uri, empty)
{
  EXPECT_EQ("/", canonicalize(""));
  EXPECT_EQ("/", canonicalize("/"));
}

TEST(s3_canonical_uri, normalize)
{
  // test that paths are not normalized
  EXPECT_EQ("/composite/path", canonicalize("/composite/path"));
  EXPECT_EQ("/composite/../path", canonicalize("/composite/../path"));
  EXPECT_EQ("/composite//..//path", canonicalize("/composite//..//path"));
}

TEST(s3_canonical_uri, unreserved)
{
  // test that none of these characters get encoded
  EXPECT_EQ("/abcdefghijklmnopqrstuvwxyz", canonicalize("/abcdefghijklmnopqrstuvwxyz"));
  EXPECT_EQ("/ABCDEFGHIJKLMNOPQRSTUVWXYZ", canonicalize("/ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
  EXPECT_EQ("/0123456789", canonicalize("/0123456789"));
  EXPECT_EQ("/_-~.", canonicalize("/_-~."));
}

TEST(s3_canonical_uri, reserved)
{
  EXPECT_EQ("/%00", canonicalize({"/\x00", 2}));
  EXPECT_EQ("/%0A", canonicalize("/\x0a"));
  EXPECT_EQ("/%20", canonicalize("/\x20"));
  EXPECT_EQ("/%20", canonicalize("/\x2b")); // '+' encoded as space
  EXPECT_EQ("/%7F", canonicalize("/\x7f"));
  EXPECT_EQ("/%80", canonicalize("/\x80"));
  EXPECT_EQ("/%FF", canonicalize("/\xff"));
}

TEST(s3_canonical_uri, space)
{
  EXPECT_EQ("/path%20with%20spaces%20", canonicalize("/path with+spaces "));
}

TEST(s3_canonical_uri, utf8)
{
  EXPECT_EQ("/%E1%88%B4", canonicalize("/ሴ"));
}

} // namespace awssign::v4
