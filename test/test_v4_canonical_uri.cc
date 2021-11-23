#include <awssign/v4/detail/canonical_uri.hpp>
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
  detail::write_canonical_uri(name.begin(), name.end(), capture{result});
  return result;
}

TEST(canonical_uri, empty)
{
  EXPECT_EQ("/", canonicalize(""));
  EXPECT_EQ("/", canonicalize("/"));
}

TEST(canonical_uri, aws4_testsuite_normalize_slash)
{
  EXPECT_EQ("/", canonicalize("//"));
}

TEST(canonical_uri, aws4_testsuite_normalize_slash_pointless_dot)
{
  EXPECT_EQ("/example", canonicalize("/./example"));
}

TEST(canonical_uri, aws4_testsuite_normalize_slash_dot_slash)
{
  EXPECT_EQ("/", canonicalize("/./"));
}

TEST(canonical_uri, aws4_testsuite_normalize_space)
{
  EXPECT_EQ("/example%2520space/", canonicalize("/example space/"));
}

TEST(canonical_uri, aws4_testsuite_normalize_slashes)
{
  EXPECT_EQ("/example/", canonicalize("//example//"));
}

TEST(canonical_uri, aws4_testsuite_normalize_relative)
{
  EXPECT_EQ("/", canonicalize("/example/.."));
}

TEST(canonical_uri, aws4_testsuite_normalize_relative_relative)
{
  EXPECT_EQ("/", canonicalize("/example1/example2/../.."));
}

TEST(canonical_uri, unreserved)
{
  // test that none of these characters get encoded
  EXPECT_EQ("/abcdefghijklmnopqrstuvwxyz", canonicalize("/abcdefghijklmnopqrstuvwxyz"));
  EXPECT_EQ("/ABCDEFGHIJKLMNOPQRSTUVWXYZ", canonicalize("/ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
  EXPECT_EQ("/0123456789", canonicalize("/0123456789"));
  EXPECT_EQ("/_-~.", canonicalize("/_-~."));
}

TEST(canonical_uri, reserved)
{
  EXPECT_EQ("/%2500", canonicalize({"/\x00", 2}));
  EXPECT_EQ("/%250A", canonicalize("/\x0a"));
  EXPECT_EQ("/%2520", canonicalize("/\x20"));
  EXPECT_EQ("/%252B", canonicalize("/\x2b"));
  EXPECT_EQ("/%257F", canonicalize("/\x7f"));
  EXPECT_EQ("/%2580", canonicalize("/\x80"));
  EXPECT_EQ("/%25FF", canonicalize("/\xff"));
}

TEST(canonical_uri, space)
{
  EXPECT_EQ("/path%2520with%252Bspaces%2520", canonicalize("/path with+spaces "));
}

TEST(canonical_uri, utf8)
{
  EXPECT_EQ("/%25E1%2588%25B4", canonicalize("/ሴ"));
}

} // namespace awssign::v4
