#include <awssign/detail/digest.hpp>
#include <string>
#include <gtest/gtest.h>
#include <awssign/detail/hex_encode.hpp>

namespace awssign {

using detail::digest;
using detail::hmac;

std::string hex_encode(const unsigned char* data, std::size_t size)
{
  std::string result;
  result.reserve(2 * size);
  detail::hex_encode(data, data + size,
      [&result] (const char* begin, const char* end) {
        result.append(begin, end);
      });
  return result;
}

TEST(digest, sha256)
{
  // $ echo -n 'foo' | sha256sum 
  // 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
  constexpr std::string_view expected{
      "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"};

  auto hash = digest{"SHA256"};
  {
    hash.update("foo", 3);
    unsigned char digest[digest::max_size];
    const auto bytes = hash.finish(digest);
    EXPECT_EQ(expected, hex_encode(digest, bytes));
  }
  {
    hash.init();
    hash.update("f", 1);
    hash.update("o", 1);
    hash.update("o", 1);
    unsigned char digest[digest::max_size];
    const auto bytes = hash.finish(digest);
    EXPECT_EQ(expected, hex_encode(digest, bytes));
  }
}

TEST(digest, hmac_sha256)
{
  // $ echo -n 'foo' | sha256hmac --key bar
  // 147933218aaabc0b8b10a2b3a5c34684c8d94341bcf10a4736dc7270f7741851
  const unsigned char key[] = {'b','a','r'};
  constexpr std::string_view expected{
      "147933218aaabc0b8b10a2b3a5c34684c8d94341bcf10a4736dc7270f7741851"};
  auto hash = hmac{"SHA256", key, sizeof(key)};
  {
    hash.update("foo", 3);
    unsigned char digest[digest::max_size];
    const auto bytes = hash.finish(digest);
    EXPECT_EQ(expected, hex_encode(digest, bytes));
  }
  {
    hash.init();
    hash.update("f", 1);
    hash.update("o", 1);
    hash.update("o", 1);
    unsigned char digest[digest::max_size];
    const auto bytes = hash.finish(digest);
    EXPECT_EQ(expected, hex_encode(digest, bytes));
  }
}

} // namespace awssign
