#pragma once

#include <iterator>
#include <awssign/detail/buffered_stream.hpp>

namespace awssign::detail {

// a stream whose output is a hash algorithm
template <typename Digest>
class digest_stream {
  Digest& digest;
 public:
  explicit digest_stream(Digest& digest) noexcept : digest(digest) {}

  void operator()(const char* begin, const char* end) {
    digest.update(begin, std::distance(begin, end));
  }
};

// create a buffered digest stream that buffers up to 256 bytes before calling
// into the digest. hash performance on these buffers is much better than with
// many tiny buffers
template <typename Digest>
auto buffered_digest_stream(Digest& digest)
{
  return buffered<256>(digest_stream{digest});
}

} // namespace awssign::detail
