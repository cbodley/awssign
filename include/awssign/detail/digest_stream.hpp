#pragma once

#include <iterator>

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

} // namespace awssign::detail
