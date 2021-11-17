#pragma once

#include <iterator>

namespace awssign::detail {

// a Writer whose output is a hash algorithm
template <typename Digest>
class digest_writer {
  Digest& digest;
 public:
  explicit digest_writer(Digest& digest) noexcept : digest(digest) {}

  void operator()(const char* begin, const char* end) {
    digest.update(begin, std::distance(begin, end));
  }
};

} // namespace awssign::detail
