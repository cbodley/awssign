#pragma once

#include <iterator>

namespace awssign::detail {

// a Writer whose output is a hash algorithm
template <typename Digest>
struct digest_writer {
  Digest& digest;

  void operator()(const char* begin, const char* end) {
    digest.update(begin, std::distance(begin, end));
  }
};

} // namespace awssign::detail
