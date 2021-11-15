#pragma once

#include <awssign/v4/detail/canonical_uri.hpp>

namespace awssign::v4 {

/// output an absolute uri path in canonical form, where the path is normalized
/// and each path segment is double-percent-encoded
template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t canonical_uri(Iterator begin, Iterator end, Writer&& out)
{
  const auto count = detail::max_segment_stack_size(begin, end);
  // allocate array for segment stack
  struct path_segment {
    Iterator begin;
    Iterator end;
  };
  const auto segments = static_cast<path_segment*>(
      ::alloca(count * sizeof(path_segment)));
  auto segments_end = segments + count;
  // build segment stack
  segments_end = detail::build_segment_stack(begin, end, segments, segments_end);

  // write out each segment with double percent encoding
  std::size_t bytes = 0;
  for (auto segment = segments; segment != segments_end; ++segment) {
    bytes += detail::emit('/', out);
    bytes += detail::canonical_path_segment(segment->begin,
                                            segment->end, out);
  }
  if (!bytes || // didn't write the initial slash yet
      *std::prev(end) == '/') { // input has a trailing slash
    bytes += detail::emit('/', out);
  }
  return bytes;
}

} // namespace awssign::v4
