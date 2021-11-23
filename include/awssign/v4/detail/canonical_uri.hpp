#pragma once

#include <algorithm>
#include <cctype>
#include <awssign/detail/write.hpp>
#include <awssign/detail/percent_encode.hpp>
#include <awssign/detail/transform.hpp>

namespace awssign::v4::detail {

using awssign::detail::write;
using awssign::detail::need_percent_encode;
using awssign::detail::percent_encode_twice;
using awssign::detail::transform_if;

inline bool is_slash(char c) { return c == '/'; }

template <typename Visitor>
void visit_path_segments(const char* begin, const char* end, Visitor&& visitor)
{
  auto i = std::find_if_not(begin, end, is_slash);
  for (;;) {
    auto next = std::find_if(i, end, is_slash);
    if (next != i) {
      visitor(i, next);
    }
    if (next == end) {
      break;
    }
    i = std::find_if_not(next, end, is_slash);
  }
}

inline std::size_t max_segment_stack_size(const char* begin, const char* end)
{
  std::size_t count = 0;
  std::size_t max_count = 0;
  auto visitor = [&count, &max_count] (const char* begin, const char* end) {
    switch (std::distance(begin, end)) {
      case 0: // empty
        break;
      case 1:
        if (*begin != '.') {
          ++count;
          max_count = std::max(count, max_count);
        }
        break;
      case 2:
        if (*begin != '.' || *std::next(begin) != '.') {
          ++count;
          max_count = std::max(count, max_count);
        } else if (count) { // ".." pops the last segment, if there was one
          --count;
        }
        break;
      default:
        ++count;
        max_count = std::max(count, max_count);
        break;
    }
  };
  visit_path_segments(begin, end, visitor);
  return max_count;
}

template <typename SegmentIterator> // bidirectional segment iterator
SegmentIterator build_segment_stack(const char* in0, const char* inN,
                                    SegmentIterator out0, SegmentIterator outN)
{
  SegmentIterator pos = out0;
  auto visitor = [&] (const char* begin, const char* end) {
    switch (std::distance(begin, end)) {
      case 0: // empty
        break;
      case 1:
        if (*begin != '.') {
          pos->begin = begin;
          pos->end = end;
          ++pos;
        }
        break;
      case 2:
        if (*begin != '.' || *std::next(begin) != '.') {
          pos->begin = begin;
          pos->end = end;
          ++pos;
        } else if (pos != out0) {
          --pos;
        }
        break;
      default:
        pos->begin = begin;
        pos->end = end;
        ++pos;
        break;
    }
  };
  visit_path_segments(in0, inN, visitor);
  return pos;
}

template <typename OutputStream>
void write_canonical_path_segment(const char* begin, const char* end,
                                  OutputStream&& out)
{
  constexpr auto double_escape = [] (char c, OutputStream& out) {
    return percent_encode_twice(c, out);
  };
  transform_if(begin, end, need_percent_encode, double_escape, out);
}

/// output an absolute uri path in canonical form, where the path is normalized
/// and each path segment is double-percent-encoded
template <typename OutputStream>
void write_canonical_uri(const char* begin, const char* end,
                         OutputStream&& out)
{
  const auto count = max_segment_stack_size(begin, end);
  // allocate array for segment stack
  struct path_segment {
    const char* begin;
    const char* end;
  };
  const auto segments = static_cast<path_segment*>(
      ::alloca(count * sizeof(path_segment)));
  auto segments_end = segments + count;
  // build segment stack
  segments_end = build_segment_stack(begin, end, segments, segments_end);
  if (segments == segments_end) {
    write('/', out);
    return;
  }
  // write out each segment with double percent encoding
  for (auto segment = segments; segment != segments_end; ++segment) {
    write('/', out);
    write_canonical_path_segment(segment->begin, segment->end, out);
  }
  if (*std::prev(end) == '/') {
    write('/', out); // input has a trailing slash
  }
}

} // namespace awssign::v4::detail
