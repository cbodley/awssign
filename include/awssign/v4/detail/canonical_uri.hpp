#pragma once

#include <algorithm>
#include <cctype>
#include <awssign/detail/emit.hpp>
#include <awssign/detail/percent_encode.hpp>
#include <awssign/detail/transform.hpp>

namespace awssign::v4::detail {

using awssign::detail::emit;
using awssign::detail::need_percent_encode;
using awssign::detail::percent_encode_twice;
using awssign::detail::transform_if;

inline bool is_slash(char c) { return c == '/'; }

template <typename Iterator, // forward iterator with value_type=char
          typename Visitor> // void(Iterator, Iterator)
void visit_path_segments(Iterator begin, Iterator end, Visitor&& visitor)
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

template <typename Iterator>
std::size_t max_segment_stack_size(Iterator begin, Iterator end)
{
  std::size_t count = 0;
  std::size_t max_count = 0;
  auto visitor = [&count, &max_count] (Iterator begin, Iterator end) {
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

template <typename InputIterator, // forward iterator with value_type=char
          typename OutputIterator> // bidirectional segment iterator
OutputIterator build_segment_stack(InputIterator in0, InputIterator inN,
                                   OutputIterator out0, OutputIterator outN)
{
  OutputIterator pos = out0;
  auto visitor = [&] (InputIterator begin, InputIterator end) {
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

template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t canonical_path_segment(Iterator begin, Iterator end, Writer&& out)
{
  constexpr auto double_escape = [] (char c, Writer& out) {
    return percent_encode_twice(c, out);
  };
  return transform_if(begin, end, need_percent_encode, double_escape, out);
}

/// output an absolute uri path in canonical form, where the path is normalized
/// and each path segment is double-percent-encoded
template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t canonical_uri(Iterator begin, Iterator end, Writer&& out)
{
  const auto count = max_segment_stack_size(begin, end);
  // allocate array for segment stack
  struct path_segment {
    Iterator begin;
    Iterator end;
  };
  const auto segments = static_cast<path_segment*>(
      ::alloca(count * sizeof(path_segment)));
  auto segments_end = segments + count;
  // build segment stack
  segments_end = build_segment_stack(begin, end, segments, segments_end);

  // write out each segment with double percent encoding
  std::size_t bytes = 0;
  for (auto segment = segments; segment != segments_end; ++segment) {
    bytes += emit('/', out);
    bytes += canonical_path_segment(segment->begin, segment->end, out);
  }
  if (!bytes || // didn't write the initial slash yet
      *std::prev(end) == '/') { // input has a trailing slash
    bytes += emit('/', out);
  }
  return bytes;
}

} // namespace awssign::v4::detail
