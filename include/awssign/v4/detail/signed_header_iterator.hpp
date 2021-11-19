#pragma once

#include <algorithm>
#include <awssign/detail/filtered_iterator.hpp>
#include <awssign/detail/split.hpp>

namespace awssign::v4::detail {

using awssign::detail::filtered_iterator;
using awssign::detail::split;
using awssign::detail::split_iterator;

// a predicate function for canonical headers that returns whether or not the
// header's name is in the set of signed_headers
class is_signed_header {
  split_iterator pos;
  split_iterator end;
 public:
  is_signed_header() = default;

  is_signed_header(split&& signed_headers) noexcept
      : pos(signed_headers.begin()),
        end(signed_headers.end())
  {}

  // requires that headers be passed in lower-case-sorted order
  template <typename Header> // canonical_header
  bool operator()(const Header& h)
  {
    // find the first entry in signed_headers that is not less than h.name
    pos = std::find_if_not(pos, end, [&h] (std::string_view name) {
        return name < h.name;
      });
    return pos != end && *pos == h.name;
  }
};

template <typename Iterator> // forward canonical_header iterator
using signed_header_iterator = filtered_iterator<is_signed_header, Iterator>;

// returns an iterator that wraps the given range, and skips any headers
// whose name is not in the set of signed_headers
template <typename Iterator> // forward canonical_header iterator
auto make_signed_header_iterator(std::string_view signed_headers,
                                 Iterator begin, Iterator end)
  -> signed_header_iterator<Iterator>
{
  return {is_signed_header{split(signed_headers, ';')}, begin, end};
}

} // namespace awssign::v4::detail
