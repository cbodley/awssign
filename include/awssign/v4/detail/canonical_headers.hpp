#pragma once

#include <algorithm>
#include <cctype>
#include <iterator>
#include <awssign/detail/emit.hpp>
#include <awssign/detail/transform_if.hpp>

namespace awssign::v4::detail {

using awssign::detail::emit;
using awssign::detail::transform_if;

inline bool whitespace(unsigned char c) { return std::isspace(c); }

// return the string with any leading/tailing whitespace trimmed
std::string_view trim(std::string_view str)
{
  auto end = str.data() + str.size();
  auto i = std::find_if_not(str.data(), end, whitespace);
  if (i == end) {
    return {};
  }
  end = std::find_if_not(std::reverse_iterator{end},
                         std::reverse_iterator{i}, whitespace).base();
  const std::size_t count = std::distance(i, end);
  return {i, count};
}

// convert the header name to lower case
template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t canonical_header_name(Iterator begin, Iterator end, Writer&& out)
{
  constexpr auto is_upper = [] (unsigned char c) {
    return std::isupper(c);
  };
  constexpr auto to_lower = [] (unsigned char c, Writer& out) {
    return emit(std::tolower(c), out);
  };
  return transform_if(begin, end, is_upper, to_lower, out);
}

// trim any leading/trailing whitespace, and replace any internal whitespace
// sequences with a single space
template <typename Iterator, // forward iterator with value_type=char
          typename Writer> // void(Iterator, Iterator)
std::size_t canonical_header_value(Iterator begin, Iterator end, Writer&& out)
{
  // skip leading whitespace
  auto i = std::find_if_not(begin, end, whitespace);
  std::size_t bytes = 0;
  for (;;) {
    auto next = std::find_if(i, end, whitespace);
    if (i != next) {
      bytes +=  emit(i, next, out);
    }
    if (next == end) {
      break;
    }
    // skip past any remaining whitespace
    i = std::find_if_not(std::next(next), end, whitespace);
    if (i == end) { // skip trailing whitespace
      break;
    }
    // emit a single space
    bytes += emit(' ', out);
  }
  return bytes;
}

struct canonical_header {
  std::string_view name; // trimmed header name
  std::string_view value;
};

// case-insensitive name comparison
struct canonical_name_less {
  bool operator()(unsigned char l, unsigned char r) const {
    return std::tolower(l) < std::tolower(r);
  }
  bool operator()(std::string_view l, std::string_view r) const {
    return std::lexicographical_compare(l.begin(), l.end(),
                                        r.begin(), r.end(), *this);
  }
  bool operator()(const canonical_header& l, const canonical_header& r) const {
    return (*this)(l.name, r.name);
  }
};

} // namespace awssign::v4::detail
