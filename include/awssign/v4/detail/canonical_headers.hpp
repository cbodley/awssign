#pragma once

#include <algorithm>
#include <cctype>
#include <iterator>
#include <awssign/detail/emit.hpp>
#include <awssign/detail/lower_case.hpp>
#include <awssign/detail/transform.hpp>

namespace awssign::v4::detail {

using awssign::detail::emit;
using awssign::detail::lower_case_less;
using awssign::detail::lower_case_writer;
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
  return emit(begin, end, lower_case_writer{out});
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

// compares header names in their canonical format
struct canonical_name_less {
  bool operator()(const canonical_header& l, const canonical_header& r) const {
    return lower_case_less{}(l.name, r.name);
  }
};

template <typename InputIterator,
          typename OutputIterator>
OutputIterator sorted_canonical_headers(InputIterator begin,
                                        InputIterator end,
                                        OutputIterator out)
{
  // initialize the canonical header array
  auto o = out;
  for (auto i = begin; i != end; ++o, ++i) {
    o->name = trim(i->name());
    o->value = i->value();
  }
  // stable sort headers by canonical name
  std::stable_sort(out, o, canonical_name_less{});
  return o;
}

// write out the sorted headers in canonical format
template <typename HeaderIterator, // forward canonical_header iterator
          typename Writer> // void(const char*, const char*)
std::size_t canonical_headers(HeaderIterator header0,
                              HeaderIterator headerN,
                              Writer&& out)
{
  std::size_t bytes = 0;
  std::string_view last_name;
  for (auto o = header0; o != headerN; ++o) {
    if (!lower_case_less{}(last_name, o->name)) {
      // comma-separate values with the same header name
      bytes += emit(',', out);
      bytes += canonical_header_value(o->value.begin(),
                                      o->value.end(), out);
    } else {
      if (!last_name.empty()) {
        // finish the previous line
        bytes += emit('\n', out);
      }
      last_name = o->name;
      // write name:value
      bytes += canonical_header_name(o->name.begin(),
                                     o->name.end(), out);
      bytes += emit(':', out);
      bytes += canonical_header_value(o->value.begin(),
                                      o->value.end(), out);
    }
  }
  if (!last_name.empty()) {
    // finish the last line
    bytes += emit('\n', out);
  }
  return bytes;
}

// write out the sorted header names, separated by semicolon
template <typename HeaderIterator, // forward canonical_header iterator
          typename Writer> // void(const char*, const char*)
std::size_t signed_headers(HeaderIterator header0,
                           HeaderIterator headerN,
                           Writer&& out)
{
  std::size_t bytes = 0;
  std::string_view last_name;
  for (auto o = header0; o != headerN; ++o) {
    if (!lower_case_less{}(last_name, o->name)) {
      continue; // skip duplicate header names
    }
    last_name = o->name;
    if (bytes) { // separate header names with ;
      bytes += emit(';', out);
    }
    bytes += canonical_header_name(o->name.begin(),
                                   o->name.end(), out);
  }
  return bytes;
}

} // namespace awssign::v4::detail
