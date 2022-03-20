#pragma once

#include <algorithm>
#include <cctype>
#include <iterator>
#include <awssign/detail/lower_case.hpp>
#include <awssign/detail/transform.hpp>
#include <awssign/detail/write.hpp>

namespace awssign::v4::detail {

using awssign::detail::lower_case_string;
using awssign::detail::transform_if;
using awssign::detail::write;

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

// write the header name in lower case
template <typename OutputStream>
void write_canonical_header_name(lower_case_string name, OutputStream&& out)
{
  write(name, out);
}

// trim any leading/trailing whitespace, and replace any internal whitespace
// sequences with a single space
template <typename OutputStream>
void write_canonical_header_value(const char* begin, const char* end,
                                  OutputStream&& out)
{
  // skip leading whitespace
  auto i = std::find_if_not(begin, end, whitespace);
  for (;;) {
    auto next = std::find_if(i, end, whitespace);
    if (i != next) {
      write(i, next, out);
    }
    if (next == end) {
      break;
    }
    // skip past any remaining whitespace
    i = std::find_if_not(std::next(next), end, whitespace);
    if (i == end) { // skip trailing whitespace
      break;
    }
    // write a single space
    write(' ', out);
  }
}

struct canonical_header {
  lower_case_string name;
  std::string_view value;

  canonical_header() = default;
  canonical_header(std::string_view name, std::string_view value)
      : name(trim(name)), value(value) {}
};

// sort by canonical header name
inline bool operator<(const canonical_header& l, const canonical_header& r)
{
  return l.name < r.name;
}

template <typename InputIterator,
          typename OutputIterator>
OutputIterator sorted_canonical_headers(InputIterator begin,
                                        InputIterator end,
                                        OutputIterator out)
{
  // initialize the canonical header array
  auto o = out;
  for (auto i = begin; i != end; ++o, ++i) {
    *o = canonical_header{i->name_string(), i->value()};
  }
  // stable sort headers by canonical name
  std::stable_sort(out, o);
  return o;
}

// write out the sorted headers in canonical format
template <typename HeaderIterator, // forward canonical_header iterator
          typename OutputStream>
void write_canonical_headers(HeaderIterator header0,
                             HeaderIterator headerN,
                             OutputStream&& out)
{
  lower_case_string last_name;
  for (auto o = header0; o != headerN; ++o) {
    if (last_name == o->name) {
      // comma-separate values with the same header name
      write(',', out);
      write_canonical_header_value(o->value.begin(), o->value.end(), out);
    } else {
      if (!last_name.empty()) {
        // finish the previous line
        write('\n', out);
      }
      last_name = o->name;
      // write name:value
      write_canonical_header_name(o->name, out);
      write(':', out);
      write_canonical_header_value(o->value.begin(), o->value.end(), out);
    }
  }
  if (!last_name.empty()) {
    // finish the last line
    write('\n', out);
  }
}

// write out the sorted header names, separated by semicolon
template <typename HeaderIterator, // forward canonical_header iterator
          typename OutputStream>
void write_signed_headers(HeaderIterator header0,
                          HeaderIterator headerN,
                          OutputStream&& out)
{
  lower_case_string last_name;
  for (auto o = header0; o != headerN; ++o) {
    if (last_name == o->name) {
      continue; // skip duplicate header names
    }
    if (!last_name.empty()) { // separate header names with ;
      write(';', out);
    }
    last_name = o->name;
    write_canonical_header_name(o->name, out);
  }
}

} // namespace awssign::v4::detail
