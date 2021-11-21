#pragma once

#include <algorithm>
#include <cctype>
#include <iterator>
#include <awssign/detail/emit.hpp>
#include <awssign/detail/lower_case.hpp>
#include <awssign/detail/transform.hpp>

namespace awssign::v4::detail {

using awssign::detail::emit;
using awssign::detail::lower_case_string;
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
template <typename OutputStream> // void(Iterator, Iterator)
void canonical_header_name(lower_case_string name, OutputStream&& out)
{
  emit(name, out);
}

// trim any leading/trailing whitespace, and replace any internal whitespace
// sequences with a single space
template <typename Iterator, // forward iterator with value_type=char
          typename OutputStream> // void(Iterator, Iterator)
void canonical_header_value(Iterator begin, Iterator end, OutputStream&& out)
{
  // skip leading whitespace
  auto i = std::find_if_not(begin, end, whitespace);
  for (;;) {
    auto next = std::find_if(i, end, whitespace);
    if (i != next) {
      emit(i, next, out);
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
    emit(' ', out);
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
    *o = canonical_header{i->name(), i->value()};
  }
  // stable sort headers by canonical name
  std::stable_sort(out, o);
  return o;
}

// write out the sorted headers in canonical format
template <typename HeaderIterator, // forward canonical_header iterator
          typename OutputStream> // void(const char*, const char*)
void canonical_headers(HeaderIterator header0,
                       HeaderIterator headerN,
                       OutputStream&& out)
{
  lower_case_string last_name;
  for (auto o = header0; o != headerN; ++o) {
    if (last_name == o->name) {
      // comma-separate values with the same header name
      emit(',', out);
      canonical_header_value(o->value.begin(), o->value.end(), out);
    } else {
      if (!last_name.empty()) {
        // finish the previous line
        emit('\n', out);
      }
      last_name = o->name;
      // write name:value
      canonical_header_name(o->name, out);
      emit(':', out);
      canonical_header_value(o->value.begin(), o->value.end(), out);
    }
  }
  if (!last_name.empty()) {
    // finish the last line
    emit('\n', out);
  }
}

// write out the sorted header names, separated by semicolon
template <typename HeaderIterator, // forward canonical_header iterator
          typename OutputStream> // void(const char*, const char*)
void signed_headers(HeaderIterator header0,
                    HeaderIterator headerN,
                    OutputStream&& out)
{
  lower_case_string last_name;
  for (auto o = header0; o != headerN; ++o) {
    if (last_name == o->name) {
      continue; // skip duplicate header names
    }
    if (!last_name.empty()) { // separate header names with ;
      emit(';', out);
    }
    last_name = o->name;
    canonical_header_name(o->name, out);
  }
}

} // namespace awssign::v4::detail
