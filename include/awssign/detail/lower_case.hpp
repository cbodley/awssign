#pragma once

#include <algorithm>
#include <cctype>
#include <iterator>
#include <awssign/detail/emit.hpp>
#include <awssign/detail/fast_tolower.h>

namespace awssign::detail {

// a case-converting string_view wrapper
class lower_case_string {
  std::string_view value;
 public:
  lower_case_string() = default;
  lower_case_string(const lower_case_string&) = default;
  explicit lower_case_string(std::string_view str) noexcept
      : value(str) {}
  lower_case_string& operator=(const lower_case_string&) = default;
  lower_case_string& operator=(std::string_view str) {
    value = str;
    return *this;
  }

  using value_type = std::string_view::value_type;
  using pointer = std::string_view::pointer;
  using reference = std::string_view::reference;
  using size_type = std::string_view::size_type;
  using difference_type = std::string_view::difference_type;

  // no data() for direct access to the buffer

  size_type size() const { return value.size(); }
  bool empty() const { return value.empty(); }

  // implicit conversion back to string_view
  operator std::string_view() const { return value; }

  // custom iterator that calls tolower() on dereference
  class const_iterator {
    using base_iterator = std::string_view::const_iterator;
    base_iterator pos;
   public:
    using difference_type = lower_case_string::difference_type;
    using value_type = lower_case_string::value_type;
    using pointer = lower_case_string::pointer;
    using reference = lower_case_string::reference;
    using iterator_category = std::forward_iterator_tag;

    const_iterator() = default;
    const_iterator(base_iterator pos) noexcept : pos(pos) {}

    const_iterator& operator++() {
      ++pos;
      return *this;
    }
    const_iterator operator++(int) {
      return pos++;
    }
    value_type operator*() const {
      return std::tolower(static_cast<unsigned char>(*pos));
    }
    friend bool operator==(const const_iterator& l, const const_iterator& r) {
      return l.pos == r.pos;
    }
    friend bool operator!=(const const_iterator& l, const const_iterator& r) {
      return l.pos != r.pos;
    }
  };
  using iterator = const_iterator;

  const_iterator begin() { return value.begin(); }
  const_iterator begin() const { return value.begin(); }
  const_iterator cbegin() const { return value.cbegin(); }
  const_iterator end() { return value.end(); }
  const_iterator end() const { return value.end(); }
  const_iterator cend() const { return value.cend(); }

  using const_reverse_iterator = std::reverse_iterator<const_iterator>;
  using reverse_iterator = const_reverse_iterator;

  const_reverse_iterator rbegin() { return value.rbegin(); }
  const_reverse_iterator rbegin() const { return value.rbegin(); }
  const_reverse_iterator crbegin() const { return value.crbegin(); }
  const_reverse_iterator rend() { return value.rend(); }
  const_reverse_iterator rend() const { return value.rend(); }
  const_reverse_iterator crend() const { return value.crend(); }
};

// comparisons between lower_case_string and std::string_view
inline bool operator==(lower_case_string l, lower_case_string r) {
  return std::equal(l.begin(), l.end(), r.begin(), r.end());
}
inline bool operator==(lower_case_string l, std::string_view r) {
  return std::equal(l.begin(), l.end(), r.begin(), r.end());
}
inline bool operator==(std::string_view l, lower_case_string r) {
  return std::equal(l.begin(), l.end(), r.begin(), r.end());
}

inline bool operator!=(lower_case_string l, lower_case_string r) {
  return std::equal(l.begin(), l.end(), r.begin(), r.end());
}
inline bool operator!=(lower_case_string l, std::string_view r) {
  return std::equal(l.begin(), l.end(), r.begin(), r.end());
}
inline bool operator!=(std::string_view l, lower_case_string r) {
  return std::equal(l.begin(), l.end(), r.begin(), r.end());
}

inline bool operator<(lower_case_string l, lower_case_string r) {
  return std::lexicographical_compare(l.begin(), l.end(), r.begin(), r.end());
}
inline bool operator<(lower_case_string l, std::string_view r) {
  return std::lexicographical_compare(l.begin(), l.end(), r.begin(), r.end());
}
inline bool operator<(std::string_view l, lower_case_string r) {
  return std::lexicographical_compare(l.begin(), l.end(), r.begin(), r.end());
}

inline bool operator<=(lower_case_string l, lower_case_string r) {
  return !(r < l);
}
inline bool operator<=(lower_case_string l, std::string_view r) {
  return !(r < l);
}
inline bool operator<=(std::string_view l, lower_case_string r) {
  return !(r < l);
}

inline bool operator>(lower_case_string l, lower_case_string r) {
  return std::lexicographical_compare(r.begin(), r.end(), l.begin(), l.end());
}
inline bool operator>(lower_case_string l, std::string_view r) {
  return std::lexicographical_compare(r.begin(), r.end(), l.begin(), l.end());
}
inline bool operator>(std::string_view l, lower_case_string r) {
  return std::lexicographical_compare(r.begin(), r.end(), l.begin(), l.end());
}

inline bool operator>=(lower_case_string l, lower_case_string r) {
  return !(r > l);
}
inline bool operator>=(lower_case_string l, std::string_view r) {
  return !(r > l);
}
inline bool operator>=(std::string_view l, lower_case_string r) {
  return !(r > l);
}

// optimized case-converting stream
template <typename OutputStream>
class lower_case_stream {
  static constexpr std::size_t buffer_size = 128;
  OutputStream& out;
 public:
  explicit lower_case_stream(OutputStream& out) : out(out) {}

  void operator()(const char* begin, const char* end) {
    char buffer[buffer_size];
    std::size_t input_remaining = std::distance(begin, end);
    while (input_remaining > buffer_size) {
      constexpr auto count = buffer_size;
      ::fast_tolower(buffer, begin, count);
      emit(buffer, buffer + count, out);

      input_remaining -= count;
      begin += count;
    }
    std::size_t count = std::min(input_remaining, buffer_size);
    fast_tolower(buffer, begin, count);
    emit(buffer, buffer + count, out);
  }
};

// specialize emit() for lower_case_string and lower_case_stream
template <typename OutputStream> // void(const char*, const char*)
void emit(lower_case_string str, OutputStream& out)
{
  emit(static_cast<std::string_view>(str), lower_case_stream{out});
}

} // namespace awssign::detail
