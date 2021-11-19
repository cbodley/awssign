#pragma once

#include <string_view>

namespace awssign::detail {

// a forward iterator over the parts of a split string
class split_iterator {
  std::string_view str; // full string
  char delim; // delimiter

  using size_type = std::string_view::size_type;
  size_type pos = 0; // start position of current part
  std::string_view part; // view of current part

  // return the next part after the given position
  std::string_view next(size_type end) {
    pos = str.find_first_not_of(delim, end);
    if (pos == str.npos) {
      return {};
    }
    return str.substr(pos, str.find_first_of(delim, pos) - pos);
  }
 public:
  // types required by std::iterator_traits
  using difference_type = std::ptrdiff_t;
  using value_type = std::string_view;
  using pointer = const value_type*;
  using reference = const value_type&;
  using iterator_category = std::forward_iterator_tag;

  split_iterator() = default;

  split_iterator(std::string_view str, char delim)
    : str(str), delim(delim), pos(0), part(next(0))
  {}

  split_iterator& operator++() {
    part = next(pos + part.size());
    return *this;
  }
  split_iterator operator++(int) {
    split_iterator tmp = *this;
    part = next(pos + part.size());
    return tmp;
  }

  reference operator*() const { return part; }
  pointer operator->() const { return &part; }

  friend bool operator==(const split_iterator& lhs, const split_iterator& rhs) {
    return lhs.part.data() == rhs.part.data()
        && lhs.part.size() == rhs.part.size();
  }
  friend bool operator!=(const split_iterator& lhs, const split_iterator& rhs) {
    return lhs.part.data() != rhs.part.data()
        || lhs.part.size() != rhs.part.size();
  }
};

// represents an immutable range of split string parts
//
// ranged-for loop example:
//
//   for (std::string_view s : split(input, ',')) {
//     ...
//
// container initialization example:
//
//   auto parts = split(input, ',');
//
//   std::vector<std::string> strings;
//   strings.assign(parts.begin(), parts.end());
//
class split {
  std::string_view str; // full string
  char delim; // delimiter
 public:
  split(std::string_view str, char delim)
    : str(str), delim(delim) {}

  using iterator = split_iterator;
  using const_iterator = split_iterator;

  iterator begin() const { return {str, delim}; }
  const_iterator cbegin() const { return {str, delim}; }

  iterator end() const { return {}; }
  const_iterator cend() const { return {}; }
};

} // namespace awssign::detail
