#pragma once

#include <algorithm>
#include <iterator>
#include <optional>
#include <awssign/detail/percent_decode.hpp>

namespace awssign::detail {

// an iterator that percent-decodes the wrapped sequence
template <typename Iterator>
class percent_decode_iterator {
  struct iterator_state {
    Iterator pos;
    Iterator end;
    // comparisons are based on current iterator only
    bool operator==(const iterator_state& r) const { return pos == r.pos; }
    bool operator!=(const iterator_state& r) const { return pos != r.pos; }
  };
  // empty state means the iterator is past-the-end
  std::optional<iterator_state> state;

  static auto make_state(Iterator begin, Iterator end)
    -> std::optional<iterator_state> {
    std::optional<iterator_state> state;
    if (begin != end) {
      state.emplace(iterator_state{begin, end});
    }
    return state;
  }

  void next() {
    if (*state->pos == '%') {
      std::advance(state->pos, 3);
    } else {
      std::advance(state->pos, 1);
    }
    if (state->pos == state->end) {
      state = std::nullopt;
    }
  }
 public:
  // types required by std::iterator_traits
  using difference_type = typename std::iterator_traits<Iterator>::difference_type;
  using value_type = typename std::iterator_traits<Iterator>::value_type;
  using pointer = typename std::iterator_traits<Iterator>::pointer;
  using reference = typename std::iterator_traits<Iterator>::reference;
  using iterator_category = std::forward_iterator_tag;

  percent_decode_iterator() = default;

  percent_decode_iterator(Iterator begin, Iterator end = Iterator())
      : state(make_state(begin, end))
  {}

  percent_decode_iterator& operator++() {
    next();
    return *this;
  }
  percent_decode_iterator operator++(int) {
    percent_decode_iterator tmp = *this;
    next();
    return tmp;
  }

  value_type operator*() const {
    value_type c = *state->pos;
    if (c != '%') {
      return c;
    }
    auto i = std::next(state->pos);
    if (i == state->end) {
      return 0;
    }
    const char first_half = percent_decode(*i++);
    if (i == state->end) {
      return 0;
    }
    const char second_half = percent_decode(*i);
    return percent_decode(first_half, second_half);
  }
  // no operator->

  friend bool operator==(const percent_decode_iterator& lhs,
                         const percent_decode_iterator& rhs) {
    return lhs.state == rhs.state;
  }
  friend bool operator!=(const percent_decode_iterator& lhs,
                         const percent_decode_iterator& rhs) {
    return lhs.state != rhs.state;
  }
};

} // namespace awssign::detail
