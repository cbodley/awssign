#pragma once

#include <algorithm>
#include <iterator>
#include <optional>

namespace awssign::detail {

// an iterator wrapper that skips any entries that fail the predicate
template <typename Predicate, typename Iterator>
class filtered_iterator {
  struct iterator_state {
    Predicate pred;
    Iterator pos;
    Iterator end;
    // comparisons are based on current iterator only
    bool operator==(const iterator_state& r) const { return pos == r.pos; }
    bool operator!=(const iterator_state& r) const { return pos != r.pos; }
  };
  // empty state means the iterator is past-the-end
  std::optional<iterator_state> state;

  template <typename Pred>
  static auto make_state(Pred&& pred, Iterator begin, Iterator end)
    -> std::optional<iterator_state>
  {
    std::optional<iterator_state> state;
    auto pos = std::find_if(begin, end, pred);
    if (pos != end) {
      state.emplace(iterator_state{std::forward<Pred>(pred), pos, end});
    }
    return state;
  }
 public:
  // types required by std::iterator_traits
  using difference_type = typename std::iterator_traits<Iterator>::difference_type;
  using value_type = typename std::iterator_traits<Iterator>::value_type;
  using pointer = typename std::iterator_traits<Iterator>::pointer;
  using reference = typename std::iterator_traits<Iterator>::reference;
  using iterator_category = std::forward_iterator_tag;

  filtered_iterator() = default;

  template <typename Pred>
  filtered_iterator(Pred&& pred, Iterator begin, Iterator end = Iterator())
      : state(make_state(std::forward<Pred>(pred), begin, end))
  {}

  filtered_iterator& operator++() {
    state->pos = std::find_if(std::next(state->pos), state->end, state->pred);
    if (state->pos == state->end) {
      state = std::nullopt;
    }
    return *this;
  }
  filtered_iterator operator++(int) {
    filtered_iterator tmp = *this;
    state->pos = std::find_if(std::next(state->pos), state->end, state->pred);
    if (state->pos == state->end) {
      state = std::nullopt;
    }
    return tmp;
  }

  reference operator*() const { return *state->pos; }
  pointer operator->() const { return &*state->pos; }

  friend bool operator==(const filtered_iterator& lhs,
                         const filtered_iterator& rhs) {
    return lhs.state == rhs.state;
  }
  friend bool operator!=(const filtered_iterator& lhs,
                         const filtered_iterator& rhs) {
    return lhs.state != rhs.state;
  }
};

} // namespace awssign::detail
