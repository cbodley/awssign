#pragma once

#include <algorithm>
#include <iterator>

namespace awssign::detail {

// an iterator wrapper that skips any entries that fail the predicate
template <typename Predicate, typename Iterator>
class filtered_iterator {
  Predicate pred;
  Iterator pos;
  Iterator end;
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
      : pred(std::forward<Pred>(pred)),
        pos(std::find_if(begin, end, this->pred)),
        end(end)
  {}

  filtered_iterator& operator++() {
    pos = std::find_if(std::next(pos), end, pred);
    return *this;
  }
  filtered_iterator operator++(int) {
    filtered_iterator tmp = *this;
    pos = std::find_if(std::next(pos), end, pred);
    return tmp;
  }

  reference operator*() const { return *pos; }
  pointer operator->() const { return &*pos; }

  // equality and inequality comparisons between filtered and wrapped iterators
  friend bool operator==(const filtered_iterator& lhs,
                         const filtered_iterator& rhs) {
    return lhs.pos == rhs.pos;
  }
  friend bool operator!=(const filtered_iterator& lhs,
                         const filtered_iterator& rhs) {
    return lhs.pos != rhs.pos;
  }
};

} // namespace awssign::detail
