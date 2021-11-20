#pragma once

#include <awssign/detail/transform.hpp>

namespace awssign::detail {

template <typename BinaryOperation, // size_t(char, Writer&)
          typename Writer> // void(Iterator, Iterator)
struct transform_writer {
  BinaryOperation op;
  Writer& out;

  void operator()(const char* begin, const char* end) {
    transform(begin, end, op, out);
  }
};

template <typename BinaryOperation, // size_t(char, Writer&)
          typename Writer> // void(Iterator, Iterator)
auto transformed(BinaryOperation&& op, Writer&& out)
  -> transform_writer<BinaryOperation, Writer>
{
  return {std::forward<BinaryOperation>(op), std::forward<Writer>(out)};
}

template <typename UnaryPredicate, // bool(char)
          typename BinaryOperation, // size_t(char, Writer&)
          typename Writer> // void(Iterator, Iterator)
struct transform_if_writer {
  UnaryPredicate pred;
  BinaryOperation op;
  Writer& out;

  void operator()(const char* begin, const char* end) {
    transform_if(begin, end, pred, op, out);
  }
};

template <typename UnaryPredicate, // bool(char)
          typename BinaryOperation, // size_t(char, Writer&)
          typename Writer> // void(Iterator, Iterator)
auto transformed_if(UnaryPredicate&& p,
                    BinaryOperation&& op,
                    Writer&& out)
  -> transform_if_writer<UnaryPredicate, BinaryOperation, Writer>
{
  return {std::forward<UnaryPredicate>(p),
          std::forward<BinaryOperation>(op),
          std::forward<Writer>(out)};
}

} // namespace awssign::detail
