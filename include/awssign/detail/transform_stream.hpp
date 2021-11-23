#pragma once

#include <awssign/detail/transform.hpp>

namespace awssign::detail {

template <typename BinaryOperation, // size_t(char, OutputStream&)
          typename OutputStream>
struct transform_stream {
  BinaryOperation op;
  OutputStream& out;

  void operator()(const char* begin, const char* end) {
    transform(begin, end, op, out);
  }
};

template <typename BinaryOperation, // size_t(char, OutputStream&)
          typename OutputStream>
auto transformed(BinaryOperation&& op, OutputStream&& out)
  -> transform_stream<BinaryOperation, OutputStream>
{
  return {std::forward<BinaryOperation>(op), std::forward<OutputStream>(out)};
}

template <typename UnaryPredicate, // bool(char)
          typename BinaryOperation, // size_t(char, OutputStream&)
          typename OutputStream>
struct transform_if_stream {
  UnaryPredicate pred;
  BinaryOperation op;
  OutputStream& out;

  void operator()(const char* begin, const char* end) {
    transform_if(begin, end, pred, op, out);
  }
};

template <typename UnaryPredicate, // bool(char)
          typename BinaryOperation, // size_t(char, OutputStream&)
          typename OutputStream>
auto transformed_if(UnaryPredicate&& p,
                    BinaryOperation&& op,
                    OutputStream&& out)
  -> transform_if_stream<UnaryPredicate, BinaryOperation, OutputStream>
{
  return {std::forward<UnaryPredicate>(p),
          std::forward<BinaryOperation>(op),
          std::forward<OutputStream>(out)};
}

} // namespace awssign::detail
