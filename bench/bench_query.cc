#include <array>
#include <random>
#include <benchmark/benchmark.h>
#include <awssign/v4.hpp>

struct header_type {
  constexpr header_type(std::string_view name,
                        std::string_view value) noexcept
      : name_(name), value_(value)
  {}
  constexpr std::string_view name_string() const { return name_; }
  constexpr std::string_view value() const { return value_; }
 private:
  std::string_view name_;
  std::string_view value_;
};

// constants that are common to each request
constexpr const char* hash_algorithm = "SHA256";
constexpr std::string_view access_key_id = "ACCESS";
constexpr std::string_view secret_access_key = "SECRET";
constexpr std::string_view method = "GET";
constexpr std::string_view uri_path = "/";
constexpr std::string_view payload_hash = "";
constexpr std::string_view date_iso8601 = "21010101";
constexpr std::string_view region = "region";
constexpr std::string_view service = "service";
constexpr header_type headers[] {
  {"Host", "example.amazonaws.com"},
  {"X-Amz-Date", "20150830T123600Z"},
};

void noop_writer(const char*, const char*) {}

using random_engine = std::default_random_engine;
using size_distribution = std::uniform_int_distribution<std::size_t>;

// function object that chooses random characters from the given string
class choose_char {
  random_engine& rng;
  std::string_view chars;
  size_distribution index;
 public:
  choose_char(random_engine& rng, std::string_view chars) noexcept
      : rng(rng), chars(chars), index(0, chars.size() - 1)
  {}
  char operator()() {
    return chars[index(rng)];
  }
};

// generate a random parameter name and value with the given constraints
template <typename OutputIterator>
static auto generate_param(random_engine& rng,
                           size_distribution name_lengths,
                           std::string_view name_chars,
                           size_distribution value_lengths,
                           std::string_view value_chars,
                           OutputIterator out)
  -> OutputIterator
{
  const std::size_t name_len = name_lengths(rng);
  auto name_chooser = choose_char{rng, name_chars};
  for (std::size_t i = 0; i < name_len; i++) {
    *out++ = name_chooser();
  }
  *out++ = '=';
  const std::size_t value_len = value_lengths(rng);
  auto value_chooser = choose_char{rng, value_chars};
  for (std::size_t i = 0; i < value_len; i++) {
    *out++ = value_chooser();
  }
  return out;
}

// generic parameterized benchmark
static void bench_query(benchmark::State& state,
                        size_distribution name_lengths,
                        std::string_view name_chars,
                        size_distribution value_lengths,
                        std::string_view value_chars,
                        std::size_t params_per_request)
{
  using awssign::v4::sign;

  random_engine rng; // default seed

  constexpr std::size_t request_count = 512;

  std::array<std::string, request_count> query_strings;
  for (auto& query : query_strings) {
    auto pos = std::back_inserter(query);
    for (std::size_t i = 0; i < params_per_request; i++) {
      pos = generate_param(rng, name_lengths, name_chars,
                           value_lengths, value_chars, pos);
    }
  }

  for (auto _ : state) {
    for (const auto& query : query_strings) {
      sign(hash_algorithm, access_key_id, secret_access_key,
           method, uri_path, query, std::begin(headers),
           std::end(headers), payload_hash,
           date_iso8601, region, service, noop_writer);
    }
  }
}

const auto short_lengths = size_distribution{1, 8};
const auto medium_lengths = size_distribution{12, 32};
const auto long_lengths = size_distribution{128, 256};

static constexpr std::string_view unreserved_chars{
  "abcdefghijklmnopqrstuvwxyz"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "-._~0123456789"
};
static constexpr std::string_view mostly_unreserved_chars{
  "abcdefghijklmnopqrstuvwxyz"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "!@#$%^&*()"
};
static constexpr std::string_view mostly_reserved_chars{
  "abcd"
  "!@#$%^&*()"
};
static constexpr std::string_view whitespacey_chars{
  "abc"
  " \f\n\r\t\v"
};

BENCHMARK_CAPTURE(bench_query, short_unreserved_8,
                  short_lengths, unreserved_chars,
                  short_lengths, unreserved_chars, 8);

BENCHMARK_CAPTURE(bench_query, short_mostly_unreserved_8,
                  short_lengths, mostly_unreserved_chars,
                  short_lengths, mostly_unreserved_chars, 8);

BENCHMARK_CAPTURE(bench_query, short_mostly_reserved_8,
                  short_lengths, mostly_reserved_chars,
                  short_lengths, mostly_reserved_chars, 8);

BENCHMARK_CAPTURE(bench_query, short_unreserved_16,
                  short_lengths, unreserved_chars,
                  short_lengths, unreserved_chars, 16);

BENCHMARK_CAPTURE(bench_query, short_mostly_unreserved_16,
                  short_lengths, mostly_unreserved_chars,
                  short_lengths, mostly_unreserved_chars, 16);

BENCHMARK_CAPTURE(bench_query, short_mostly_reserved_16,
                  short_lengths, mostly_reserved_chars,
                  short_lengths, mostly_reserved_chars, 16);

BENCHMARK_CAPTURE(bench_query, short_unreserved_32,
                  short_lengths, unreserved_chars,
                  short_lengths, unreserved_chars, 32);

BENCHMARK_CAPTURE(bench_query, short_mostly_unreserved_32,
                  short_lengths, mostly_unreserved_chars,
                  short_lengths, mostly_unreserved_chars, 32);

BENCHMARK_CAPTURE(bench_query, short_mostly_reserved_32,
                  short_lengths, mostly_reserved_chars,
                  short_lengths, mostly_reserved_chars, 32);

BENCHMARK_CAPTURE(bench_query, short_unreserved_64,
                  short_lengths, unreserved_chars,
                  short_lengths, unreserved_chars, 64);

BENCHMARK_CAPTURE(bench_query, short_mostly_unreserved_64,
                  short_lengths, mostly_unreserved_chars,
                  short_lengths, mostly_unreserved_chars, 64);

BENCHMARK_CAPTURE(bench_query, short_mostly_reserved_64,
                  short_lengths, mostly_reserved_chars,
                  short_lengths, mostly_reserved_chars, 64);

BENCHMARK_CAPTURE(bench_query, medium_unreserved_8,
                  medium_lengths, unreserved_chars,
                  medium_lengths, unreserved_chars, 8);

BENCHMARK_CAPTURE(bench_query, medium_mostly_unreserved_8,
                  medium_lengths, mostly_unreserved_chars,
                  medium_lengths, mostly_unreserved_chars, 8);

BENCHMARK_CAPTURE(bench_query, medium_mostly_reserved_8,
                  medium_lengths, mostly_reserved_chars,
                  medium_lengths, mostly_reserved_chars, 8);

BENCHMARK_CAPTURE(bench_query, medium_unreserved_16,
                  medium_lengths, unreserved_chars,
                  medium_lengths, unreserved_chars, 16);

BENCHMARK_CAPTURE(bench_query, medium_mostly_unreserved_16,
                  medium_lengths, mostly_unreserved_chars,
                  medium_lengths, mostly_unreserved_chars, 16);

BENCHMARK_CAPTURE(bench_query, medium_mostly_reserved_16,
                  medium_lengths, mostly_reserved_chars,
                  medium_lengths, mostly_reserved_chars, 16);

BENCHMARK_CAPTURE(bench_query, long_unreserved_8,
                  long_lengths, unreserved_chars,
                  long_lengths, unreserved_chars, 8);

BENCHMARK_CAPTURE(bench_query, long_mostly_unreserved_8,
                  long_lengths, mostly_unreserved_chars,
                  long_lengths, mostly_unreserved_chars, 8);

BENCHMARK_CAPTURE(bench_query, long_mostly_reserved_8,
                  long_lengths, mostly_reserved_chars,
                  long_lengths, mostly_reserved_chars, 8);

BENCHMARK_CAPTURE(bench_query, long_unreserved_16,
                  long_lengths, unreserved_chars,
                  long_lengths, unreserved_chars, 16);

BENCHMARK_CAPTURE(bench_query, long_mostly_unreserved_16,
                  long_lengths, mostly_unreserved_chars,
                  long_lengths, mostly_unreserved_chars, 16);

BENCHMARK_CAPTURE(bench_query, long_mostly_reserved_16,
                  long_lengths, mostly_reserved_chars,
                  long_lengths, mostly_reserved_chars, 16);


BENCHMARK_CAPTURE(bench_query, multi_value_mostly_unreserved_16,
                  // use "aaaaaaaa" for all param names
                  size_distribution{8, 8},
                  std::string_view{"a"},
                  medium_lengths, mostly_unreserved_chars, 16);

BENCHMARK_MAIN();
