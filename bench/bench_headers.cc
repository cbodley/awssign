#include <random>
#include <string>
#include <benchmark/benchmark.h>
#include <awssign/v4.hpp>

// constants that are common to each request
constexpr const char* hash_algorithm = "SHA256";
constexpr std::string_view access_key_id = "ACCESS";
constexpr std::string_view secret_access_key = "SECRET";
constexpr std::string_view method = "GET";
constexpr std::string_view uri_path = "/";
constexpr std::string_view query = "";
constexpr std::string_view payload_hash = "";
constexpr std::string_view date_iso8601 = "21010101";
constexpr std::string_view region = "region";
constexpr std::string_view service = "service";

void noop_writer(const char*, const char*) {}

struct header_type {
  std::string_view name_string() const { return name_; }
  std::string_view value() const { return value_; }

  std::string name_;
  std::string value_;
};

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

// generate a random header name and value with the given constraints
static void generate_header(random_engine& rng,
                            size_distribution name_lengths,
                            std::string_view name_chars,
                            size_distribution value_lengths,
                            std::string_view value_chars,
                            header_type& header)
{
  const std::size_t name_len = name_lengths(rng);
  std::generate_n(std::back_inserter(header.name_), name_len,
                  choose_char{rng, name_chars});

  const std::size_t value_len = value_lengths(rng);
  std::generate_n(std::back_inserter(header.value_), value_len,
                  choose_char{rng, value_chars});
}

// generic parameterized benchmark
static void bench_headers(benchmark::State& state,
                          size_distribution name_lengths,
                          std::string_view name_chars,
                          size_distribution value_lengths,
                          std::string_view value_chars,
                          std::size_t headers_per_request)
{
  using awssign::v4::sign;

  random_engine rng; // default seed

  constexpr std::size_t request_count = 512;
  std::size_t header_count = request_count * headers_per_request;

  auto headers = std::vector<header_type>{header_count};
  for (auto& h : headers) {
    generate_header(rng, name_lengths, name_chars,
                    value_lengths, value_chars, h);
  }

  for (auto _ : state) {
    auto header = headers.begin();
    for (std::size_t request = 0; request < request_count; ++request) {
      auto end = header + headers_per_request;
      sign(hash_algorithm, access_key_id, secret_access_key,
           method, uri_path, query, header, end, payload_hash,
           date_iso8601, region, service, noop_writer);
      header = end;
    }
  }
}

const auto short_lengths = size_distribution{1, 8};
const auto medium_lengths = size_distribution{12, 32};
const auto long_lengths = size_distribution{128, 512};

static constexpr std::string_view lowercase_chars{
  "abcdefghijklmnopqrstuvwxyz"
};
static constexpr std::string_view uppercase_chars{
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
};
static constexpr std::string_view alphanumeric_chars{
  "abcdefghijklmnopqrstuvwxyz"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "0123456789"
};
// distribution likely to produce whitespace sequences in header values
static constexpr std::string_view whitespacey_chars{
  "abcdefghijklmnopqrstuvwxyz"
  " \f\n\r\t\v"
  " \f\n\r\t\v"
  " \f\n\r\t\v"
  " \f\n\r\t\v"
};

BENCHMARK_CAPTURE(bench_headers, short_8,
                  short_lengths, alphanumeric_chars,
                  short_lengths, alphanumeric_chars, 8);

BENCHMARK_CAPTURE(bench_headers, short_16,
                  short_lengths, alphanumeric_chars,
                  short_lengths, alphanumeric_chars, 16);

BENCHMARK_CAPTURE(bench_headers, short_32,
                  short_lengths, alphanumeric_chars,
                  short_lengths, alphanumeric_chars, 32);

BENCHMARK_CAPTURE(bench_headers, short_64,
                  short_lengths, alphanumeric_chars,
                  short_lengths, alphanumeric_chars, 64);

BENCHMARK_CAPTURE(bench_headers, medium_8,
                  medium_lengths, alphanumeric_chars,
                  medium_lengths, alphanumeric_chars, 8);

BENCHMARK_CAPTURE(bench_headers, medium_16,
                  medium_lengths, alphanumeric_chars,
                  medium_lengths, alphanumeric_chars, 16);

BENCHMARK_CAPTURE(bench_headers, medium_32,
                  medium_lengths, alphanumeric_chars,
                  medium_lengths, alphanumeric_chars, 32);

BENCHMARK_CAPTURE(bench_headers, long_names_8,
                  long_lengths, alphanumeric_chars,
                  short_lengths, alphanumeric_chars, 8);

BENCHMARK_CAPTURE(bench_headers, long_names_16,
                  long_lengths, alphanumeric_chars,
                  short_lengths, alphanumeric_chars, 16);

BENCHMARK_CAPTURE(bench_headers, long_values_8,
                  short_lengths, alphanumeric_chars,
                  long_lengths, alphanumeric_chars, 8);

BENCHMARK_CAPTURE(bench_headers, long_values_16,
                  short_lengths, alphanumeric_chars,
                  long_lengths, alphanumeric_chars, 16);

BENCHMARK_CAPTURE(bench_headers, medium_lowercase_8,
                  medium_lengths, lowercase_chars,
                  medium_lengths, lowercase_chars, 8);

BENCHMARK_CAPTURE(bench_headers, medium_uppercase_8,
                  medium_lengths, uppercase_chars,
                  medium_lengths, uppercase_chars, 8);

BENCHMARK_CAPTURE(bench_headers, medium_whitespacey_8,
                  medium_lengths, whitespacey_chars,
                  medium_lengths, whitespacey_chars, 8);

BENCHMARK_CAPTURE(bench_headers, multi_value_8,
                  // use "aaaaaaaa" for all header names
                  size_distribution{8, 8},
                  std::string_view{"a"},
                  medium_lengths, alphanumeric_chars, 8);

BENCHMARK_CAPTURE(bench_headers, multi_value_16,
                  // use "aaaaaaaa" for all header names
                  size_distribution{8, 8},
                  std::string_view{"a"},
                  medium_lengths, alphanumeric_chars, 16);

BENCHMARK_MAIN();
