#include <random>
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
  std::string_view name() const { return name_; }
  std::string_view value() const { return value_; }

  char buffer[1024];
  std::string_view name_;
  std::string_view value_;
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
  const std::size_t value_len = value_lengths(rng);

  header.name_ = std::string_view{header.buffer, name_len};
  header.value_ = std::string_view{header.buffer + name_len, value_len};

  std::generate(header.buffer,
                header.buffer + name_len,
                choose_char{rng, name_chars});
  std::generate(header.buffer + name_len,
                header.buffer + name_len + value_len,
                choose_char{rng, value_chars});
}

// generic parameterized benchmark
static void bench_headers(size_distribution name_lengths,
                          std::string_view name_chars,
                          size_distribution value_lengths,
                          std::string_view value_chars,
                          std::size_t headers_per_request,
                          benchmark::State& state)
{
  using awssign::v4::sign_header;

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
      sign_header(hash_algorithm, access_key_id, secret_access_key,
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

static void bench_8_short_headers(benchmark::State& state)
{
  const auto name_lengths = short_lengths;
  constexpr auto name_chars = alphanumeric_chars;
  const auto value_lengths = short_lengths;
  constexpr auto value_chars = alphanumeric_chars;
  constexpr std::size_t headers_per_request = 8;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_8_short_headers);

static void bench_8_medium_headers(benchmark::State& state)
{
  const auto name_lengths = medium_lengths;
  constexpr auto name_chars = alphanumeric_chars;
  const auto value_lengths = medium_lengths;
  constexpr auto value_chars = alphanumeric_chars;
  constexpr std::size_t headers_per_request = 8;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_8_medium_headers);

static void bench_16_medium_headers(benchmark::State& state)
{
  const auto name_lengths = medium_lengths;
  constexpr auto name_chars = alphanumeric_chars;
  const auto value_lengths = medium_lengths;
  constexpr auto value_chars = alphanumeric_chars;
  constexpr std::size_t headers_per_request = 16;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_16_medium_headers);

static void bench_32_medium_headers(benchmark::State& state)
{
  const auto name_lengths = medium_lengths;
  constexpr auto name_chars = alphanumeric_chars;
  const auto value_lengths = medium_lengths;
  constexpr auto value_chars = alphanumeric_chars;
  constexpr std::size_t headers_per_request = 32;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_32_medium_headers);

static void bench_4_long_header_names(benchmark::State& state)
{
  const auto name_lengths = long_lengths;
  constexpr auto name_chars = alphanumeric_chars;
  const auto value_lengths = short_lengths;
  constexpr auto value_chars = alphanumeric_chars;
  constexpr std::size_t headers_per_request = 4;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_4_long_header_names);

static void bench_64_long_header_names(benchmark::State& state)
{
  const auto name_lengths = long_lengths;
  constexpr auto name_chars = alphanumeric_chars;
  const auto value_lengths = short_lengths;
  constexpr auto value_chars = alphanumeric_chars;
  constexpr std::size_t headers_per_request = 64;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_64_long_header_names);

static void bench_8_long_header_values(benchmark::State& state)
{
  const auto name_lengths = short_lengths;
  constexpr auto name_chars = alphanumeric_chars;
  const auto value_lengths = long_lengths;
  constexpr auto value_chars = alphanumeric_chars;
  constexpr std::size_t headers_per_request = 8;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_8_long_header_values);

static void bench_8_lowercase_headers(benchmark::State& state)
{
  const auto name_lengths = medium_lengths;
  constexpr auto name_chars = lowercase_chars;
  const auto value_lengths = medium_lengths;
  constexpr auto value_chars = lowercase_chars;
  constexpr std::size_t headers_per_request = 8;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_8_lowercase_headers);

static void bench_8_uppercase_headers(benchmark::State& state)
{
  const auto name_lengths = medium_lengths;
  constexpr auto name_chars = uppercase_chars;
  const auto value_lengths = medium_lengths;
  constexpr auto value_chars = uppercase_chars;
  constexpr std::size_t headers_per_request = 8;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_8_uppercase_headers);

static void bench_8_whitespacey_headers(benchmark::State& state)
{
  const auto name_lengths = medium_lengths;
  constexpr auto name_chars = uppercase_chars;
  const auto value_lengths = medium_lengths;
  constexpr auto value_chars = whitespacey_chars;
  constexpr std::size_t headers_per_request = 8;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_8_whitespacey_headers);

static void bench_16_multi_value_headers(benchmark::State& state)
{
  // use "aaaaaaaa" for all header names
  auto name_lengths = size_distribution{8, 8};
  constexpr auto name_chars = std::string_view{"a"};
  auto value_lengths = medium_lengths;
  constexpr auto value_chars = alphanumeric_chars;
  constexpr std::size_t headers_per_request = 16;

  bench_headers(name_lengths, name_chars,
                value_lengths, value_chars,
                headers_per_request, state);
}
BENCHMARK(bench_16_multi_value_headers);

BENCHMARK_MAIN();
