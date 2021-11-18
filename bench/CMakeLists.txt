add_subdirectory(dependency)

add_executable(bench_headers bench_headers.cc)
target_link_libraries(bench_headers awssign benchmark benchmark_main)

add_executable(bench_query bench_query.cc)
target_link_libraries(bench_query awssign benchmark benchmark_main)
