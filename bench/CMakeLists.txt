add_subdirectory(dependency)

add_executable(bench_headers bench_headers.cc)
target_link_libraries(bench_headers awssign benchmark benchmark_main)
