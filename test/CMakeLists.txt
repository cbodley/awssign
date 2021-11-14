add_subdirectory(dependency)

add_library(address-sanitizer INTERFACE)
target_compile_options(address-sanitizer INTERFACE "-fsanitize=address,undefined")
target_link_libraries(address-sanitizer INTERFACE "-fsanitize=address,undefined")

add_executable(test_v4_canonical_headers test_v4_canonical_headers.cc)
target_link_libraries(test_v4_canonical_headers awssign address-sanitizer gtest gtest_main)
add_test(test_v4_canonical_headers test_v4_canonical_headers)
