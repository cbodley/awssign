cmake_minimum_required (VERSION 3.5.1)
project(awssign)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(AWSSIGN_TEST "Build awssign tests" ON)
option(AWSSIGN_BENCH "Build awssign benchmarks" ON)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(awssign INTERFACE)
target_include_directories(awssign INTERFACE include)
target_link_libraries(awssign INTERFACE OpenSSL::Crypto)
install(DIRECTORY include/awssign DESTINATION include)

if(AWSSIGN_TEST)
enable_testing()
add_subdirectory(test)
endif()

if(AWSSIGN_BENCH)
add_subdirectory(bench)
endif()
