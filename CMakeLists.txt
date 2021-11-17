cmake_minimum_required (VERSION 3.5.1)
project(awssign)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(awssign INTERFACE)
target_include_directories(awssign INTERFACE include)
target_link_libraries(awssign INTERFACE OpenSSL::Crypto)
install(DIRECTORY include/awssign DESTINATION include)

enable_testing()
add_subdirectory(test)
add_subdirectory(bench)
