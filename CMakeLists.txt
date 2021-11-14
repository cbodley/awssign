cmake_minimum_required (VERSION 3.5.1)
project(awssign)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(awssign INTERFACE)
target_include_directories(awssign INTERFACE include)
install(DIRECTORY include/awssign DESTINATION include)

enable_testing()
add_subdirectory(test)
