cmake_minimum_required (VERSION 3.21.1)

set(CMAKE_CXX_CLANG_TIDY clang-tidy-11)

project(cryptopals)
set(CMAKE_CXX_STANDARD 20)

add_executable(crypto cryptopals.cpp)

target_compile_options(crypto PRIVATE -Wall -Werror -Wpedantic -Wextra)
