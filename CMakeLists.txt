cmake_minimum_required(VERSION 3.28)
project(aetherring VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow -fno-omit-frame-pointer)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
  add_compile_options(-march=x86-64-v3)
endif()

option(AETHER_TSAN "ThreadSanitizer" OFF)
if(AETHER_TSAN)
  add_compile_options(-fsanitize=thread)
  add_link_options(-fsanitize=thread)
endif()

include(FetchContent)
FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/refs/tags/v1.16.0.tar.gz)
FetchContent_Declare(benchmark  URL https://github.com/google/benchmark/archive/refs/tags/v1.9.1.tar.gz)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest benchmark)

find_package(PkgConfig REQUIRED)
pkg_check_modules(URING REQUIRED IMPORTED_TARGET liburing>=2.8)

enable_testing()
add_subdirectory(tests)
add_subdirectory(bench)
add_subdirectory(arena)
