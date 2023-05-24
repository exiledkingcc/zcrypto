cmake_minimum_required(VERSION 3.0.0)
project(zcrypto VERSION 0.1.0)

include(CTest)
enable_testing()

add_compile_options(-Wall -Wextra -Wuninitialized -Wsign-conversion)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

include_directories(include)
add_subdirectory(src)
add_subdirectory(tests)
