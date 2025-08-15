cmake_minimum_required(VERSION 3.28)
project(ReLiveNative C CXX)

set(LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# add_compile_definitions("NO_LOGGING")

add_subdirectory(src)
add_subdirectory(tests)