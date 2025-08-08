project(curltest C CXX)

add_executable(curltest
    src/curltest.cpp
)

target_link_libraries(curltest PUBLIC "-lcurl")
target_include_directories(curltest PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

include("${CMAKE_SOURCE_DIR}/cmake/StripSymbols.cmake")
strip_symbols(curltest)
include("${CMAKE_SOURCE_DIR}/cmake/SignBinary.cmake")
sign_target(curltest ".exe")