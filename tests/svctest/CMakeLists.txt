project(wlidtest C CXX)

add_executable(wlidtest
    src/wlidtest.cpp
)

target_link_libraries(wlidtest PUBLIC "-lole32" crypt32)
target_include_directories(wlidtest PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# include msidcrl headers, not the library
target_include_directories(wlidtest PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/msidcrl/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/wlidshared/include
)

include("${CMAKE_SOURCE_DIR}/cmake/StripSymbols.cmake")
strip_symbols(wlidtest)
include("${CMAKE_SOURCE_DIR}/cmake/SignBinary.cmake")
sign_target(wlidtest ".exe")