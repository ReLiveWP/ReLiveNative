project(msidcrl C CXX)

add_library(msidcrl SHARED
    src/msidcrl.cpp
)

target_link_options(msidcrl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/msidcrl.def)
target_include_directories(msidcrl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

include("${CMAKE_SOURCE_DIR}/cmake/SignBinary.cmake")
sign_target(msidcrl ".dll")