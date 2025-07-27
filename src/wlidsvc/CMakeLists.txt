project(wlidsvc C CXX)

add_library(wlidsvc SHARED
    src/wlidsvc.cpp
)

target_link_options(wlidsvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/wlidsvc.def)
target_include_directories(wlidsvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

include("${CMAKE_SOURCE_DIR}/cmake/SignBinary.cmake")
sign_target(wlidsvc ".dll")