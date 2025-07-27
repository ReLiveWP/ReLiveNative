project(wlidsvc C CXX)

add_library(wlidsvc SHARED
    src/log.cpp
    src/wlidsvc.cpp
    src/ioctls.cpp
    src/nanoprintf.c
)

target_link_libraries(wlidsvc PRIVATE wlidshared "-latomic" "-lcurl")

target_link_options(wlidsvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/wlidsvc.def)
target_include_directories(wlidsvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(wlidsvc PROPERTIES
    OUTPUT_NAME "wlidsvc"
    PREFIX ""
)

include("${CMAKE_SOURCE_DIR}/cmake/SignBinary.cmake")
sign_target(wlidsvc ".dll")