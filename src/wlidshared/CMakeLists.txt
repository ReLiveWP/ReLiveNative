project(wlidshared C CXX)

add_library(wlidshared STATIC
    src/wlidshared.c
    src/nanoprintf.c
    src/gthr-win32.c
)

target_include_directories(wlidshared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)