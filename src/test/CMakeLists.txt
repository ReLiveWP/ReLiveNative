project(wlidtest C CXX)

add_executable(wlidtest
    src/wlidtest.cpp
)

target_link_libraries(wlidtest PUBLIC msidcrl "-lole32")
target_include_directories(wlidtest PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)