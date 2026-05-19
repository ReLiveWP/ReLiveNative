project(relivecfg C CXX)

add_executable(relivecfg
    src/relivecfg.cpp
    src/PageManager.cpp
)

target_link_libraries(relivecfg PUBLIC  
    wlidshared "-lole32" crypt32 d3d11 d3dcompiler)
target_include_directories(relivecfg PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

include("${CMAKE_SOURCE_DIR}/cmake/StripSymbols.cmake")
strip_symbols(relivecfg)
include("${CMAKE_SOURCE_DIR}/cmake/SignBinary.cmake")
sign_target(relivecfg ".exe")