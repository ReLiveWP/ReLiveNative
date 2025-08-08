project(wlidsvc C CXX)

add_library(wlidsvc SHARED
    src/dllmain.cpp
    src/globals.cpp
    src/log.cpp
    src/config.cpp
    src/storage.cpp
    src/wlidsvc.cpp
    src/ioctls.cpp
    src/update.cpp
)

target_link_libraries(wlidsvc PRIVATE 
    wlidshared 
    "-lole32"
    "-latomic"
    "-lcurl"
    "-lsqlite3"
    "-static-libstdc++"
)

include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)

target_link_libraries(wlidsvc PRIVATE nlohmann_json::nlohmann_json)

target_link_options(wlidsvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/wlidsvc.def)
target_include_directories(wlidsvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(wlidsvc PROPERTIES
    OUTPUT_NAME "wlidsvc"
    PREFIX ""
)

include("${CMAKE_SOURCE_DIR}/cmake/StripSymbols.cmake")
strip_symbols(wlidsvc)
include("${CMAKE_SOURCE_DIR}/cmake/SignBinary.cmake")
sign_target(wlidsvc ".dll")