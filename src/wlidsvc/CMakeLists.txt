project(wlidsvc C CXX)

include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)

add_library(objlib_wlidsvc OBJECT 
    src/dllmain.cpp
    src/globals.cpp
    src/log.cpp
    src/config.cpp
    src/storage.cpp
    src/storage/config_storage.cpp
    src/storage/identity_storage.cpp
    src/storage/identity_property_storage.cpp
    src/storage/token_storage.cpp
    src/wlidsvc.cpp
    src/ioctls.cpp
    src/update.cpp
    src/types.cpp
)

target_link_libraries(objlib_wlidsvc PRIVATE wlidshared nlohmann_json::nlohmann_json)
target_include_directories(objlib_wlidsvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(wlidsvc SHARED
    $<TARGET_OBJECTS:objlib_wlidsvc>
)

set_target_properties(wlidsvc PROPERTIES
    OUTPUT_NAME "wlidsvc"
    PREFIX ""
)
target_link_libraries(wlidsvc PRIVATE 
    wlidshared 
    "-lole32"
    "-latomic"
    "-lcurl"
    "-lsqlite3"
    "-static-libgcc"
    "-static-libstdc++"
)

target_link_libraries(wlidsvc PRIVATE nlohmann_json::nlohmann_json)
target_link_options(wlidsvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/wlidsvc.def)
target_include_directories(wlidsvc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

include("${CMAKE_SOURCE_DIR}/cmake/StripSymbols.cmake")
strip_symbols(wlidsvc)
include("${CMAKE_SOURCE_DIR}/cmake/SignBinary.cmake")
sign_target(wlidsvc ".dll")

add_library(libwlidsvc STATIC
    $<TARGET_OBJECTS:objlib_wlidsvc>
)

set_target_properties(libwlidsvc PROPERTIES
    OUTPUT_NAME "libwlidsvc"
    PREFIX ""
)

target_link_libraries(libwlidsvc PUBLIC 
    wlidshared 
    "-lole32"
    "-latomic"
    "-lcurl"
    "-lsqlite3"
    "-static-libgcc"
    "-static-libstdc++"
)
