project(msidcrl C CXX)

add_library(msidcrl SHARED
    src/dllmain.cpp
    src/globals.cpp
    src/msidcrl.cpp
    src/util.cpp
    src/test.cpp
)

target_link_libraries(msidcrl PRIVATE wlidshared ole32)

if(CE_BUILD)
target_link_libraries(msidcrl PRIVATE toolhelp)
endif()

target_link_options(msidcrl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/msidcrl.def)
target_include_directories(msidcrl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(msidcrl PRIVATE "-DWLIDSVC_INPROC=0")
target_compile_definitions(msidcrl PRIVATE "-DNO_LOGGING=1")

set_target_properties(msidcrl PROPERTIES
    OUTPUT_NAME "msidcrl"
    PREFIX ""
)

include("${CMAKE_SOURCE_DIR}/cmake/StripSymbols.cmake")
strip_symbols(msidcrl)
include("${CMAKE_SOURCE_DIR}/cmake/SignBinary.cmake")
sign_target(msidcrl ".dll")

add_library(msidcrl40 SHARED
    src/dllmain.cpp
    src/globals.cpp
    src/msidcrl.cpp
    src/test.cpp
    src/util.cpp
)

target_link_libraries(msidcrl40 PRIVATE libwlidsvc wlidshared ole32)

if(CE_BUILD)
target_link_libraries(msidcrl40 PRIVATE toolhelp)
endif()

target_link_options(msidcrl40 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/msidcrl.def)
target_include_directories(msidcrl40 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(msidcrl40 PRIVATE WLIDSVC_INPROC=1)
target_compile_definitions(msidcrl40 PRIVATE "-DNO_LOGGING=1")

set_target_properties(msidcrl40 PROPERTIES
    OUTPUT_NAME "msidcrl40"
    PREFIX ""
)

include("${CMAKE_SOURCE_DIR}/cmake/StripSymbols.cmake")
# strip_symbols(msidcrl40)
include("${CMAKE_SOURCE_DIR}/cmake/SignBinary.cmake")
sign_target(msidcrl40 ".dll")