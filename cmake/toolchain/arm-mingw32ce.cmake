set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(TOOLCHAIN_PREFIX arm-mingw32ce)

set(ADDITIONAL_LINK_ARGS "-Wl,--subsystem,wince:7.10")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv7-a+fp -D_WIN32_WINNT=0x0502 -DUNICODE -Wl,--enable-auto-import -fstack-protector-strong -ffunction-sections -Wl,--gc-sections ${ADDITIONAL_LINK_ARGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv7-a+fp -D_WIN32_WINNT=0x0502 -DUNICODE -Wl,--enable-auto-import -fstack-protector-strong -fno-exceptions -fno-rtti -ffunction-sections -Wl,--gc-sections ${ADDITIONAL_LINK_ARGS}")

set(CMAKE_INSTALL_PREFIX /opt/cegcc/arm-mingw32ce)

set(CMAKE_C_STANDARD_LIBRARIES "")
set(CMAKE_CXX_STANDARD_LIBRARIES "")
set(CMAKE_REQUIRED_LIBRARIES "coredll")

set(CE_BUILD 1)

# enforce -Os, we need the memory footprint to be as small as possible
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os")

set(CMAKE_FIND_LIBRARY_SUFFIXES .a .dll.a)
set(CMAKE_STATIC_LIBRARY_PREFIX "lib")
set(CMAKE_STATIC_LIBRARY_SUFFIX ".a")
set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll.a") 

set(CMAKE_FIND_ROOT_PATH /opt/cegcc/arm-mingw32ce)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)