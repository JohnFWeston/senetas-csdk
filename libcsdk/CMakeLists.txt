cmake_minimum_required (VERSION 3.6)

project(libcsdk C ASM)
set(CSDK_VERSION_TEXT "0.0.4")
set(CSDK_COMPILE_BUILD_TARGET "${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_HOST_SYSTEM}")

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR
   CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64")
    set(ARCH "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
    # cmake reports AMD64 on Windows, but we might be building for 32-bit.
    if(CMAKE_CL_64)
        set(ARCH "x86_64")
    else()
        set(ARCH "x86")
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86" OR
       CMAKE_SYSTEM_PROCESSOR STREQUAL "i386" OR
       CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
    set(ARCH "x86")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64" OR
       CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(ARCH "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "armhf")
    set(ARCH "armhf")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(ARCH "arm")
else()
    message(FATAL_ERROR "Unknown or unsupported processor: " ${CMAKE_SYSTEM_PROCESSOR})
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(WIN32)
    set(CMAKE_GENERATOR_CC cl)
endif()
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR
   CMAKE_C_COMPILER_ID STREQUAL "Clang" OR
   CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wstrict-prototypes -Wshadow -Wformat-security -Wwrite-strings")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g -Wno-unused-variable -fno-omit-frame-pointer -march=${ENGARCH}")
    message(STATUS "Using C_FLAGS: " ${CMAKE_C_FLAGS})
endif()
if(CMAKE_C_COMPILER_ID STREQUAL "Clang" OR
   CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fcolor-diagnostics -Wno-missing-braces")
endif()


if(NOT DEFINED OPENSSL_ROOT_DIR)
    if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Darwin")
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@1.1")
    elseif(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
        set(OPENSSL_ROOT_DIR "/usr")
    endif()
endif()
find_package(OpenSSL 1.1.1 REQUIRED)
add_subdirectory(src)
add_subdirectory(tests)

