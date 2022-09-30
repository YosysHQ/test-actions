cmake_minimum_required(VERSION 3.6.0)
project(OpenPGP LANGUAGES CXX C)

option(BUILD_TESTS "Build tests" OFF)

# require C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(CODE_COVERAGE "Collect coverage from test library" OFF)

add_library(preload SHARED lib/preload.c)
set_target_properties(preload PROPERTIES PREFIX "")
set_target_properties(preload PROPERTIES SUFFIX ".o")
target_link_libraries(preload dl)
set_target_properties(preload PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})
install(TARGETS preload DESTINATION lib)

# GMP is not a built-in module, so it needs FindGMP.cmake to be available
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/3rdparty/OpenPGP/contrib/cmake)

# GNU Multiple Precision Arithmetic Library
find_package(GMP 5.0.0 REQUIRED)
message(STATUS "GMP headers:        ${GMP_INCLUDES}")
message(STATUS "GMP libraries:      ${GMP_LIBRARIES}")
include_directories(SYSTEM ${GMP_INCLUDES})
link_libraries     (${GMP_LIBRARIES})

# BZip2
find_package(BZip2 1.0.6 REQUIRED)
message(STATUS "BZip2 headers:      ${BZIP2_INCLUDE_DIR}")
message(STATUS "BZip2 libraries:    ${BZIP2_LIBRARIES}")
include_directories(SYSTEM ${BZIP2_INCLUDE_DIR})
link_libraries     (${BZIP2_LIBRARIES})

# zlib
find_package(ZLIB 1.2.8 REQUIRED)
message(STATUS "zlib headers:       ${ZLIB_INCLUDE_DIR}")
message(STATUS "zlib libraries:     ${ZLIB_LIBRARIES}")
include_directories(SYSTEM ${ZLIB_INCLUDE_DIR})
link_libraries     (${ZLIB_LIBRARIES})

find_package(CURL 7.0.0 REQUIRED)
message(STATUS "curl headers:       ${CURL_INCLUDE_DIR}")
message(STATUS "curl libraries:     ${CURL_LIBRARIES}")
include_directories(SYSTEM ${CURL_INCLUDE_DIR})
link_libraries     (${CURL_LIBRARIES})

# -Iinclude
include_directories(3rdparty/OpenPGP/include)

# add library directories
add_subdirectory(3rdparty/OpenPGP/include ${CMAKE_CURRENT_BINARY_DIR}/generated/OpenPGP/include)
add_subdirectory(3rdparty/OpenPGP/src ${CMAKE_CURRENT_BINARY_DIR}/generated/OpenPGP/src)

# build the static library
add_library(OpenPGP_static STATIC
    $<TARGET_OBJECTS:TopLevel>
    $<TARGET_OBJECTS:common>
    $<TARGET_OBJECTS:Compress>
    $<TARGET_OBJECTS:Encryptions>
    $<TARGET_OBJECTS:Hashes>
    $<TARGET_OBJECTS:HashAlgs>
    $<TARGET_OBJECTS:Misc>
    $<TARGET_OBJECTS:Packets>
    $<TARGET_OBJECTS:PKA>
    $<TARGET_OBJECTS:RNG>
    $<TARGET_OBJECTS:Tag2Subpackets>
    $<TARGET_OBJECTS:Tag17Subpackets>
)
set_target_properties(OpenPGP_static PROPERTIES OUTPUT_NAME "OpenPGP")
install(TARGETS OpenPGP_static DESTINATION lib)

add_subdirectory(src ${CMAKE_CURRENT_BINARY_DIR}/generated/src)
add_subdirectory(lib ${CMAKE_CURRENT_BINARY_DIR}/generated/lib)

if (BUILD_TESTS)
    Include(FetchContent)

    FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v2.13.6)

    FetchContent_MakeAvailable(Catch2)

    add_subdirectory(test ${CMAKE_CURRENT_BINARY_DIR}/generated/test)
endif()