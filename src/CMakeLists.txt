cmake_minimum_required(VERSION 3.6.0)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
aux_source_directory(. TABBYLIC_SRC_FILES)
file(GLOB_RECURSE TABBYLIC_INCLUDE_FILES "include/*.h*")

list(FILTER TABBYLIC_SRC_FILES EXCLUDE REGEX ".*main.cpp$")
add_library(license STATIC ${TABBYLIC_SRC_FILES})
target_include_directories(license PUBLIC include)
string( TIMESTAMP BUILD_TIME "%s" UTC)
message( STATUS "BUILD_TIME = ${BUILD_TIME}" )
target_compile_definitions(license PRIVATE -DYOSYSHQ_RELEASE=${BUILD_TIME})
set_target_properties(license PROPERTIES OUTPUT_NAME "license")
set_target_properties(license PROPERTIES PUBLIC_HEADER "${TABBYLIC_INCLUDE_FILES}" )
install(TARGETS license DESTINATION lib PUBLIC_HEADER DESTINATION include)
add_executable(tabbylic main.cpp)
target_link_libraries(tabbylic OpenPGP_static license )
if(WIN32)
  target_link_libraries(tabbylic iphlpapi ws2_32)
endif()
set_target_properties(tabbylic PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})
install(TARGETS tabbylic DESTINATION bin)

#Add a dummy target that removes the CMake variable BUILD_TIME from CMake's cache.
#this forces CMake to be-rerun when we hit this target.
add_custom_target(
	clear_cache
	COMMAND ${CMAKE_COMMAND} -U BUILD_TIME ${CMAKE_BINARY_DIR}
)

add_dependencies(license clear_cache)