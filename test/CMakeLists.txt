aux_source_directory(. TABBYLIC_TEST_FILES)
aux_source_directory(../src TABBYLIC_SRC_FILES)
list(FILTER TABBYLIC_SRC_FILES EXCLUDE REGEX ".*main.cpp$")

add_executable(tests ${TABBYLIC_TEST_FILES} ${TABBYLIC_SRC_FILES})
target_include_directories(tests PRIVATE Catch2::Catch2 ../src/include)
target_link_libraries(tests PRIVATE Catch2::Catch2 OpenPGP_static)
set_target_properties(tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})
if(CODE_COVERAGE)
    include(CodeCoverage.cmake)
    append_coverage_compiler_flags()
    setup_target_for_coverage_lcov(NAME coverage 
        EXECUTABLE ${CMAKE_SOURCE_DIR}/tests 
        BASE_DIRECTORY ../coverage
        EXCLUDE "/usr/*" "../_deps/*" "../test/*"
        )
endif()
