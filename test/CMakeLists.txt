add_subdirectory(utils)

find_package(GTest REQUIRED)

aux_source_directory(. TEST_CPP)
add_executable(agith_test ${TEST_CPP})
target_link_libraries(agith_test model)
target_link_libraries(agith_test graph)
target_link_libraries(agith_test test_tool)
target_link_libraries(agith_test tool)
target_link_libraries(agith_test ${GTEST_BOTH_LIBRARIES})
target_include_directories(agith_test PRIVATE ${GTEST_INCLUDE_DIRS})

add_test(NAME agith_test 
    COMMAND sudo ${CMAKE_BINARY_DIR}/test/agith_test
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/prod/)
