file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../config/agith.config DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/config)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../config/syscall_64.tbl DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/config)

include_directories($(CMAKE_CURRENT_SOURCE_DIR)/../include)


add_subdirectory(utils)


find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

aux_source_directory(. TEST_CPP)
add_executable(agith_test ${TEST_CPP})

target_link_libraries(agith_test model)
target_link_libraries(agith_test graph)
target_link_libraries(agith_test test_tool)
target_link_libraries(agith_test tool)
target_link_libraries(agith_test Threads::Threads)
target_link_libraries(agith_test ${GTEST_BOTH_LIBRARIES})
target_link_libraries(agith_test ${CMAKE_THREAD_LIBS_INIT})

add_test(NAME Test 
    COMMAND sudo ${CMAKE_BINARY_DIR}/test/agith_test
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src)

# add_custom_target(BUILD_BPF_OBJ ALL 
#     COMMAND ${CMAKE_MAKE_PROGRAM} OUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR}/BPF
#     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../src/BPF/
#     COMMENT "Compile bpf kernel program file")