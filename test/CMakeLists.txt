cmake_minimum_required(VERSION 2.8)

project(Agith_Test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11 -Wall -Wno-delete-non-virtual-dtor -Wno-pointer-arith -Wno-format-truncation -DDEBUG")

set(Agith_VERSION_MAJOR 1)
set(Agith_VERSION_MINOR 0)
set(Agith_VERSION_PATCH 0)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../config/agith.config DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/config)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../config/syscall_64.tbl DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/config)

include_directories($(CMAKE_CURRENT_SOURCE_DIR)/../include)

add_subdirectory(../src/model model)
add_subdirectory(../src/tool tool)
add_subdirectory(../src/graph graph)
add_subdirectory(utils)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(JSONCPP jsoncpp)
if (JSONCPP_FOUND)
    link_libraries(${JSONCPP_LIBRARIES})
    message(STATUS "found library:${JSONCPP_LIBRARIES}")
else ()
    message(STATUS "can't find jsoncpp")
endif ()

pkg_check_modules(LOG4CPLUS log4cplus)
if (LOG4CPLUS_FOUND)
    link_libraries(${LOG4CPLUS_LIBRARIES})
    message(STATUS "found library:${LOG4CPLUS_LIBRARIES}")
else ()
    message(STATUS "can't find log4cplus")
endif ()

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

add_test(Test agith_test)
enable_testing()

add_custom_target(BUILD_BPF_OBJ ALL 
    COMMAND ${CMAKE_MAKE_PROGRAM} OUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR}/BPF
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../src/BPF/
    COMMENT "Compile bpf kernel program file")