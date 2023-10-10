cmake_minimum_required(VERSION 2.8)

project(Agith)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11 -Wall -Wno-delete-non-virtual-dtor -Wno-pointer-arith")

set(Agith_VERSION_MAJOR 1)
set(Agith_VERSION_MINOR 0)
set(Agith_VERSION_PATCH 0)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../config/agith.config DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/config)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../config/syscall_64.tbl DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/config)


include_directories($(CMAKE_CURRENT_SOURCE_DIR)/../include)

add_subdirectory(model)
add_subdirectory(tool)
add_subdirectory(graph)


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

add_executable(agith main.cpp)

target_link_libraries(agith model)
target_link_libraries(agith tool)
target_link_libraries(agith graph)
target_link_libraries(agith Threads::Threads)

add_custom_target(BUILD_BPF_OBJ ALL 
    COMMAND ${CMAKE_MAKE_PROGRAM} OUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR}/BPF
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/BPF/
    COMMENT "Compile bpf kernel program file")