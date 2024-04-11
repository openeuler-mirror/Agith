cmake_minimum_required(VERSION 3.10)
SET(CMAKE_C_COMPILER clang)
SET(CMAKE_CXX_COMPILER clang++)
project(Agith)
set(CMAKE_CXX_STANDARD 14)

set(Agith_VERSION_MAJOR 1)
set(Agith_VERSION_MINOR 0)
set(Agith_VERSION_PATCH 0)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -Wno-delete-non-virtual-dtor -Wno-pointer-arith")

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CmakeScripts)


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

include_directories(include)


file(COPY config/agith.config DESTINATION ${CMAKE_BINARY_DIR}/prod/config)
file(COPY config/syscall_64.tbl DESTINATION ${CMAKE_BINARY_DIR}/prod/config)


add_subdirectory(src)
enable_testing()
add_subdirectory(test)
