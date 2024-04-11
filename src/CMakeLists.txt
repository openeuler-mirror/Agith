add_subdirectory(BPF)
add_subdirectory(tool)
add_subdirectory(graph)
add_subdirectory(model)

add_executable(agith main.cpp)
target_link_libraries(agith model)
target_link_libraries(agith tool)
target_link_libraries(agith graph)

add_custom_command(TARGET agith POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:agith> ${PROJECT_BINARY_DIR}/prod/)

foreach(BPF_SOURCE ${BPF_SOURCES})
    get_filename_component(BPF_NAME ${BPF_SOURCE} NAME_WE)
    add_dependencies(agith ${BPF_NAME})
    if (NOT EXISTS ${PROJECT_BINARY_DIR}/prod/BPF)
        make_directory(${PROJECT_BINARY_DIR}/prod/BPF)
    endif()
    add_custom_command(TARGET agith POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:${BPF_NAME}> ${PROJECT_BINARY_DIR}/prod/BPF/${BPF_NAME}.o)
endforeach()
