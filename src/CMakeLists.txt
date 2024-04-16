add_subdirectory(BPF)
add_subdirectory(tool)
add_subdirectory(graph)
add_subdirectory(model)

add_executable(agith main.cpp)
add_dependencies(agith BPF)
target_link_libraries(agith model)
target_link_libraries(agith tool)
target_link_libraries(agith graph)

add_custom_command(TARGET agith POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:agith> ${PROJECT_BINARY_DIR}/prod/)
