aux_source_directory(. tool_cpp)
add_library(tool ${tool_cpp})
target_link_libraries(tool bpf)
