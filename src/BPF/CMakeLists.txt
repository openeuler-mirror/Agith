find_package(BpfObject REQUIRED)

list(APPEND BPF_SOURCES file.c)
list(APPEND BPF_SOURCES map.c)
list(APPEND BPF_SOURCES process.c)
list(APPEND BPF_SOURCES socket.c)
set(BPF_SOURCES ${BPF_SOURCES} PARENT_SCOPE)

foreach(BPF_SOURCE ${BPF_SOURCES})
    get_filename_component(BPF_NAME ${BPF_SOURCE} NAME_WE)
    bpf_object(${BPF_NAME} ${BPF_SOURCE})
    list(APPEND BPF_TARGETS ${BPF_NAME})
    list(APPEND BPF_OUTPUTS $<TARGET_OBJECTS:${BPF_NAME}>)
endforeach()

set(COUNTER 0)
add_custom_target(BPF DEPENDS ${BPF_TARGETS})
foreach(BPF_TARGET ${BPF_TARGETS})
    list(GET BPF_OUTPUTS ${COUNTER} OBJECT_FILE)
    add_custom_command(
        TARGET BPF POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${OBJECT_FILE} ${PROJECT_BINARY_DIR}/prod/BPF/${BPF_TARGET}.o)
    math(EXPR COUNTER "${COUNTER} + 1")
endforeach()