find_package(BpfObject REQUIRED)

list(APPEND BPF_SOURCES file.c)
list(APPEND BPF_SOURCES map.c)
list(APPEND BPF_SOURCES process.c)
list(APPEND BPF_SOURCES socket.c)
set(BPF_SOURCES ${BPF_SOURCES} PARENT_SCOPE)

foreach(BPF_SOURCE ${BPF_SOURCES})
    get_filename_component(BPF_NAME ${BPF_SOURCE} NAME_WE)
    bpf_object(${BPF_NAME} ${BPF_SOURCE})
endforeach()