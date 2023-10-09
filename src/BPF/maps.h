#ifndef __MAPS_H
#define __MAPS_H

#include <bpf/bpf_helpers.h>
#include "BPF/map_shared.h"

/* flags for BPF_MAP_UPDATE_ELEM command */
#define BPF_ANY 0     /* create new element or update existing */
#define BPF_NOEXIST 1 /* create new element if it didn't exist */
#define BPF_EXIST 2   /* update existing element */

// definition of AT_FDCWD
#define AT_FDCWD -100

#define MAX_PID_NUM 1024

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_PARM6(x) ((x)->r9)

struct trace {
    unsigned int tgid;
    unsigned int action;  // system call number
    unsigned long ts;
    union object obj;
    long ret;
    int ready;  // // 0: empty or writing; 1: readable; 2: useless
};

struct bpf_map_def SEC("maps") trace_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct trace),
    .max_entries = CPU_NUM * ENTRY_NUM_PER_CPU,
};

struct bpf_map_def SEC("maps") trace_ptr_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = CPU_NUM,
};

struct bpf_map_def SEC("maps") tgid_target_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(pid_t),
    .value_size = sizeof(u32),
    .max_entries = MAX_PID_NUM,
};

struct bpf_map_def SEC("maps") file_target_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(long),
    .value_size = sizeof(u32),
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps") used_trace_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct pid_syscall_key),
    .value_size = sizeof(u32),
    .max_entries = MAX_PID_NUM,
};

struct bpf_map_def SEC("maps") str1_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(char) * STR_BUF_SIZE,
    .max_entries = CPU_NUM * ENTRY_NUM_PER_CPU,
};

struct bpf_map_def SEC("maps") str2_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(char) * STR_BUF_SIZE,
    .max_entries = CPU_NUM * ENTRY_NUM_PER_CPU,
};

struct bpf_map_def SEC("maps") str3_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(char) * STR_BUF_SIZE,
    .max_entries = CPU_NUM * ENTRY_NUM_PER_CPU,
};

struct bpf_map_def SEC("maps") repeat_trace_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct pid_syscall_obj_key),
    .value_size = sizeof(int),
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps") perf_event_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(unsigned int),
    .max_entries = CPU_NUM,
};

#endif
