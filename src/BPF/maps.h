#ifndef __MAPS_H
#define __MAPS_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "BPF/map_shared.h"
#include "vmlinux.h"

/* flags for BPF_MAP_UPDATE_ELEM command */
#define BPF_ANY 0     /* create new element or update existing */
#define BPF_NOEXIST 1 /* create new element if it didn't exist */
#define BPF_EXIST 2   /* update existing element */

// definition of AT_FDCWD
#define AT_FDCWD -100

#define MAX_PID_NUM 1024

struct trace {
    unsigned int tgid;
    unsigned int action;  // system call number
    unsigned long ts;
    union object obj;
    long ret;
    int ready;  // // 0: empty or writing; 1: readable; 2: useless
};

struct str_buf {
    char buf[STR_BUF_SIZE];
};

struct cmd_args {
    char cmd_str[MAX_ARG_LENGTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CPU_NUM * ENTRY_NUM_PER_CPU);
    __type(key, u32);
    __type(value, struct trace);
} trace_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CPU_NUM);
    __type(key, u32);
    __type(value, u32);
} trace_ptr_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PID_NUM);
    __type(key, pid_t);
    __type(value, u32);
} tgid_target_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PID_NUM);
    __type(key, long);
    __type(value, u32);
} file_target_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PID_NUM);
    __type(key, struct pid_syscall_key);
    __type(value, u32);
} used_trace_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CPU_NUM * ENTRY_NUM_PER_CPU);
    __type(key, int);
    __type(value, struct str_buf);
} str1_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CPU_NUM * ENTRY_NUM_PER_CPU);
    __type(key, int);
    __type(value, struct cmd_args);
} str2_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PID_NUM);
    __type(key, struct pid_syscall_obj_key);
    __type(value, int);
} repeat_trace_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, CPU_NUM);
    __type(key, unsigned int);
    __type(value, unsigned int);
} perf_event_map SEC(".maps");


#endif
