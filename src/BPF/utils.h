#ifndef __BPF_UTILS_H
#define __BPF_UTILS_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.h"
#include "syscall_args.h"

#ifdef bpf_printk
    #undef bpf_printk
    #define bpf_printk(fmt, ...)                                       \
        ({                                                             \
            char ____fmt[] = fmt;                                      \
            bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
        })
#endif

#define REPEAT_TRACE 1
#define NOT_REPEAT_TRACE 0

static __always_inline int create_trace(struct trace** trace, u32* trace_map_key) {
    u32 processor_id, *trace_ptr;
    processor_id = bpf_get_smp_processor_id();
    trace_ptr = bpf_map_lookup_elem(&trace_ptr_map, &processor_id);
    if (trace_ptr == NULL) {
        return -1;
    }

    *trace_map_key = processor_id * ENTRY_NUM_PER_CPU + *trace_ptr % ENTRY_NUM_PER_CPU;
    *trace_ptr += 1;
    *trace = bpf_map_lookup_elem(&trace_map, trace_map_key);
    if (*trace == NULL) {
        return -1;
    }
    (*trace)->ready = 0;
    return 0;
}

// sgdd
static __always_inline long add_file_target(long i_ino) {
    u32 init_val = 1;
    return bpf_map_update_elem(&file_target_map, &i_ino, &init_val, BPF_NOEXIST);
}

static __always_inline long delete_file_target(long i_ino) {
    return bpf_map_delete_elem(&file_target_map, &i_ino);
}

static __always_inline long add_tgid_target(pid_t tgid) {
    u32 init_val = 1;
    return bpf_map_update_elem(&tgid_target_map, &tgid, &init_val, BPF_NOEXIST);
}

static __always_inline long delete_tgid_target(pid_t tgid) {
    return bpf_map_delete_elem(&tgid_target_map, &tgid);
}

// This function can be used to judge whether a pid is in tgid_target_map,
// although the key of tgid_target_map is 32bit.
static __always_inline bool in_targets(void* map, unsigned long key) {
    u32* value = (u32*)bpf_map_lookup_elem(map, &key);
    return value ? true : false;
}

static __always_inline u32* get_trace_map_key(unsigned int pid, unsigned int syscall_nr) {
    struct pid_syscall_key ps_key;
    ps_key.pid = pid;
    ps_key.syscall_nr = syscall_nr;
    return bpf_map_lookup_elem(&used_trace_map, &ps_key);
}

static __always_inline long set_trace_map_key(unsigned int pid, int syscall_nr, u32 value) {
    struct pid_syscall_key ps_key;
    ps_key.pid = pid;
    ps_key.syscall_nr = syscall_nr;

    return bpf_map_update_elem(&used_trace_map, &ps_key, &value, BPF_NOEXIST);
}

static __always_inline int delete_trace_map_key(unsigned int pid, int syscall_nr) {
    struct pid_syscall_key ps_key;
    ps_key.pid = pid;
    ps_key.syscall_nr = syscall_nr;

    return bpf_map_delete_elem(&used_trace_map, &ps_key);
}

static __always_inline long set_str1(unsigned int trace_ptr, const char* value) {
    char* buf;
    buf = bpf_map_lookup_elem(&str1_map, &trace_ptr);
    if (buf == NULL) return -1;
    return bpf_probe_read_str(buf, STR_BUF_SIZE, value);
}

static __always_inline long set_str2(unsigned int trace_ptr, const char* value) {
    char* buf;
    buf = bpf_map_lookup_elem(&str2_map, &trace_ptr);
    if (buf == NULL) return -1;
    return bpf_probe_read_str(buf, STR_BUF_SIZE, value);
}

static __always_inline long set_str3(unsigned int trace_ptr, const char* value) {
    char* buf;
    buf = bpf_map_lookup_elem(&str3_map, &trace_ptr);
    if (buf == NULL) return -1;
    return bpf_probe_read_str(buf, STR_BUF_SIZE, value);
}

static __always_inline int default_set_ret(struct sys_exit_args* ctx) {
    u64 tgid_pid;
    u32 pid, tgid;
    struct trace* tr;
    u32* trace_ptr;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    pid = (u32)tgid_pid;
    tgid = tgid_pid >> 32;

    trace_ptr = get_trace_map_key(pid, ctx->syscall_nr);
    if (trace_ptr == NULL) {
        return 0;
    }

    tr = bpf_map_lookup_elem(&trace_map, trace_ptr);
    if (tr == NULL) {
        return 0;
    }
    tr->ret = ctx->ret;
    tr->ready = 1;

    delete_trace_map_key(pid, ctx->syscall_nr);
    return 0;
}

static __always_inline unsigned long get_inode_num(int fd) {
    unsigned long i_ino;
    // struct files_struct* files;
    struct file **fd_array, *target_file;
    // struct inode* inode;
    struct fdtable* fdt;
    unsigned int max_fds;
    int err;

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    err = BPF_CORE_READ_INTO(&max_fds, task, files, fdt, max_fds);
    // bpf_probe_read(&files, sizeof(files), &(task->files));
    // bpf_probe_read(&fdt, sizeof(fdt), &(files->fdt));
    // bpf_probe_read(&max_fds, sizeof(max_fds), &fdt->max_fds);

    if (max_fds <= fd || err) {
        return 0;
    }
    err = BPF_CORE_READ_INTO(&fd_array, task, files, fdt, fd);
    err = bpf_core_read(&target_file, sizeof(target_file), &fd_array[fd]);
    err = BPF_CORE_READ_INTO(&i_ino, target_file, f_inode, i_ino);

    // bpf_probe_read(&fd_array, sizeof(fd_array), &(fdt->fd));
    // bpf_probe_read(&target_file, sizeof(target_file), &fd_array[fd]);
    // bpf_probe_read(&inode, sizeof(inode), &target_file->f_inode);
    // bpf_probe_read(&i_ino, sizeof(i_ino), &inode->i_ino);

    return i_ino;
}

// judge whether syscall is repeated
static __always_inline int set_repeat_mark(u32 pid, long syscall, unsigned long obj) {
    struct pid_syscall_obj_key rw_key;
    rw_key.pid = pid;
    rw_key.obj = obj;
    rw_key.syscall_nr = syscall;
    return bpf_map_update_elem(&repeat_trace_map, &rw_key, &pid, BPF_ANY);
}

static __always_inline int get_repeat_mark(u32 pid, long syscall, unsigned long obj) {
    struct pid_syscall_obj_key rw_key;
    int* rw_value;

    rw_key.pid = pid;
    rw_key.obj = obj;
    rw_key.syscall_nr = syscall;
    rw_value = bpf_map_lookup_elem(&repeat_trace_map, &rw_key);
    if (rw_value != NULL) {
        return REPEAT_TRACE;
    } else {
        return NOT_REPEAT_TRACE;
    }
}

static __always_inline int delete_repeat_mark(u32 pid, long syscall, unsigned long obj) {
    struct pid_syscall_obj_key rw_key;
    rw_key.pid = pid;
    rw_key.obj = obj;
    rw_key.syscall_nr = syscall;
    return bpf_map_delete_elem(&repeat_trace_map, &rw_key);
}

#endif