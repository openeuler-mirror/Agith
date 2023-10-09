#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "utils.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct sys_enter_connect_args* ctx) {
    pid_t pid, tgid;
    int ret;
    struct trace* tr;
    u32 trace_ptr;

    u64 tgid_pid = bpf_get_current_pid_tgid();
    pid = (u32)tgid_pid;
    tgid = tgid_pid >> 32;
    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&tr, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_connect] get trace map failed");
        return 0;
    }

    tr->tgid = tgid;
    tr->action = ctx->syscall_nr;
    tr->ts = bpf_ktime_get_ns();
    tr->obj.ops_connect.fd = ctx->fd;
    bpf_probe_read(&(tr->obj.ops_connect.addr), sizeof(struct sockaddr), ctx->addr);

    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_exit_connect(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_enter_recvfrom(struct sys_enter_recvfrom_args* ctx) {
    pid_t pid, tgid;
    struct trace* tr;
    u32 trace_ptr;
    int ret;
    unsigned long i_ino;

    u64 tgid_pid = bpf_get_current_pid_tgid();
    pid = (u32)tgid_pid;
    tgid = tgid_pid >> 32;
    if (!in_targets(&tgid_target_map, tgid)) return 0;

    i_ino = get_inode_num(ctx->fd);
    if (get_repeat_mark(pid, ctx->syscall_nr, i_ino) == REPEAT_TRACE) {
        return 0;
    } else {
        set_repeat_mark(pid, ctx->syscall_nr, i_ino);
    }

    ret = create_trace(&tr, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_recvfrom] get trace map failed");
        return 0;
    }

    tr->tgid = tgid;
    tr->action = ctx->syscall_nr;
    tr->ts = bpf_ktime_get_ns();
    tr->obj.ops_recv.fd = ctx->fd;
    tr->obj.ops_recv.len = ctx->len;
    tr->obj.ops_recv.buf = ctx->buff;

    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_exit_recvfrom(struct sys_exit_args* ctx) {
    pid_t pid, tgid;
    struct trace* tr;
    u32* trace_ptr;
    int ret;

    u64 tgid_pid = bpf_get_current_pid_tgid();
    pid = (u32)tgid_pid;
    tgid = tgid_pid >> 32;
    trace_ptr = get_trace_map_key(pid, ctx->syscall_nr);
    if (trace_ptr == NULL) {
        return -1;
    }

    tr = bpf_map_lookup_elem(&trace_map, trace_ptr);
    if (tr == NULL) {
        return -1;
    }

    tr->ret = ctx->ret;
    set_str1(*trace_ptr, tr->obj.ops_recv.buf);
    tr->ready = 1;

    delete_trace_map_key(pid, ctx->syscall_nr);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_enter_sendto(struct sys_enter_sendto_args* ctx) {
    pid_t pid, tgid;
    struct trace* tr;
    u32 trace_ptr;
    int ret;
    unsigned long i_ino;

    u64 tgid_pid = bpf_get_current_pid_tgid();
    pid = (u32)tgid_pid;
    tgid = tgid_pid >> 32;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    i_ino = get_inode_num(ctx->fd);
    if (get_repeat_mark(pid, ctx->syscall_nr, i_ino) == REPEAT_TRACE) {
        return 0;
    } else {
        set_repeat_mark(pid, ctx->syscall_nr, i_ino);
    }

    ret = create_trace(&tr, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_sendto] get trace map failed");
        return 0;
    }

    tr->tgid = tgid;
    tr->action = ctx->syscall_nr;
    tr->ts = bpf_ktime_get_ns();
    tr->obj.ops_send.fd = ctx->fd;
    tr->obj.ops_send.len = ctx->len;
    set_str1(trace_ptr, ctx->buff);

    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_exit_sendto(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}
