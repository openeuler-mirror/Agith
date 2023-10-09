#include "vmlinux.h"
#include "utils.h"
#include "syscall_args.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_exit_clone")  // _do_fork
int trace_exit_clone(struct sys_exit_args* ctx) {
    struct task_struct *current, *parent;
    u32 father_tgid, cur_tgid;
    u8 value;
    u32 trace_ptr;
    struct trace* trace;
    int ret;
    u32 processor_id;

    // we only care clone() calls returned in the child
    // process' conext
    if (ctx->ret != 0) return 0;

    current = (struct task_struct*)bpf_get_current_task();

    bpf_probe_read(&parent, sizeof(parent), &(current->parent));
    bpf_probe_read(&father_tgid, sizeof(father_tgid), &(parent->tgid));

    // if father tgid is not a tracing target, stop processing and return
    if (!in_targets(&tgid_target_map, father_tgid)) return 0;

    // updating target_tgid map
    bpf_probe_read(&cur_tgid, sizeof(cur_tgid), &(current->tgid));
    value = 1;
    bpf_map_update_elem(&tgid_target_map, &cur_tgid, &value, BPF_NOEXIST);

    // generating trace
    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_exit_clone] get trace map failed");
        return 0;
    }
    trace->tgid = father_tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->obj.tgid = cur_tgid;
    trace->ret = ctx->ret;
    trace->ready = 1;

    processor_id = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &perf_event_map, processor_id, &processor_id, sizeof(u32));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int trace_enter_exit(struct sys_enter_exit_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    // We assume that if the leader of a thread group exits, the
    // whole thread group terminates.
    if (tgid != pid) return 0;

    bpf_map_delete_elem(&tgid_target_map, &tgid);

    // generating trace
    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_exit] get trace map failed");
        return 0;
    }
    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->ready = 1;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int trace_enter_exit_group(struct sys_enter_exit_args* ctx) {
    u32 tgid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;

    tgid = bpf_get_current_pid_tgid() >> 32;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    bpf_map_delete_elem(&tgid_target_map, &tgid);

    // generating trace
    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_exit_group] get trace map failed");
        return 0;
    }
    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->ready = 1;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct sys_enter_execve_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;
    const char* envp;
    const char* argv;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    // if current process is not a tracing target, stop
    // processing and return
    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_execve] get trace map failed");
        return 0;
    }

    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    set_str1(trace_ptr, ctx->filename);
    ret = bpf_probe_read(&argv, sizeof(argv), &ctx->argv[1]);
    if (ret) {
        return 0;
    }
    set_str2(trace_ptr, argv);

    ret = bpf_probe_read(&argv, sizeof(argv), &ctx->argv[2]);
    if (ret) {
        return 0;
    }
    set_str3(trace_ptr, argv);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int trace_enter_chdir(struct sys_enter_chdir_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    // if current process is not a tracing target, stop
    // processing and return
    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_chdir] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    set_str1(trace_ptr, ctx->filename);
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int trace_exit_chdir(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}