#include "vmlinux.h"
#include "utils.h"
#include "syscall_args.h"
#define bpf_read(val, addr) bpf_probe_read(&val, sizeof(val), &addr);

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_enter_finit_module(struct sys_enter_finit_module_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    struct trace* trace;
    u32 trace_ptr;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_finit_module] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("kprobe/do_init_module")
int kprobe_do_init_module(struct pt_regs* ctx) {
    u64 tgid_pid;
    u32 pid, tgid;
    struct trace* trace;
    u32* trace_ptr;
    int ret;
    u32 syscall_nr = 313;
    struct module* mod;
    char name[56];

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    trace_ptr = get_trace_map_key(pid, syscall_nr);
    if (trace_ptr == NULL) return 0;
    trace = bpf_map_lookup_elem(&trace_map, trace_ptr);
    if (trace == NULL) return 0;

    mod = (struct module*)PT_REGS_PARM1(ctx);
    set_str1(*trace_ptr, mod->name);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_finit_module")
int trace_exit_finit_module(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int trace_enter_delete_module(struct sys_enter_delete_module_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    struct trace* trace;
    u32 trace_ptr;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_delete_module] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    set_str1(trace_ptr, ctx->name);
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_delete_module")
int trace_exit_delete_module(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}
