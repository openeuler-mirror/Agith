#include "vmlinux.h"
#include "utils.h"
#include "syscall_args.h"

#define bpf_read(val, addr) bpf_probe_read(&val, sizeof(val), &addr);

char LICENSE[] SEC("license") = "GPL";

// SEC("tracepoint/syscalls/sys_enter_pread64")
// int trace_enter_pread64(struct sys_enter_read_write_args* ctx) {
//     u64 tgid_pid;
//     u32 tgid, pid;
//     struct trace* trace;
//     unsigned long i_ino;
//     u32 trace_ptr;
//     int ret;

//     tgid_pid = bpf_get_current_pid_tgid();
//     tgid = tgid_pid >> 32;
//     pid = (u32)tgid_pid;
//     i_ino = get_inode_num(ctx->fd);
//     if (!in_targets(&tgid_target_map, tgid) && !in_targets(&file_target_map, i_ino)) return 0;
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_pread64")
// int trace_exit_pread64(struct sys_exit_args* ctx) {
//     return default_set_ret(ctx);
// }

// SEC("tracepoint/syscalls/sys_enter_pwrite64")
// int trace_enter_pwrite64(struct sys_enter_read_write_args* ctx) {
//     u64 tgid_pid;
//     u32 tgid, pid;
//     struct trace* trace;
//     unsigned long i_ino;
//     u32 trace_ptr;
//     int ret;

//     tgid_pid = bpf_get_current_pid_tgid();
//     tgid = tgid_pid >> 32;
//     pid = (u32)tgid_pid;
//     i_ino = get_inode_num(ctx->fd);
//     if (!in_targets(&tgid_target_map, tgid) && !in_targets(&file_target_map, i_ino)) return 0;

//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_pwrite64")
// int trace_exit_pwrite64(struct sys_exit_args* ctx) {
//     return default_set_ret(ctx);
// }

// file: fd, i_ino
SEC("tracepoint/syscalls/sys_enter_read")
int trace_enter_read(struct sys_enter_read_write_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    struct trace* trace;
    unsigned long i_ino;
    u32 trace_ptr;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;
    i_ino = get_inode_num(ctx->fd);

    if (!in_targets(&tgid_target_map, tgid) && !in_targets(&file_target_map, i_ino)) return 0;

    if (get_repeat_mark(pid, ctx->syscall_nr, i_ino) == REPEAT_TRACE) {
        return 0;
    } else {
        set_repeat_mark(pid, ctx->syscall_nr, i_ino);
    }

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->obj.file.fd = ctx->fd;
    trace->obj.file.i_ino = i_ino;
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_exit_read(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}

// file: fd, i_ino
SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct sys_enter_read_write_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    struct trace* trace;
    unsigned long i_ino;
    u32 trace_ptr;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    i_ino = get_inode_num(ctx->fd);

    if (!in_targets(&tgid_target_map, tgid) && !in_targets(&file_target_map, i_ino)) return 0;

    if (get_repeat_mark(pid, ctx->syscall_nr, i_ino) == REPEAT_TRACE) {
        return 0;
    } else {
        set_repeat_mark(pid, ctx->syscall_nr, i_ino);
    }

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->obj.file.fd = ctx->fd;
    trace->obj.file.i_ino = i_ino;
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_exit_write(struct sys_exit_args* ctx) {
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
    add_file_target(tr->obj.file.i_ino);

    return 0;
}
// TODO:
//   - Add tracepoint methods to symlinkat(266), linkat(265), mount(165), umount(166)

// syscall for command: mv
SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_enter_renameat2(struct sys_enter_renameat2_args* ctx) {
    u64 tgid_pid;
    u32 pid, tgid;
    struct trace* trace;
    u32 trace_ptr;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_execve] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->obj.ops_rename.olddfd = ctx->oldfd;
    trace->obj.ops_rename.newdfd = ctx->newfd;
    set_str1(trace_ptr, ctx->oldname);
    set_str2(trace_ptr, ctx->newname);
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("kprobe/vfs_rename")
int kprobe_vfs_rename(struct pt_regs* ctx) {
    u64 tgid_pid;
    u32 pid, tgid;
    struct trace* trace;
    u32* trace_ptr;
    int ret;
    u32 syscall_nr = 316;
    struct dentry* dentry;
    struct inode* inode;
    u64 i_ino;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;
    trace_ptr = get_trace_map_key(pid, syscall_nr);
    if (trace_ptr == NULL) return 0;
    trace = bpf_map_lookup_elem(&trace_map, trace_ptr);
    if (trace == NULL) return 0;

    dentry = (struct dentry*)PT_REGS_PARM2(ctx);  // old_dentry
    bpf_read(inode, dentry->d_inode);
    bpf_read(i_ino, inode->i_ino);
    trace->obj.ops_rename.old_i_ino = i_ino;

    dentry = (struct dentry*)PT_REGS_PARM4(ctx);  // new_dentry
    bpf_read(inode, dentry->d_inode);
    bpf_read(i_ino, inode->i_ino);
    trace->obj.ops_rename.new_i_ino = i_ino;

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int trace_exit_renameat2(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}

// // syscall for command: chown
// // int fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag);
// // f_state: dfd. ctx->filename
// SEC("tracepoint/syscalls/sys_enter_fchownat")
// int trace_enter_fchownat(struct sys_enter_fchownat_args* ctx) {
//     u64 tgid_pid = bpf_get_current_pid_tgid();
//     u32 tgid = tgid_pid >> 32;
//     if (!in_targets(&tgid_target_map, tgid)) return 0;
//     // return file_state_trace_enter((int)ctx->syscall_nr, 0, -1, ctx->dfd, ctx->filename);
//     return 0;  // depreciate
// }

// // failed to open event chown_common
// SEC("kprobe/chown_common")
// int kprobe_enter_chown_common(struct pt_regs* ctx) {
//     u64 tgid_pid = bpf_get_current_pid_tgid();
//     u32 tgid = tgid_pid >> 32;
//     u32 pid = (u32)tgid_pid;

//     u32 syscall_nr = 260;
//     if (!in_targets(&tgid_target_map, tgid)) return 0;

//     struct path* path = (struct path*)PT_REGS_PARM1(ctx);
//     struct dentry* dentry;
//     struct inode* inode;
//     u64 i_ino;
//     struct tmp_state_map_key state_key;
//     union tmp_state* state;

//     bpf_read(dentry, path->dentry);
//     bpf_read(inode, dentry->d_inode);
//     bpf_read(i_ino, inode->i_ino);

//     state_key.pid = tgid;
//     state_key.syscall_nr = syscall_nr;

//     state = bpf_map_lookup_elem(&tmp_state_map, &state_key);
//     if (state == NULL)
//         return 0;
//     else
//         state->f_state.i_ino = i_ino;
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_fchownat")
// int trace_exit_fchownat(struct sys_exit_args* ctx) {
//     u64 tgid_pid = bpf_get_current_pid_tgid();
//     u32 tgid = tgid_pid >> 32;
//     u32 pid = (u32)tgid_pid;

//     if (!in_targets(&tgid_target_map, tgid)) return 0;
//     return 0;  // depreciate
// }

// syscall for command: chmod
//         int fchmodat(int fd, const char *path, mode_t mode, int flag);
// f_state: dfd. ctx->filename
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_enter_fchmodat(struct sys_enter_fchmodat_args* ctx) {
    u64 tgid_pid;
    u32 pid, tgid;
    struct trace* trace;
    u32 trace_ptr;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;
    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_execve] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->obj.file.dfd = ctx->dfd;
    set_str1(trace_ptr, ctx->filename);
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("kprobe/chmod_common")
int kprobe_enter_chmod_common(struct pt_regs* ctx) {
    u64 tgid_pid;
    u32 pid, tgid;
    struct trace* trace;
    u32* trace_ptr;
    int ret;
    u32 syscall_nr = 268;
    struct path* path;
    struct dentry* dentry;
    struct inode* inode;
    u64 i_ino;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    trace_ptr = get_trace_map_key(pid, syscall_nr);
    if (trace_ptr == NULL) return 0;
    trace = bpf_map_lookup_elem(&trace_map, trace_ptr);
    if (trace == NULL) return 0;

    path = (struct path*)PT_REGS_PARM1(ctx);
    bpf_read(dentry, path->dentry);
    bpf_read(inode, dentry->d_inode);
    bpf_read(i_ino, inode->i_ino);
    trace->obj.file.i_ino = i_ino;

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int trace_exit_fchmodat(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}

// syscall for command: mkdir
//      int mkdir(const char *pathname, mode_t mode);
// f_state: . ctx->filename
SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_enter_mkdir(struct sys_enter_mkdir_args* ctx) {
    u64 tgid_pid;
    u32 pid, tgid;
    struct trace* trace;
    u32 trace_ptr;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_execve] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    set_str1(trace_ptr, ctx->filename);
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

// Only for mkdir(83), need to change implementation if necessary
SEC("kprobe/done_path_create")
int kprobe_enter_done_path_create(struct pt_regs* ctx) {
    u64 tgid_pid;
    u32 pid, tgid;
    struct trace* trace;
    u32* trace_ptr;
    int ret;
    u32 syscall_nr = 83;
    struct dentry* dentry;
    struct inode* inode;
    u64 i_ino;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    trace_ptr = get_trace_map_key(pid, syscall_nr);
    if (trace_ptr == NULL) return 0;
    trace = bpf_map_lookup_elem(&trace_map, trace_ptr);
    if (trace == NULL) return 0;

    dentry = (struct dentry*)PT_REGS_PARM2(ctx);
    bpf_read(inode, dentry->d_inode);
    bpf_read(i_ino, inode->i_ino);
    trace->obj.file.i_ino = i_ino;

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdir")
int trace_exit_mkdir(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}

// syscall for command: rm
//  int unlinkat(int dirfd, const char *pathname, int flags);
// f_state: dfd. ctx->filename
SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_enter_unlink(struct sys_enter_unlink_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_execve] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->obj.file.dfd = AT_FDCWD;
    trace->obj.file.i_ino = 0;
    set_str1(trace_ptr, ctx->filename);
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct sys_enter_unlinkat_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_execve] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->obj.file.dfd = ctx->dfd;
    trace->obj.file.i_ino = 0;
    set_str1(trace_ptr, ctx->filename);
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("kprobe/vfs_rmdir")
int kprobe_vfs_rmdir(struct pt_regs* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32* trace_ptr;
    struct trace* trace;
    int ret;
    u32 syscall_nr = 263;
    struct dentry* dentry;
    struct inode* inode;
    u64 i_ino;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    trace_ptr = get_trace_map_key(pid, syscall_nr);
    if (trace_ptr == NULL) return 0;
    trace = bpf_map_lookup_elem(&trace_map, trace_ptr);
    if (trace == NULL) return 0;

    dentry = (struct dentry*)PT_REGS_PARM2(ctx);  // victum
    bpf_read(inode, dentry->d_inode);
    bpf_read(i_ino, inode->i_ino);
    trace->obj.file.i_ino = i_ino;

    return 0;
}

SEC("kprobe/vfs_unlink")
int kprobe_vfs_unlink(struct pt_regs* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32* trace_ptr;
    struct trace* trace;
    int ret;
    u32 syscall_nr = 263;
    struct dentry* dentry;
    struct inode* inode;
    u64 i_ino;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    trace_ptr = get_trace_map_key(pid, syscall_nr);
    if (trace_ptr == NULL) return 0;
    trace = bpf_map_lookup_elem(&trace_map, trace_ptr);
    if (trace == NULL) return 0;

    dentry = (struct dentry*)PT_REGS_PARM2(ctx);  // victum
    bpf_read(inode, dentry->d_inode);
    bpf_read(i_ino, inode->i_ino);
    trace->obj.file.i_ino = i_ino;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int trace_exit_unlink(struct sys_exit_args* ctx) {
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
    delete_file_target(tr->obj.file.i_ino);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int trace_exit_unlinkat(struct sys_exit_args* ctx) {
    return trace_exit_unlink(ctx);
}

// syscall for command: touch
// utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
// f_state: dfd. ctx->filename
SEC("tracepoint/syscalls/sys_enter_utimensat")
int trace_enter_utimesat(struct sys_enter_utimensat_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;
    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_execve] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->obj.file.dfd = ctx->dfd;
    trace->obj.file.i_ino = 0;
    set_str1(trace_ptr, ctx->filename);
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

// kprobe: utimes_common(const struct path *path, struct timespec64 *times)
// corrsponding to syscall: `utime`, `utimensat`, `utimes`.
// Here to specify syscall_nr 280 (utimensat)
SEC("kprobe/utimes_common")
int kprobe_enter_utimes(struct pt_regs* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32* trace_ptr;
    struct trace* trace;
    int ret;
    u32 syscall_nr = 280;  // usimensat
    struct path* path;
    struct dentry* dentry;
    struct inode* inode;
    u64 i_ino;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    trace_ptr = get_trace_map_key(pid, syscall_nr);
    if (trace_ptr == NULL) return 0;
    trace = bpf_map_lookup_elem(&trace_map, trace_ptr);
    if (trace == NULL) return 0;

    path = (struct path*)PT_REGS_PARM1(ctx);
    bpf_read(dentry, path->dentry);
    bpf_read(inode, dentry->d_inode);
    bpf_read(i_ino, inode->i_ino);
    trace->obj.file.i_ino = i_ino;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_utimensat")
int trace_exit_utimesat(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}

// Maintain opening file, mapping (pid, fd) <-> full filename in userspace
// related syscalls: open, openat, dup2, close
// working dir: pid <-> chdir/fchdir

// trace_ptr. ctx->filename
SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct sys_enter_open_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_execve] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    set_str1(trace_ptr, ctx->filename);
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

// f_state: dfd. ctx->filename
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct sys_enter_openat_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    set_str1(trace_ptr, ctx->filename);
    trace->obj.file.dfd = ctx->dfd;
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
__always_inline int trace_exit_open(struct sys_exit_args* ctx) {
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
    tr->obj.file.fd = ctx->ret;
    tr->obj.file.i_ino = get_inode_num(ctx->ret);
    tr->ret = ctx->ret;
    if (ctx->ret < 0) {
        tr->ready = 2;
    } else {
        tr->ready = 1;
    }
    delete_trace_map_key(pid, ctx->syscall_nr);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct sys_exit_args* ctx) {
    return trace_exit_open(ctx);
}

// TODO: is dup also needed?
// f_state: dfd.
SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_enter_dup2(struct sys_enter_dup2_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_execve] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->obj.ops_dup.oldfd = ctx->oldfd;
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int trace_exit_dup2(struct sys_exit_args* ctx) {
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
    tr->obj.ops_dup.newfd = ctx->ret;
    tr->ready = 1;

    delete_trace_map_key(pid, ctx->syscall_nr);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int trace_enter_fcntl(struct sys_enter_fcntl_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    int ret;

    if (ctx->cmd != 0 && ctx->cmd != 1030) return 0;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;

    if (!in_targets(&tgid_target_map, tgid)) return 0;

    ret = create_trace(&trace, &trace_ptr);
    if (ret) {
        bpf_printk("[sys_enter_execve] get trace map failed");
        return 0;
    }

    trace->tgid = tgid;
    trace->action = ctx->syscall_nr;
    trace->ts = bpf_ktime_get_ns();
    trace->obj.ops_fcntl.cmd = ctx->cmd;
    trace->obj.ops_fcntl.fd = ctx->fd;
    trace->obj.ops_fcntl.i_ino = get_inode_num(ctx->fd);
    set_trace_map_key(pid, ctx->syscall_nr, trace_ptr);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int trace_exit_fcntl(struct sys_exit_args* ctx) {
    return default_set_ret(ctx);
}

// f_state: dfd, i_ino.
SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct sys_enter_close_args* ctx) {
    u64 tgid_pid;
    u32 tgid, pid;
    u32 trace_ptr;
    struct trace* trace;
    unsigned long i_ino;

    tgid_pid = bpf_get_current_pid_tgid();
    tgid = tgid_pid >> 32;
    pid = (u32)tgid_pid;
    i_ino = get_inode_num(ctx->fd);
    if (!in_targets(&tgid_target_map, tgid)) return 0;

    if (get_repeat_mark(pid, ctx->syscall_nr, i_ino) == REPEAT_TRACE) {
        return delete_repeat_mark(pid, ctx->syscall_nr, i_ino);
    }

    return 0;
}

// SEC("tracepoint/syscalls/sys_exit_close")
// int trace_exit_close(struct sys_exit_args* ctx) {
//     return default_set_ret(ctx);
// }
