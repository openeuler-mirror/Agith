#ifndef __SYSCALL_ARGS_H
#define __SYSCALL_ARGS_H

struct sys_enter_read_write_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long fd;
    char* buf;
    unsigned long count;
};

struct sys_enter_renameat2_args {
    unsigned long long unused;
    long syscall_nr;

    unsigned long oldfd;
    char* oldname;
    unsigned long newfd;
    char* newname;
    unsigned long flags;
};

struct sys_enter_fchownat_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long dfd;
    char* filename;
    unsigned long user;
    unsigned long group;
    unsigned long flag;
};

struct sys_enter_fchmodat_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long dfd;
    char* filename;
    unsigned long mode;
};

struct sys_enter_mkdir_args {
    unsigned long long unused;
    long syscall_nr;
    char* filename;
    unsigned long mode;
};

struct sys_enter_unlinkat_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long dfd;
    char* filename;
    unsigned long flags;
};

struct sys_enter_unlink_args {
    unsigned long long unused;
    long syscall_nr;
    char* filename;
};

struct sys_enter_utimensat_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long dfd;
    char* filename;
    struct timespec* utimes;
    unsigned long flags;
};

// structs for maintain (pid, fd) -> filename
struct sys_enter_open_args {
    unsigned long long unused;
    long syscall_nr;
    char* filename;
    unsigned long flags;
    unsigned long mode;
};

struct sys_enter_openat_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long dfd;
    char* filename;
    unsigned long flags;
    unsigned long mode;
};

struct sys_enter_dup2_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long oldfd;
    unsigned long newfd;
};

struct sys_enter_copy_file_range_args
{
    unsigned long long unused;
    long syscall_nr;
    unsigned long fd_in;
    loff_t * off_in;
    unsigned long fd_out;
    loff_t * off_out;
    unsigned long len;
    unsigned long flags;
};

struct sys_enter_fcntl_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long fd;
    unsigned long cmd;
    unsigned long arg;
};

struct sys_enter_close_args {
    unsigned long long unused;
    // sgdd
    long syscall_nr;
    unsigned long fd;
};

struct sys_enter_recvfrom_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long fd;
    void* buff;
    unsigned long len;
    unsigned long flags;
    struct sockaddr* addr;
    int* addr_len;
};

struct sys_enter_sendto_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long fd;
    void* buff;
    unsigned long len;
    unsigned long flags;
    struct sockaddr* addr;
    unsigned long addr_len;
};

struct sys_enter_connect_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long fd;
    struct sockaddr* addr;
    unsigned long addrlen;
};

struct sys_enter_execve_args {
    unsigned long long unused;
    long syscall_nr;
    const char* filename;
    const char* const* argv;
    const char* const* envp;
};

struct sys_enter_chdir_args {
    unsigned long long unused;
    long syscall_nr;
    const char* filename;
};

struct sys_exit_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

struct sys_enter_socket_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long family;
    unsigned long type;
    unsigned long protocol;
};

struct sys_enter_writev_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long fd;
    struct iovec * vec;
    unsigned long vlen;
};

struct sys_enter_delete_module_args {
    unsigned long long unused;
    long syscall_nr;
    const char * name;
    unsigned int flags;
};

struct sys_enter_finit_module_args
{
    unsigned long long unused;
    long syscall_nr;
    const char* uargs;
    unsigned int flags;
};


struct sys_enter_exit_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long error_code;
};

#endif