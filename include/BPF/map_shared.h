#ifndef __MAP_SHARED_H
#define __MAP_SHARED_H

#define STR_BUF_SIZE 128
#define MAX_ARG 15
#define MAX_ARG_LENGTH 512

#ifndef CPU_NUM
    #define CPU_NUM 16
#endif

#ifndef NULL
    #define NULL ((void*)0)
#endif
#define ENTRY_NUM_PER_CPU 320

union object {
    // object for clone()
    unsigned int tgid;

    // object for file Info (dfd & fd & i_ino).
    struct file_info {
        unsigned long i_ino;
        unsigned long dfd;
        unsigned long fd;
        struct dentry* dentry;
    } file;

    struct socket_ops {
        unsigned long family;
        unsigned long type;
        unsigned long protocol;
    } ops_socket;

    struct connect_ops {
        unsigned long fd;
        unsigned char addr[16];
    } ops_connect;

    struct recv_ops {
        unsigned long fd;
        unsigned long len;
        char* buf;
    } ops_recv;

    struct send_ops {
        unsigned long fd;
        unsigned long len;
    } ops_send;

    // object for file dup2()
    struct dup_ops {
        unsigned long oldfd;
        unsigned long newfd;
    } ops_dup;

    struct rename_ops {
        unsigned long olddfd;
        unsigned long newdfd;
        unsigned long old_i_ino;
        unsigned long new_i_ino;
    } ops_rename;

    struct fcntl_ops {
        unsigned long i_ino;
        unsigned long fd;
        unsigned long cmd;
    } ops_fcntl;

    struct copy_file_rang_ops {
        unsigned long i_ino_in;
        unsigned long i_ino_out;
        unsigned long fd_in;
        unsigned long fd_out;

    } ops_copy_file_range;
};

struct pid_syscall_key {
    unsigned int pid;
    unsigned int syscall_nr;
};

struct pid_syscall_obj_key {
    unsigned int pid;
    long syscall_nr;
    unsigned long obj;
};

#endif