#ifndef __MAP_USER_H
#define __MAP_USER_H

#include <string>
#include <vector>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include "tool/Manual.h"
#include "BPF/map_shared.h"

#define PID_TARGET_MAP "tgid_target_map"
#define FILE_TARGET_MAP "file_target_map"
#define TRACE_MAP "trace_map"
#define TRACE_PTR_MAP "trace_ptr_map"
#define STR1_MAP "str1_map"
#define STR2_MAP "str2_map"
#define STR3_MAP "str3_map"
#define PERF_EVENT_MAP "perf_event_map"
#define REPEAT_TRACE_MAP "repeat_trace_map"

struct Trace {
    unsigned int tgid;
    unsigned int action;  // system call number
    unsigned long ts;
    union object obj;
    long ret;
    int ready;  // 0: empty or writing; 1: readable; 2: useless
    std::vector<std::string> str_data;

    const char* c_str(char* buf, int buf_size) {
        struct sockaddr_in* ip = NULL;
        int num = 0;
        char* buf_head = buf;
        std::shared_ptr<Manual> book = Manual::get_manual();
        num = snprintf(buf, buf_size, "pid:%d, syscall:%s, ret: %ld, time:%lu, ready:%d, ", tgid,
                       book->get_syscall_name(action), ret, ts, ready);
        buf += num;
        buf_size -= num;
        if (buf_size <= 0) return buf;

        switch (action) {
            case SYS_close:
            case SYS_write:
            case SYS_read:
            case SYS_open:
                num = snprintf(buf, buf_size, "obj:{fd:%lu, i_ino:%lu}", obj.file.fd, obj.file.i_ino);
                break;
            case SYS_openat:
                num = snprintf(buf, buf_size, "obj:{fd:%lu, i_ino:%lu, dfd:%lu}", obj.file.fd, obj.file.i_ino,
                               obj.file.dfd);
                break;
            case SYS_mkdir:
                num = snprintf(buf, buf_size, "obj:{i_ino:%lu}", obj.file.i_ino);
                break;
            case SYS_connect:
                ip = (struct sockaddr_in*)obj.ops_connect.addr;
                num = snprintf(buf, buf_size, "obj:{fd:%lu, family:%s, ip:%s, port:%d}", obj.ops_connect.fd, book->get_socket_family_name(ip->sin_family),inet_ntoa(ip->sin_addr), ip->sin_port);
                break;
            case SYS_clone:
                num = snprintf(buf, buf_size, "obj:{child_tgid:%d}", obj.tgid);
                break;
            case SYS_chmod:
            case SYS_fchmodat:
            case SYS_fchownat:
            case SYS_unlink:
            case SYS_utimensat:
            case SYS_unlinkat:
                num = snprintf(buf, buf_size, "obj:{dfd:%lu, i_ino:%lu}", obj.file.dfd, obj.file.i_ino);
                break;
            case SYS_renameat2:
                num = snprintf(buf, buf_size, "obj:{old_fd:%lu, old_inode:%lu, new_fd:%lu, new_inode:%lu}",
                               obj.ops_rename.olddfd, obj.ops_rename.old_i_ino, obj.ops_rename.newdfd,
                               obj.ops_rename.new_i_ino);
                break;
            case SYS_dup2:
                num = snprintf(buf, buf_size, "obj:{old_fd:%lu, new_fd:%lu}", obj.ops_dup.oldfd, obj.ops_dup.newfd);
                break;
            case SYS_fcntl:
                num = snprintf(buf, buf_size, "obj:{cmd:%lu, fd:%lu, inode:%lu}", obj.ops_fcntl.cmd, obj.ops_fcntl.fd,
                               obj.ops_fcntl.i_ino);
                break;
            case SYS_recvfrom:
                num = snprintf(buf, buf_size, "obj:{fd:%lu, len:%lu}", obj.ops_recv.fd, obj.ops_recv.len);
                break;
            case SYS_sendto:
                num = snprintf(buf, buf_size, "obj:{fd:%lu, len:%lu}", obj.ops_send.fd, obj.ops_send.len);
                break;
            case SYS_exit:
            case SYS_exit_group:
            case SYS_execve:
            case SYS_chdir:
                break;
            default:
                num = snprintf(buf, buf_size, "obj:unknown");
                break;
        }

        for (size_t j = 0; j < str_data.size(); j++) {
            buf += num;
            buf_size -= num;
            if (buf_size <= 0) return buf;
            num = snprintf(buf, buf_size, "str_%lu: %s ", j, str_data[j].c_str());
        }
        return buf_head;
    }
};

// 自定义sockaddr，为了能在std::map中作为key。必须实现"<"操作符
struct sockaddr_ipv4 {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    unsigned char __pad[8];

    sockaddr_ipv4 operator=(const sockaddr_ipv4& s) {
        sin_family = s.sin_family;
        sin_port = s.sin_port;
        sin_addr = s.sin_addr;
        for (int i = 0; i < 8; i++) {
            __pad[i] = s.__pad[i];
        }
        return *this;
    }

    bool operator==(const sockaddr_ipv4& s) const {
        if (sin_family == s.sin_family && sin_port == s.sin_port && sin_addr == s.sin_addr) {
            return true;
        } else {
            return false;
        }
    }

    bool operator<(const sockaddr_ipv4& s) const {
        if (sin_family < s.sin_family) {
            return true;
        } else if (sin_family > s.sin_family) {
            return false;
        }

        if (sin_addr < s.sin_addr) {
            return true;
        } else if (sin_addr > s.sin_addr){
            return false;
        }        

        if (sin_port < s.sin_port) {
            return true;
        } else {
            return false;
        }
    }
};
#endif