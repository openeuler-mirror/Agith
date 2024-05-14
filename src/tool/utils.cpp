#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fstream>
#include <fcntl.h>
#include <mqueue.h>
#include "tool/utils.h"
#include "string.h"
#include "signal.h"
#include "graph/Node.h"
#include "graph/Edge.h"
#include "graph/ProcessNode.h"
#include "graph/PipeNode.h"
#include "graph/ServiceNode.h"


const char* help_info =
    "Agith help infomation:\n"
    "\t-p: PID, monitor process\n"
    "\t-c: configure file path, default as /usr/local/Agith/config/agith.config\n"
    "\t-q: quit, stop Agith service\n";

void parse_opt(int argn, char** argv, unsigned int* p_tgid, char* filepath, int bufsize, int *stop) {
    int opt;
    const char* optstring = "p:hc:q";

    // set default value
    *p_tgid = 0;
    snprintf(filepath, bufsize, "%s", "/usr/local/Agith/config/agith.config");
    *stop = 0;

    while ((opt = getopt(argn, argv, optstring)) != -1) {
        switch (opt) {
            case 'p':
                *p_tgid = atol(optarg);
                break;
            case 'h':
                printf("%s", help_info);
                break;
            case 'c':
                snprintf(filepath, bufsize, "%s", optarg);
                break;
            case 'q':
                *stop = 1;
                break;
            default:
                printf("invalid option -- %c\n", opt);
                printf("%s", help_info);
        }
    }
}

int str_list_to_str(std::deque<std::string>* list, char* buf, int buf_size) {
    int n = 0;
    int left_size = buf_size;
    buf[0] = '[';
    buf += 1;
    left_size -= 1;
    std::deque<std::string>::reverse_iterator it;
    for (it = list->rbegin(); it != list->rend(); it++) {
        n = snprintf(buf, left_size, "\"%s\",", it->c_str());
        left_size -= n;
        if (left_size < 2) {
            left_size += n;
            break;
        }
        buf += n;
    }
    if (list->size() != 0) {
        buf -= 1;
        left_size += 1;
    }
    buf[0] = ']';
    buf[1] = '\0';
    left_size -= 1;
    return buf_size - left_size;
}

int int_list_to_str(std::deque<unsigned long>* list, char* buf, int buf_size) {
    int n;
    int left_size = buf_size;
    buf[0] = '[';
    buf += 1;
    left_size -= 1;
    for (size_t i = 0; i < list->size(); i++) {
        n = snprintf(buf, left_size, "%lu,", list->at(i));
        left_size -= n;
        if (left_size <= 1) {
            left_size += n;
            break;
        }
        buf += n;
    }
    buf -= 1;
    if (buf[0] == ',') {
        buf[0] = ']';
        buf[1] = '\0';
    } else {
        buf[1] = ']';
        buf[2] = '\0';
        left_size -= 1;
    }
    return buf_size - left_size;
}

// 获取总的CPU时间
unsigned long get_os_cpu_time() {
    unsigned long user, nice, system, idle, iowait;
    unsigned long irq, softirq, steal, guest, guest_nice;
    char buf[PATH_MAX];
    std::ifstream file;
    file.open("/proc/stat", std::ios::in);

    if (!file.is_open()) {
        return 0;
    }

    file.getline(buf, PATH_MAX);
    sscanf(buf, "cpu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu", &user, &nice, &system, &idle, &iowait, &irq, &softirq,
           &steal, &guest, &guest_nice);

    file.close();

    return user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
}

// 获取进程的CPU时间
unsigned long get_proc_cpu_time(unsigned int pid) {
    unsigned long utime, stime, cutime, cstime;
    std::ifstream file;
    char buf[PATH_MAX];
    std::string str;
    size_t i = 0, n = 0;

    sprintf(buf, "/proc/%d/stat", pid);

    file.open(buf, std::ios::in);
    if (!file.is_open()) {
        return 0;
    }
    file.getline(buf, PATH_MAX);
    file.close();

    str = buf;
    while (n < 13) {
        i = str.find(' ', i + 1);
        if (i == std::string::npos) break;
        n += 1;
    }

    sscanf(buf + i, "%lu %lu %lu %lu", &utime, &stime, &cutime, &cstime);
    return utime + stime + cutime + cstime;
}

// 获取进程占用内存
unsigned int get_proc_mem(unsigned int pid) {
    unsigned long size, resident, shared, text, lib, data, dt;
    char buf[PATH_MAX];
    std::ifstream file;

    snprintf(buf, PATH_MAX, "/proc/%d/statm", pid);
    file.open(buf, std::ios::in);
    if (!file.is_open()) {
        return 0;
    }

    file.getline(buf, PATH_MAX);
    file.close();
    sscanf(buf, "%lu %lu %lu %lu %lu %lu %lu", &size, &resident, &shared, &text, &lib, &data, &dt);

    // MB
    resident = (getpagesize() * resident) >> 20;
    return resident;
}


volatile sig_atomic_t g_exit_flag;

static void handler(int sig) {
    g_exit_flag = 1;
}

int set_signal_handle() {
    struct sigaction sa;

    // 响应终止信号
    sa.sa_flags = 0;
    sa.sa_handler = handler;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        printf("error in interrupt signal config");
        return 0;
    }   
    return 0;
}

int delete_node(Node* node) {
    std::deque<Edge*>* edges = node->get_edge();

    for(Edge* edge: *edges) {
        delete_edge(edge);
    }
    // delete基类指针不会调用子类的析构函数，最终导致内存泄露。所以需要转换为子类指针之后再删除。
    switch(node->get_node_type()){
        case PROCESS_NODE:{
            ProcessNode *proc_node = (ProcessNode*)node;
            delete proc_node;
            break;            
        }
        case FILE_NODE:{
            FileNode *file_node = (FileNode*)node;
            delete file_node;
            break;            
        }
        case SOCKET_NODE:{
            SocketNode* sock_node = (SocketNode*)node;
            delete sock_node;
            break;            
        }
        case PIPE_NODE:{
            PipeNode* pipe_node = (PipeNode*)node;
            delete pipe_node;
            break;            
        }
        case SERVICE_NODE:{
            ServiceNode* service_node = (ServiceNode*)node;
            delete service_node;
            break;            
        }
        default:
            printf("delete node fail, unknown type %d", node->get_node_type());
            return -1;
    }
    return 0;
}

int delete_edge(Edge* edge) {
    Node* first = edge->get_first();
    Node* second = edge->get_second();
    first->del_edge(edge);
    second->del_edge(edge);
    std::pair<Node*, Node*> key = std::make_pair(first, second);
    Edge::edges.erase(key);    
    delete edge;    
    return 0;
}