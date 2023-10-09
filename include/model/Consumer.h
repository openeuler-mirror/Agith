#ifndef __CONSUMER_H
#define __CONSUMER_H

#include <thread>
#include <string>
#include <fstream>
#include <list>
#include <queue>
#include "BPF/map_user.h"
#include "tool/Log.h"

struct cmp {
    bool operator()(Trace* v1, Trace* v2) { return v1->ts > v2->ts; }
};

class Consumer {
public:
    static std::shared_ptr<Consumer> get_consumer();
    int init(int trace_fd, int trace_ptr_fd, int str1_fd, int str2_fd, int str3_fd);
    void start();
    void stop();
    void notify();
    void set_signal(unsigned int signal);
    void clear_signal(unsigned int signal);

private:
    Consumer();
    int read_trace_map();
    int fill_trace(struct Trace* trace, int* index);
    void handle();

    int m_signal;
    int m_trace_map_fd;
    int m_trace_ptr_map_fd;
    int m_str1_map_fd;
    int m_str2_map_fd;
    int m_str3_map_fd;

    std::mutex m_mutex;
    std::condition_variable m_cv;

    std::deque<int> m_not_ready_trace[CPU_NUM];
    unsigned int m_last_ptr[CPU_NUM];
    std::priority_queue<struct Trace*, std::vector<Trace*>, cmp> m_trace_buf;
    log4cplus::Logger m_log;
};

#endif