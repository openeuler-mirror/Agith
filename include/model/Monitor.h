#ifndef __MONITOR_H
#define __MONITOR_H

#include <queue>
#include <set>
#include "BPF/map_user.h"
#include "tool/Log.h"
#include "graph/Edge.h"

class Monitor {
public:
    static std::shared_ptr<Monitor> get_Monitor();
    int analyse_trace(int syscall_id, Edge* edge);
    int init(Json::Value conf);
    void start();
    void stop();
    /**在压缩内存的过程中，edge指针会失效。为防止错误访问，设置简化
     * 标记。简化标记的告警信息只会输出风险系统调用名，没有详细信息。只有
     * 在monitor将buf中的edge全部处理完之后，才会消除简化标记。
     */
    void set_signal(unsigned int signal);
    void clear_signal(unsigned int signal);
    void wait_clean_buf();

private:
    Monitor();
    int m_signal;
    int send_alert(Edge* edge);
    std::deque<Edge*> m_trace_buf;
    std::deque<int> m_syscall_buf;
    std::set<unsigned int> m_risk_syscalls;
    // "name:%s, email:%s"
    std::vector<std::string> m_contacts;
    log4cplus::Logger m_log;

    std::mutex m_mutex;
    std::condition_variable m_cv;
};

#endif