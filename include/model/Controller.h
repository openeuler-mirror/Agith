#ifndef __CONTROLLER_H
#define __CONTROLLER_H

#include <thread>
#include <memory>
#include <vector>
#include <json/json.h>
#include "model/BPFLoader.h"
#include "model/Consumer.h"
#include "tool/Log.h"
#include "tool/MessageQueue.h"

class Controller {
public:
    static std::shared_ptr<Controller> get_controller();
    int init(Json::Value config_file);
    int set_pid_target(pid_t pid);
    int stop();
    int start();
    int is_master();
    void set_signal(unsigned int signal);
    void clear_signal(unsigned int signal);

private:
    Controller();
    int init_perf_event();
    int init_consumer();
    int init_monitor();
    int init_repository();
    int init_log_module();
    int check_cpu_mem();
    int check_root_tgid();
    // 清空PID_TARGET_MAP & FILE_TARGET_MAP，然后将root_tgid重新写入
    int clear_target();
    // 清空repeat_trace_map, 防止冗余的openat，read等数据
    int clear_repeat_trace_map();

    int lock();
    int unlock();
    // 处理消息队列的信息
    int handle_mq();

    std::thread m_consumer_thread;
    std::thread m_monitor_thread;
    std::thread m_repository_thread;

    int m_signal;
    BPFLoader m_bpf_loader;
    log4cplus::Logger m_log;
    std::vector<unsigned int> m_root_tgid;
    Json::Value m_config;
    Json::Value m_root_config;

    int m_perf_event_map_fd;
    struct perf_buffer* p_perf_buffer;
    struct perf_buffer_opts m_perf_buf_opts;

    unsigned long m_os_cpu;
    unsigned long m_my_cpu;

    int m_pid_file_fd;
    static const char* m_pid_file_path;
    MessageQueue m_mq;
};

#endif