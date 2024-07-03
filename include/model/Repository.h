#ifndef __REPOSITORY_H
#define __REPOSITORY_H

#include <queue>
#include <map>
#include <memory>
#include <string>
#include <set>
#include "BPF/map_user.h"
#include "tool/Log.h"
#include "graph/Node.h"

class Repository {
public:
    static std::shared_ptr<Repository> get_repository();
    int store_trace(struct Trace* trace);
    int init(Json::Value config);
    int add_root_pid(unsigned int root_pid);
    int del_root_pid(unsigned int root_pid);
    void start();
    void stop();
    void set_signal(unsigned int signal);
    void clear_signal(unsigned int signal);
    void get_docker_list(Json::Value& docker_list_now);
        // curl回调函数
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s);

private:
    // 将无用数据输出
    int output_part(unsigned int max_output_num);
    // 将全部数据输出
    int output_all();
    // 将buf的内容输出到node中的file_id所指向的cypher文件中
    int output_node(Node* node, char* buf);
    int output_edge(Edge* edge);

    // 逐步清理数据并检查内存，用于寻找内存碎片。
    int delete_all();
    void show_memory(const char* info);
    // 将graph中的map数据通过swap整理，减少内存碎片。
    int swap_map();

    Repository();
    // 根据trace数据修正/填充Repository中的图结构
    int fill_graph(struct Trace* trace);
    // SYS_write与SYS_read的进程可以不必在进程树中，需要单独处理
    int add_unrelated_process(struct Trace* trace);


    // 控制信号
    int m_signal;

    std::deque<struct Trace*> m_trace_repo;
    std::deque<struct Trace*> m_trace_buf;

    log4cplus::Logger m_log;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    Json::Value m_config;
    std::vector<std::ofstream*> m_cypher_file;
    std::vector<std::ofstream*> m_cypher_file_bak;
    std::vector<std::string> m_cypher_file_path;
    std::ofstream m_trace_file;
    std::string m_trace_file_path;
    std::vector<int> m_root_graph_id;
    Json::Value docker_list;
};

#endif