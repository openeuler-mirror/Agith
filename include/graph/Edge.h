#ifndef __EDGE_H
#define __EDGE_H

#include <deque>
#include <set>
#include <json/json.h>
#include "tool/Log.h"
#include "graph/Node.h"

class Edge {
public:
    static bool have(Node* first, Node* second);
    static std::map<std::pair<Node*, Node*>, Edge*> edges;
    static int add_edge(Node* first, Node* second, int syscall, const char* msg = NULL);
    static log4cplus::Logger m_log;
    static std::set<unsigned int> g_risk_syscalls;

    Edge(Node* first, Node* second);
    int add_syscall(int syscall);
    int add_msg(const char* msg);
    const char* get_msg();
    // 计算风险等级并返回风险等级
    int set_risk_level();
    int get_syscall_num(int syscall_id);
    int to_json(Json::Value& value);
    int to_cypher(char* buf, int buf_size);
    Node* get_first();
    Node* get_second();

private:
    std::map<int, int> m_syscall;
    std::deque<std::string> m_msg;
    Node* first;
    Node* second;
    int m_risk_level;
};
#endif