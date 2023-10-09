#include <sys/syscall.h>
#include "graph/Edge.h"
#include "graph/ProcessNode.h"
#include "model/Monitor.h"
#include "tool/utils.h"

std::map<std::pair<Node*, Node*>, Edge*> Edge::edges = std::map<std::pair<Node*, Node*>, Edge*>();
log4cplus::Logger Edge::m_log;
std::set<unsigned int> Edge::g_risk_syscalls = std::set<unsigned int>();

Edge::Edge(Node* first, Node* second) {
    this->first = first;
    this->second = second;
    m_risk_level = 0;
}

int Edge::add_syscall(int syscall) {
    if (m_syscall.find(syscall) == m_syscall.end()) {
        m_syscall[syscall] = 1;
    } else {
        m_syscall[syscall] += 1;
    }
    return 0;
}

int Edge::add_edge(Node* first, Node* second, int syscall, const char* msg) {
    Edge* edge;
    std::shared_ptr<Manual> book = Manual::get_manual();
    if (first == NULL || second == NULL) {
        log_warn("node is NULL, can't create %s edge", book->get_syscall_name(syscall));
        return -1;
    }
    std::pair<Node*, Node*> node_pair = std::make_pair(first, second);
    if (have(first, second)) {
        edge = edges[node_pair];
    } else {
        edge = new Edge(first, second);
        first->add_edge(edge);
        second->add_edge(edge);
        second->set_file_id(first->get_file_id());
        edges[node_pair] = edge;    
    }
    edge->add_syscall(syscall);
    if (msg != NULL && msg[0] != '\0') {
        edge->add_msg(msg);
    }

    Monitor::get_Monitor()->analyse_trace(syscall, edge);
    return 0;
}

bool Edge::have(Node* first, Node* second) {
    std::pair<Node*, Node*> key = std::make_pair(first, second);
    if (edges.find(key) == edges.end()) {
        return false;
    } else {
        return true;
    }
}

int Edge::to_json(Json::Value& value) {
    Json::Value syscall_dict;
    Json::Value msg_list;
    std::shared_ptr<Manual> book = Manual::get_manual();

    value["first_node_id"] = first->get_graph_id();
    value["seconde_node_id"] = second->get_graph_id();
    value["risk_level"] = m_risk_level;
    for (auto syscall : m_syscall) {
        syscall_dict[book->get_syscall_name(syscall.first)] = syscall.second;
    }

    value["syscall"] = syscall_dict;

    for (size_t i = 0; i < this->m_msg.size(); i++) {
        msg_list.append(m_msg[i]);
    }
    value["msg"] = msg_list;
    return 0;
}

int Edge::to_cypher(char* buf, int buf_size) {
    char type1[20];
    char type2[20];
    int id1, id2;
    int n, left_size;
    std::shared_ptr<Manual> book = Manual::get_manual();

    first->get_node_type(type1);
    second->get_node_type(type2);
    id1 = first->get_graph_id();
    id2 = second->get_graph_id();
    left_size = buf_size;

    n = snprintf(buf, buf_size,
                 "MATCH (a:%s{graph_id:%d}) MATCH (b:%s{graph_id:%d}) CREATE (a) -[:syscall{risk_level:%d, syscall:[",
                 type1, id1, type2, id2, m_risk_level);
    buf += n;
    left_size -= n;

    for (auto syscall : m_syscall) {
        n = snprintf(buf, left_size, "\"%s:%d\",", book->get_syscall_name(syscall.first), syscall.second);
        left_size -= n;
        if (left_size < 20) break;
        buf += n;
    }

    buf -= 1;
    left_size += 1;
    if (buf[0] == ',') {
        n = snprintf(buf, left_size, "],msg:");
    } else {
        n = snprintf(buf, left_size, "[],msg:");
    }
    buf += n;
    left_size -= n;

    n = str_list_to_str(&m_msg, buf, left_size - 8);
    buf += n;
    left_size -= n;
    snprintf(buf, left_size, "}]->(b)");
    return buf_size - left_size;
}

/**
 * @brief 如果m_syscall中包含有风险的系统调用，风险等级加一
 *
 * @param syscall 含风险的系统调用编号
 * @return int risk level
 */
int Edge::set_risk_level() {
    m_risk_level = 0;
    for (auto id : m_syscall) {
        if (g_risk_syscalls.count(id.first)) {
            m_risk_level += id.second;
        }
    }
    return m_risk_level;
}

int Edge::add_msg(const char* msg) {
    std::string str;
    size_t len = strlen(msg);
    char buf[STR_BUF_SIZE];
    size_t i;
    for (i = 0; i < len; i++) {
        if (!isascii(msg[i])) {
            return -1;
        }

        if (msg[i] == '\r' || msg[i] == '\n' || msg[i] == '"') {
            break;
        }
    }

    strncpy(buf, msg, i);
    buf[i] = '\0';
    m_msg.push_back(buf);
    return 0;
}

Node* Edge::get_second() {
    return second;
}

Node* Edge::get_first() {
    return first;
}

int Edge::get_syscall_num(int syscall_id) {
    if (m_syscall.find(syscall_id) == m_syscall.end()) {
        return 0;
    }
    return m_syscall[syscall_id];
}