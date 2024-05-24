#include <arpa/inet.h>
#include "graph/SocketNode.h"

std::map<struct sockaddr_ipv4, SocketNode*> SocketNode::socket_nodes = std::map<struct sockaddr_ipv4, SocketNode*>();
log4cplus::Logger SocketNode::m_log;

bool SocketNode::have(struct sockaddr_ipv4* addr) {
    if (socket_nodes.find(*addr) == socket_nodes.end()) {
        return false;
    } else {
        return true;
    }
}

Node* SocketNode::get_socket_node_by_link(const char* link) {
    // TODO
    return NULL;
}

SocketNode::SocketNode(struct sockaddr_ipv4* addr)
    : Node(SOCKET_NODE), m_addr(*addr) {}


int SocketNode::to_json(Json::Value& value) {
    in_addr ip;
    ip.s_addr = m_addr.sin_addr;
    value["ip"] = inet_ntoa(ip);
    value["port"] = m_addr.sin_port;
    value["type"] = m_node_type;
    value["graph_id"] = m_graph_id;
    value["family"] = m_addr.sin_family;
    return 0;
}

int SocketNode::to_cypher(char* buf, int buf_size) {
    char node_type[20];
    get_node_type(node_type);
    in_addr ip;
    ip.s_addr = m_addr.sin_addr;
    std::shared_ptr<Manual> book = Manual::get_manual();
    snprintf(buf, buf_size, "CREATE (:%s{graph_id:%d, family:\"%s\", ip:\"%s\", port:%d})",
             node_type, m_graph_id, book->get_socket_family_name(m_addr.sin_family), inet_ntoa(ip), m_addr.sin_port);
    return 0;
}

const struct sockaddr_ipv4 SocketNode::get_sockaddr_ipv4() {
    return m_addr;
}