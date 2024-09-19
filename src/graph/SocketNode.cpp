#include <arpa/inet.h>
#include "graph/SocketNode.h"
#include "tool/utils.h"

std::map<struct sockaddr_ipv4, SocketNode*> SocketNode::ipv4_socket_nodes = std::map<struct sockaddr_ipv4, SocketNode*>();
std::map<std::string, SocketNode*> SocketNode::unix_socket_nodes = std::map<std::string, SocketNode*>();
log4cplus::Logger SocketNode::m_log;

bool SocketNode::have(struct sockaddr_ipv4* addr) {
    if (ipv4_socket_nodes.find(*addr) == ipv4_socket_nodes.end()) {
        return false;
    } else {
        return true;
    }
}

bool SocketNode::unix_socket_have(std::string unix_addr){
    if (unix_socket_nodes.find(unix_addr) == unix_socket_nodes.end())
    {
        return false;
    }else{
        return true;
    }
    
}


Node* SocketNode::get_socket_node_by_link(const char* link) {
    // TODO
    return NULL;
}

SocketNode::SocketNode(unsigned short sin_family,struct sockaddr_ipv4* addr,std::string unix_addr)
    : Node(SOCKET_NODE),m_sin_family(sin_family), m_addr(*addr),m_unix_addr(unix_addr) {}


int SocketNode::to_json(Json::Value& value) {
    in_addr ip;
    ip.s_addr = m_addr.sin_addr;
    value["ip"] = inet_ntoa(ip);
    value["port"] = ntohs(m_addr.sin_port);
    value["type"] = m_node_type;
    value["graph_id"] = m_graph_id;
    value["family"] = m_addr.sin_family;
    value["unix_addr"]= m_unix_addr;
    return 0;
}

int SocketNode::to_cypher(char* buf, int buf_size) {
    char node_type[20];
    get_node_type(node_type);
    std::shared_ptr<Manual> book = Manual::get_manual();
     if (m_sin_family == AF_UNIX)
    {
        snprintf(buf, buf_size, "CREATE (:%s{graph_id:%d, family:\"%s\", unix_socket:\"%s\", service:\"%s\"})",
                node_type, m_graph_id, book->get_socket_family_name(m_addr.sin_family),m_unix_addr.c_str(),get_service_name_by_unix_socket(m_unix_addr).c_str());
    }else{
        in_addr ip;
        ip.s_addr = m_addr.sin_addr;
        snprintf(buf, buf_size, "CREATE (:%s{graph_id:%d, family:\"%s\", ip:\"%s\", port:%d , service:\"%s\"})",
                node_type, m_graph_id, book->get_socket_family_name(m_addr.sin_family), inet_ntoa(ip), ntohs(m_addr.sin_port),get_service_name_by_port(ntohs(m_addr.sin_port)).c_str());
    }
    return 0;
}

 std::string SocketNode::get_unix_addr(){
    return m_unix_addr;
 }
const struct sockaddr_ipv4 SocketNode::get_sockaddr_ipv4() {
    return m_addr;
} 