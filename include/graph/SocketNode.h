#ifndef __SOCKETNODE_H
#define __SOCKETNODE_H

#include <json/json.h>
#include "tool/Log.h"
#include "graph/Node.h"
#include "BPF/map_user.h"

class SocketNode : public Node {
public:
    static bool have(struct sockaddr_ipv4* addr);
    static bool unix_socket_have(std::string unix_addr);
    static std::map<struct sockaddr_ipv4, SocketNode*> ipv4_socket_nodes;
    static std::map<std::string, SocketNode*> unix_socket_nodes;
    static Node* get_socket_node_by_link(const char* link);
    static log4cplus::Logger m_log;
    std::string get_unix_addr();
    SocketNode(unsigned short sin_family, struct sockaddr_ipv4 *addr,std::string unix_addr);
    const struct sockaddr_ipv4 get_sockaddr_ipv4();
    
    virtual int to_json(Json::Value& value) override;
    virtual int to_cypher(char* buf, int buf_size) override;

private:
    unsigned short m_sin_family;
    struct sockaddr_ipv4 m_addr;
    std::string m_unix_addr;
};
#endif