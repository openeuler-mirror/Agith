#ifndef __SOCKETNODE_H
#define __SOCKETNODE_H

#include <json/json.h>
#include "tool/Log.h"
#include "graph/Node.h"
#include "BPF/map_user.h"

class SocketNode : public Node {
public:
    static bool have(struct sockaddr_ipv4* addr);
    static std::map<struct sockaddr_ipv4, SocketNode*> socket_nodes;

    static Node* get_socket_node_by_link(const char* link);
    static log4cplus::Logger m_log;

    SocketNode(struct sockaddr_ipv4 *addr);
    const struct sockaddr_ipv4 get_sockaddr_ipv4();
    
    virtual int to_json(Json::Value& value) override;
    virtual int to_cypher(char* buf, int buf_size) override;

private:
    struct sockaddr_ipv4 m_addr;
};
#endif