#ifndef __SERVICENODE_H
#define __SERVICENODE_H

#include <map>
#include <deque>
#include <json/json.h>
#include "tool/Log.h"
#include "graph/Node.h"

class ServiceNode : public Node {
public:
    static bool have(std::string service_name);
    static std::map<std::string, ServiceNode*> service_nodes;
    static log4cplus::Logger m_log;
    static int remove_node(const char* service_name);

    ServiceNode(std::string service_name, int service_type);
    ServiceNode(std::string service_name, std::string id, int service_type);
    virtual int to_json(Json::Value& value) override;
    virtual int to_cypher(char* buf, int buf_size) override;
    const char* get_service_name();

private:
    std::string m_service_name;
    std::string m_id;
    // 1 systemd服务、2 module服务、3 docker服务
    int m_service_type;
};

#endif