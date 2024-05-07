#ifndef __SERVICENODE_H
#define __SERVICENODE_H

#include <map>
#include <deque>
#include <json/json.h>
#include "tool/Log.h"
#include "graph/Node.h"

class ServiceNode : public Node {
public:
    static bool have(const char* service_name);
    static std::map<std::string, ServiceNode*> service_nodes;
    static log4cplus::Logger m_log;
    static int remove_node(const char* service_name);

    ServiceNode(const char* service_name);
    virtual int to_json(Json::Value& value) override;
    virtual int to_cypher(char* buf, int buf_size) override;
    const char* get_service_name();

private:
    const char* service_name;
};

#endif