#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <tool/utils.h>
#include "graph/ServiceNode.h"

std::map<std::string, ServiceNode*> ServiceNode::service_nodes = std::map<std::string, ServiceNode*>();
log4cplus::Logger ServiceNode::m_log;

bool ServiceNode::have(const char* service_name) {
    if (service_nodes.find(service_name) == service_nodes.end()) {
        return false;
    } else {
        return true;
    }
}
ServiceNode::ServiceNode(const char* name) : Node(SERVICE_NODE) {
    service_name = new char[strlen(name) + 1];
    strcpy(service_name, name);
}
int ServiceNode::to_json(Json::Value& value) {
    Json::Value path;

    value["service"] = service_name;
    value["type"] = m_node_type;
    value["graph_id"] = m_graph_id;

    return 0;
}

int ServiceNode::to_cypher(char* buf, int buf_size) {
    char type[20];
    int n;
    get_node_type(type);
    n = snprintf(buf, buf_size, "CREATE (:%s{graph_id:%d, service:\"%s\"", type, m_graph_id, service_name);
    buf += n;
    buf_size -= n;

    // n = str_list_to_str(&m_path, buf, buf_size - 3);
    // buf += n;
    // buf_size -= n;

    snprintf(buf, buf_size, "})");
    return 0;
}

int ServiceNode::remove_node(const char* service_name) {
    ServiceNode::service_nodes.erase(service_name);
    return 0;
}

const char* ServiceNode::get_service_name() {
    return service_name;
}