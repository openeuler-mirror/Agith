#include "graph/PipeNode.h"

std::map<unsigned long, PipeNode*> PipeNode::pipe_nodes = std::map<unsigned long, PipeNode*>();
log4cplus::Logger PipeNode::m_log;

bool PipeNode::have(unsigned long id) {
    if (pipe_nodes.find(id) == pipe_nodes.end()) {
        return false;
    } else {
        return true;
    }
}

PipeNode::PipeNode(unsigned long id) : Node(PIPE_NODE), id(id) {}

Node* PipeNode::get_pipe_node_by_link(const char* link) {
    std::string str = link;
    int i1 = str.find('[');
    int i2 = str.find(']');
    unsigned long id = atol(str.substr(i1 + 1, i2 - i1).c_str());
    if (!have(id)) {
        pipe_nodes[id] = new PipeNode(id);
    }
    return pipe_nodes[id];
}

int PipeNode::to_json(Json::Value& value) {
    value["id"] = id;
    value["type"] = m_node_type;
    value["graph_id"] = m_graph_id;
    return 0;
}

int PipeNode::to_cypher(char* buf, int buf_size) {
    char type[20];
    get_node_type(type);
    snprintf(buf, buf_size, "CREATE (:%s{graph_id:%d, pipe_id:%lu})", type, m_graph_id, id);
    return 0;
}

unsigned long PipeNode::get_id() {
    return id;
}
