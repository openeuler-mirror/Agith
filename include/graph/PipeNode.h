#ifndef __PIPENODE_H
#define __PIPENODE_H

#include <map>
#include <json/json.h>
#include "tool/Log.h"
#include "graph/Node.h"

class PipeNode : public Node {
public:
    static bool have(unsigned long id);
    static std::map<unsigned long, PipeNode*> pipe_nodes;
    static Node* get_pipe_node_by_link(const char* link);
    static log4cplus::Logger m_log;
    PipeNode(unsigned long id);
    virtual int to_json(Json::Value& value) override;
    virtual int to_cypher(char* buf, int buf_size) override;
    unsigned long get_id();

private:
    unsigned long id;
};
#endif