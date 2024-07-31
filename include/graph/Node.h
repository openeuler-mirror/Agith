#ifndef __NODE_H
#define __NODE_H

#include <json/json.h>
#include <deque>
#include <set>

#define FILE_NODE 1
#define PROCESS_NODE 2
#define SOCKET_NODE 3
#define PIPE_NODE 4
#define SERVICE_NODE 5

class Edge;
class Node {
public:
    Node(int type);
    virtual int to_json(Json::Value& value) = 0;
    virtual int to_cypher(char* buf, int buf_size) = 0;
    int get_graph_id();
    // 获取节点类型，返回值是整型的node_type
    int get_node_type();
    // 获取节点类型，根据node_type转换为字符串写入type中
    void get_node_type(char* type);
    int get_edge_num();
    void add_edge(Edge* edge);
    void del_edge(Edge* edge);
    std::deque<Edge *>* get_edge();
    void set_file_id(int file_id);
    void set_file_id(std::set<unsigned int> *file_id);
    std::set<unsigned int>* get_file_id();

protected:
    static int g_graph_id;
    int m_graph_id;
    int m_node_type;
    std::deque<Edge*> m_edges;
    std::set<unsigned int> m_file_id;    
};

#endif