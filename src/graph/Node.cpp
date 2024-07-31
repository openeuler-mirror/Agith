#include "graph/Node.h"
#include <string.h>
#include <algorithm>

int Node::g_graph_id = 0;

Node::Node(int type) {
    m_node_type = type;
    m_graph_id = g_graph_id++;
}

void Node::set_file_id(int file_id) {
    m_file_id.insert(file_id);
}

void Node::set_file_id(std::set<unsigned int> *file_id) {
    std::set<unsigned int>::iterator it; 
    for(it = file_id->begin();it != file_id->end();it++) {
        m_file_id.insert(*it);
    }
}

std::set<unsigned int>* Node::get_file_id() {
    return &m_file_id;
}

int Node::get_edge_num() {
    return m_edges.size();
}

void Node::add_edge(Edge* edge) {
    m_edges.push_back(edge);
}

void Node::del_edge(Edge* edge) {
    std::deque<Edge*>::iterator it;
    it = std::find(m_edges.begin(), m_edges.end(), edge);
    if (it != m_edges.end()) {
        m_edges.erase(it);
    }
}

std::deque<Edge *>* Node::get_edge() {
    return &m_edges;
}

int Node::get_graph_id() {
    return m_graph_id;
}

int Node::get_node_type() {
    return m_node_type;
}

void Node::get_node_type(char* type) {
    switch (m_node_type) {
        case FILE_NODE:
            strcpy(type, "File");
            break;
        case PROCESS_NODE:
            strcpy(type, "Process");
            break;
        case SOCKET_NODE:
            strcpy(type, "Socket");
            break;
        case PIPE_NODE:
            strcpy(type, "Pipe");
            break;
        case SERVICE_NODE:
            strcpy(type, "Service");
            break;
        default:
            strcpy(type, "Unknown");
            break;
    }
}
