#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <tool/utils.h>
#include "graph/FileNode.h"

std::map<unsigned long, FileNode*> FileNode::file_nodes = std::map<unsigned long, FileNode*>();
log4cplus::Logger FileNode::m_log;

bool FileNode::have(unsigned long i_ino) {
    if (file_nodes.find(i_ino) == file_nodes.end()) {
        return false;
    } else {
        return true;
    }
}

const char* FileNode::get_pathname() {
    return m_path.back().c_str();
}

FileNode::FileNode(unsigned long i_ino, const char* pathname) : Node(FILE_NODE), i_ino(i_ino) {
    m_path.push_back(pathname);
}

int FileNode::rename(const char* new_name) {
    if (strcmp(new_name, "null") == 0 || strcmp(new_name, m_path.back().c_str()) == 0) {
        return -1;
    }
    m_path.push_back(new_name);
    return 0;
}

Node* FileNode::get_file_node_by_path(const char* path) {
    unsigned long i_ino;
    struct stat file_stat;

    if (access(path, F_OK)) {
        log_warn("Can not find file:%s, errno: %d", path, errno);
        return NULL;
    }
    if (stat(path, &file_stat)) {
        return NULL;
    }
    i_ino = file_stat.st_ino;

    if (!have(i_ino)) {
        file_nodes[i_ino] = new FileNode(i_ino, path);
    }
    return file_nodes[i_ino];
}

int FileNode::to_json(Json::Value& value) {
    Json::Value path;

    value["inode"] = i_ino;
    value["type"] = m_node_type;
    value["graph_id"] = m_graph_id;
    for (size_t i = 0; i < m_path.size(); i++) {
        path.append(m_path[i]);
    }
    value["path"] = path;
    return 0;
}

int FileNode::to_cypher(char* buf, int buf_size) {
    char type[20];
    int n;
    get_node_type(type);
    n = snprintf(buf, buf_size, "CREATE (:%s{graph_id:%d, inode:%lu, path: ", type, m_graph_id, i_ino);
    buf += n;
    buf_size -= n;

    n = str_list_to_str(&m_path, buf, buf_size - 3);
    buf += n;
    buf_size -= n;

    snprintf(buf, buf_size, "})");
    return 0;
}

unsigned long FileNode::get_inode() {
    return i_ino;
}
