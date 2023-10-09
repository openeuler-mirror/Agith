#ifndef __FILENODE_H
#define __FILENODE_H

#include <map>
#include <deque>
#include <json/json.h>
#include "tool/Log.h"
#include "graph/Node.h"

class FileNode : public Node {
public:
    static bool have(unsigned long i_ino);
    static std::map<unsigned long, FileNode*> file_nodes;
    static Node* get_file_node_by_path(const char* path);
    static log4cplus::Logger m_log;

    const char* get_pathname();
    int rename(const char* new_name);
    FileNode(unsigned long i_ino, const char* pathname);
    virtual int to_json(Json::Value& value) override;
    virtual int to_cypher(char* buf, int buf_size) override;
    unsigned long get_inode();

private:
    unsigned long i_ino;
    std::deque<std::string> m_path;
};

#endif