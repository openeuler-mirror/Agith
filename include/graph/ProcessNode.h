#ifndef __PROCESSNODE_H
#define __PROCESSNODE_H

#include <deque>
#include <json/json.h>
#include "tool/Log.h"
#include "graph/Node.h"
#include "graph/FileNode.h"
#include "graph/SocketNode.h"
#include <future>

class ProcessNode : public Node {
public:
    static std::map<unsigned int, ProcessNode*> process_nodes;
    static bool have(unsigned int pid);
    static log4cplus::Logger m_log;

    ProcessNode(unsigned int pid);
    ProcessNode(unsigned int pid, ProcessNode& parent);

    ProcessNode* clone(unsigned int child_pid);
    int execve(const char* new_cmd);
    int chdir(const char* new_wd);
    int close(int fd);
    int dup2(int oldfd, int newfd);
    int fcntl(int fd, int cmd, int ret);
    int exit(unsigned long time);
    unsigned long get_exit_time();
    FileNode* mkdir(const char* filename, unsigned long i_ino);
    FileNode* open(const char* filename, unsigned long i_ino, int fd);
    FileNode* openat(int dfd, const char* filename, unsigned long i_ino, int fd);
    FileNode* add_filenode_by_dfd(int dfd, const char* filename, unsigned long i_ino);
    FileNode* renameat2(int olddfd, const char* oldpath, int newdfd, const char* newpath, int new_i_ino, int old_i_ino);
    SocketNode* connect(int fd, struct sockaddr_ipv4* addr);
    const char* get_wd();
    const char* get_cmd();
    Node* add_fd_from_proc(int fd);
    int add_fd(int fd, Node* node);
    Node* get_node_by_fd(int fd);
    unsigned int get_pid();
    virtual int to_json(Json::Value& value) override;
    virtual int to_cypher(char* buf, int buf_size) override;
    int remove_service_node();
    void set_future(std::future<void> future);
    bool is_future_ready();
private:
    int set_wd_cmd_from_proc();
    int get_path_by_dfd(int dfd, const char* filename, char* path, int path_size);

    std::map<int, Node*> fd_table;
    unsigned int m_pid;
    // parent pid
    unsigned int m_ppid;
    // process exit time
    unsigned long m_exit_time;
    // work folder
    std::deque<std::string> m_wd;
    // command
    std::deque<std::string> m_cmd;
    // 部分命令需多线程长时间处理，存在m_exit_time设置后直接output情况，导致最后pnode被清理
    std::future<void> m_future;
};
#endif