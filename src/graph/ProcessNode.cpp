#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include "graph/ProcessNode.h"
#include "graph/PipeNode.h"
#include "graph/Edge.h"
#include "graph/ServiceNode.h"
#include "tool/utils.h"

std::map<unsigned int, ProcessNode*> ProcessNode::process_nodes = std::map<unsigned int, ProcessNode*>();
log4cplus::Logger ProcessNode::m_log;

ProcessNode::ProcessNode(unsigned int pid) : Node(PROCESS_NODE) {
    m_pid = pid;
    m_ppid = 0;
    m_exit_time = 0;
    if (set_wd_cmd_from_proc() != 0) {
        log_warn("not find process %u in /proc", pid);
        m_wd.push_back("null");
        m_cmd.push_back("null");
    }
}

ProcessNode::ProcessNode(unsigned int pid, ProcessNode& parent) : Node(PROCESS_NODE) {
    m_pid = pid;
    m_ppid = parent.m_pid;
    m_exit_time = 0;
    m_cmd.push_back(parent.m_cmd.back());
    m_wd.push_back(parent.m_wd.back());
    for (auto it : parent.fd_table) {
        fd_table.insert(it);
    }
}

int ProcessNode::set_wd_cmd_from_proc() {
    char path[PATH_MAX], buf[PATH_MAX];
    ssize_t len;
    DIR* p_dir;
    struct dirent* p_dirent;

    // check if pid exists
    snprintf(path, sizeof(path), "/proc/%d", m_pid);
    if (access(path, F_OK)) {
        return -1;
    }

    // set work path
    snprintf(path, sizeof(path), "/proc/%d/cwd", m_pid);
    len = readlink(path, buf, PATH_MAX);
    buf[len] = 0;
    std::string wd = buf;
    this->m_wd.push_back(wd);

    // set command
    snprintf(path, sizeof(path), "/proc/%d/exe", m_pid);
    len = readlink(path, buf, PATH_MAX);
    buf[len] = 0;
    std::string cmd = buf;
    this->m_cmd.push_back(cmd);

    // sef fd table
    snprintf(path, sizeof(path), "/proc/%d/fd", m_pid);
    p_dir = opendir(path);
    if (!p_dir) return 0;

    while ((p_dirent = readdir(p_dir)) != 0) {
        if (p_dirent->d_type != DT_LNK) continue;
        add_fd_from_proc(atoi(p_dirent->d_name));
    }

    closedir(p_dir);
    return 0;
}

bool ProcessNode::have(unsigned int pid) {
    if (process_nodes.find(pid) == process_nodes.end()) {
        return false;
    } else {
        return true;
    }
}

const char* ProcessNode::get_cmd() {
    return m_cmd.back().c_str();
}

const char* ProcessNode::get_wd() {
    return m_wd.back().c_str();
}

ProcessNode* ProcessNode::clone(unsigned int child_pid) {
    if (!have(child_pid)) {
        process_nodes[child_pid] = new ProcessNode(child_pid, *this);
    }
    return process_nodes[child_pid];
}

int ProcessNode::execve(const char* new_cmd) {
    if (new_cmd == NULL || new_cmd[0] == '\0') {
        m_cmd.push_back("null");
    } else if (new_cmd[0] == '/') {
        m_cmd.push_back(new_cmd);
    } else {
        m_cmd.push_back(m_wd.back() + new_cmd);
    }
    return 0;
}

int ProcessNode::chdir(const char* new_wd) {
    if (new_wd == NULL || new_wd[0] == '\0') {
        m_wd.push_back("null");
    } else if (new_wd[0] == '/') {
        m_wd.push_back(new_wd);
    } else {
        m_wd.push_back(m_wd.back() + new_wd);
    }
    return 0;
}

int ProcessNode::close(int fd) {
    if (fd_table.find(fd) == fd_table.end()) {
        log_warn("close failed, can't find fd %d", fd);
        return EINVAL;
    }

    fd_table.erase(fd);
    return 0;
}

int ProcessNode::add_fd(int fd, Node* node) {
    fd_table[fd] = node;
    return 0;
}

Node* ProcessNode::add_fd_from_proc(int fd) {
    char buf[PATH_MAX];
    char path[PATH_MAX];
    Node* node;
    int len;
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", m_pid, fd);
    if (access(path, F_OK)) {
        return NULL;
    }

    len = readlink(path, buf, PATH_MAX);
    buf[len] = '\0';
    std::string fd_str(buf);

    if (fd_str.find("socket") != std::string::npos) {
        node = SocketNode::get_socket_node_by_link(fd_str.c_str());
    } else if (fd_str[0] == '/') {
        node = FileNode::get_file_node_by_path(fd_str.c_str());
    } else if (fd_str.find("pipe") != std::string::npos) {
        node = PipeNode::get_pipe_node_by_link(fd_str.c_str());
    } else {
        log_warn("%s:%d, encounter unknown fd %d type: %s", get_cmd(), m_pid, fd, fd_str.c_str());
        return NULL;
    }
    if (node == NULL) {
        log_warn("read process fd %s failed", path);
        return NULL;
    }
    add_fd(fd, node);
    return node;
}

int ProcessNode::exit(unsigned long time) {
    m_exit_time = time;
    return 0;
}

unsigned long ProcessNode::get_exit_time() {
    return m_exit_time;
}

int ProcessNode::dup2(int oldfd, int newfd) {
    if (fd_table.find(oldfd) == fd_table.end()) {
        if (add_fd_from_proc(oldfd) == NULL) {
            return -1;
        }
    }
    add_fd(newfd, fd_table[oldfd]);
    return 0;
}

int ProcessNode::fcntl(int fd, int cmd, int ret) {
    // 监控fcntl的目的是掌握fd指向文件的变化，不监控文件信息的获取
    if (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC) {
        return -1;
    }

    return dup2(fd, ret);
}

int ProcessNode::get_path_by_dfd(int dfd, const char* filename, char* path, int path_size) {
    const char* base_path;

    if (filename == NULL || filename[0] == '\0') {
        strcpy(path, "null");
        return 0;
    }

    // absolute path
    if (filename[0] == '/') {
        snprintf(path, path_size, "%s", filename);
        return 0;
    }

    // relative path by wd
    if (dfd == AT_FDCWD) {
        snprintf(path, path_size, "%s/%s", m_wd.back().c_str(), filename);
        return 0;
    }

    // relative path by dfd
    if (fd_table.find(dfd) == fd_table.end()) {
        strcpy(path, filename);
        return 0;
    }

    base_path = ((FileNode*)fd_table[dfd])->get_pathname();
    if (base_path[strlen(base_path) - 1] == '/') {
        snprintf(path, path_size, "%s%s", base_path, filename);
    } else {
        snprintf(path, path_size, "%s/%s", base_path, filename);
    }
    return 0;
}

FileNode* ProcessNode::mkdir(const char* filename, unsigned long i_ino) {
    FileNode* file_node;
    char path[PATH_MAX];

    if (i_ino == 0) {
        log_warn("[mkdir] create file node error, inode is %lu", i_ino);
        return NULL;
    }

    get_path_by_dfd(AT_FDCWD, filename, path, PATH_MAX);

    if (FileNode::have(i_ino)) {
        file_node = FileNode::file_nodes[i_ino];
        file_node->rename(path);
    } else {
        file_node = new FileNode(i_ino, path);
        FileNode::file_nodes[i_ino] = file_node;
    }

    return file_node;
}

FileNode* ProcessNode::open(const char* filename, unsigned long i_ino, int fd) {
    return openat(AT_FDCWD, filename, i_ino, fd);
}

FileNode* ProcessNode::openat(int dfd, const char* filename, unsigned long i_ino, int fd) {
    FileNode* file_node;
    file_node = add_filenode_by_dfd(dfd, filename, i_ino);
    add_fd(fd, file_node);
    return file_node;
}

Node* ProcessNode::get_node_by_fd(int fd) {
    if (fd_table.find(fd) == fd_table.end()) {
        return NULL;
    } else {
        return fd_table[fd];
    }
}

FileNode* ProcessNode::add_filenode_by_dfd(int dfd, const char* filename, unsigned long i_ino) {
    FileNode* file_node;
    char path[PATH_MAX];

    if (i_ino == 0 && strlen(filename) == 0) {
        log_warn("create file node fail, inode is 0 and file name is null");
        return NULL;
    }

    get_path_by_dfd(dfd, filename, path, PATH_MAX);

    if (FileNode::have(i_ino)) {
        file_node = FileNode::file_nodes[i_ino];
        file_node->rename(path);
    } else {
        file_node = new FileNode(i_ino, path);
        FileNode::file_nodes[i_ino] = file_node;
    }
    return file_node;
}

FileNode* ProcessNode::renameat2(int oldfd, const char* oldfile, int newdfd, const char* newfile, int new_i_ino,
                                 int old_i_ino) {
    char new_path[PATH_MAX];
    char old_path[PATH_MAX];
    FileNode* file_node;

    get_path_by_dfd(newdfd, newfile, new_path, PATH_MAX);
    get_path_by_dfd(oldfd, oldfile, old_path, PATH_MAX);

    if (FileNode::have(new_i_ino)) {
        file_node = FileNode::file_nodes[new_i_ino];
        file_node->rename(new_path);
    } else if (FileNode::have(old_i_ino)) {
        file_node = FileNode::file_nodes[old_i_ino];
        file_node->rename(new_path);
        FileNode::file_nodes.erase(old_i_ino);
        FileNode::file_nodes[new_i_ino] = file_node;
    } else {
        file_node = new FileNode(old_i_ino, old_path);
        file_node->rename(new_path);
        FileNode::file_nodes[new_i_ino] = file_node;
    }
    return file_node;
}

SocketNode* ProcessNode::connect(int fd, struct sockaddr_ipv4* addr) {
    SocketNode* socknode;
    std::deque<SocketNode*>::iterator it;
    // 丢失socket系统调用，直接是connect系统调用。fd_table中没有，或者对应的节点不是socket。
    if (SocketNode::have(addr)) {
        socknode = SocketNode::socket_nodes[*addr];
    } else {
        socknode = new SocketNode(addr);
        SocketNode::socket_nodes[*addr] = socknode;
    }
    add_fd(fd, socknode);
    return socknode;
}

int ProcessNode::to_json(Json::Value& value) {
    Json::Value wd_list;
    Json::Value cmd_list;

    value["type"] = m_node_type;
    value["graph_id"] = m_graph_id;
    value["parent_pid"] = m_ppid;
    value["pid"] = m_pid;

    for (size_t i = 0; i < m_wd.size(); i++) {
        wd_list.append(m_wd[i]);
    }
    for (size_t i = 0; i < m_cmd.size(); i++) {
        cmd_list.append(m_cmd[i]);
    }

    value["work_dir"] = wd_list;
    value["command"] = cmd_list;
    return 0;
}

int ProcessNode::to_cypher(char* buf, int buf_size) {
    char type[20];
    int n;
    get_node_type(type);
    n = snprintf(buf, buf_size, "CREATE (:%s{graph_id:%d, pid:%d, parent_pid:%d, work_dir:", type, m_graph_id, m_pid,
                 m_ppid);
    buf += n;
    buf_size -= n;

    n = str_list_to_str(&m_wd, buf, buf_size - 20);
    buf += n;
    buf_size -= n;

    n = snprintf(buf, buf_size, ", command:");
    buf += n;
    buf_size -= n;

    n = str_list_to_str(&m_cmd, buf, buf_size - 3);
    buf += n;
    buf_size -= n;

    n = snprintf(buf, buf_size, "})");
    return 0;
}

unsigned int ProcessNode::get_pid() {
    return m_pid;
}

int ProcessNode::remove_process_node() {
    std::deque<Edge*>* edge_list = get_edge();
    std::deque<Edge*>::iterator it_edge;
    Edge* edge;
    Node* node;
    for (it_edge = edge_list->begin(); it_edge != edge_list->end(); it_edge++) {
        edge = *it_edge;
        node = edge->get_second();
        if (node == this) {
            continue;
        }
        int type = node->get_node_type();
        switch (type) {
            case PROCESS_NODE:
                ((ProcessNode*)node)->remove_process_node();
                break;
            case FILE_NODE:
                FileNode::file_nodes.erase(((FileNode*)node)->get_inode());
                break;
            case SOCKET_NODE:
                SocketNode::socket_nodes.erase(((SocketNode*)node)->get_sockaddr_ipv4());
                break;
            case PIPE_NODE:
                PipeNode::pipe_nodes.erase(((PipeNode*)node)->get_id());
                break;
            case SERVICE_NODE:
                ServiceNode::service_nodes.erase(((ServiceNode*)node)->get_service_name());
                break;
            default:
                break;
        }
    }
    return 0;
}