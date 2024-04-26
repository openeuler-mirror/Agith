#include <mutex>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <fstream>
#include <climits>
#include <dirent.h>
#include <regex>
#include <json/json.h>
#include <malloc.h>

#include "model/Repository.h"
#include "model/Monitor.h"
#include "tool/Manual.h"
#include "graph/Edge.h"
#include "graph/FileNode.h"
#include "graph/ProcessNode.h"
#include "graph/SocketNode.h"
#include "graph/PipeNode.h"
#include "tool/utils.h"

#define BUF_SIZE 40960

static std::shared_ptr<Repository> m_repository = nullptr;
static std::once_flag create_flag;

Repository::Repository() {
    m_log = LoggerFactory::create_logger("Repository");
    m_signal = NO_ACTION;
}

std::shared_ptr<Repository> Repository::get_repository() {
    std::call_once(create_flag, [&] { m_repository = std::shared_ptr<Repository>(new Repository()); });
    return m_repository;
}

int Repository::store_trace(struct Trace* trace) {
    m_trace_buf.push_back(trace);
    m_cv.notify_one();
    return 0;
}

void Repository::start() {
    std::unique_lock<std::mutex> lock(m_mutex);
    struct timespec now = {0, 0};
    struct timespec last_time_output = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    last_time_output = now;

    while ((m_signal & END_SIGNAL) == 0) {
        m_cv.wait(lock);
        for (; !m_trace_buf.empty(); m_trace_buf.pop_front()) {
            fill_graph(m_trace_buf.front());
            m_trace_repo.push_back(m_trace_buf.front());
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - last_time_output.tv_sec > 1 || now.tv_nsec - last_time_output.tv_nsec > 1e8 /*time, ns*/) {
            last_time_output = now;
            output_part(m_config["max_output_trace"].asUInt());
        }

        if (m_signal & SWAP_MEMORY) {
            swap_map();
            clear_signal(SWAP_MEMORY);
        }

        if (m_signal & OUTPUT_USELESS) {
            output_part(UINT32_MAX);
            clear_signal(OUTPUT_USELESS);
        }
    }

    log_info("output graph to file");
    output_all();
    log_info("repository stop");
}

int Repository::add_unrelated_process(struct Trace* trace) {
    FileNode* fnode;
    ProcessNode* pnode;

    switch (trace->action) {
        case SYS_read:
        case SYS_write:
            if (FileNode::have(trace->obj.file.i_ino)) {
                fnode = FileNode::file_nodes[trace->obj.file.i_ino];
                pnode = new ProcessNode(trace->tgid);
                pnode->set_file_id(fnode->get_file_id());
                ProcessNode::process_nodes[trace->tgid] = pnode;
                Edge::add_edge(pnode, fnode, trace->action);
                break;
            } else {
                return -1;
            }
        default:
            return -1;
    }
    return 0;
}

int Repository::fill_graph(struct Trace* trace) {
    unsigned long i_ino;
    pid_t tgid;
    int fd;
    int dfd;
    ProcessNode* pnode;
    FileNode* fnode;
    SocketNode* socknode;
    struct sockaddr_ipv4* addr;
    const char* filename = NULL;
    const char* data = NULL;
    char buf[BUF_SIZE];

    tgid = trace->tgid;
    if (!ProcessNode::have(tgid)) {
        if (tgid == getpid()) {
            // agith进入监控目标是由于inode复用
            return 0;
        }
        if (add_unrelated_process(trace) == 0) {
            return 0;
        }
        trace->c_str(buf, BUF_SIZE);
        log_error("can't find process. trace:%s", buf);
        return EINVAL;
    }

    pnode = ProcessNode::process_nodes[tgid];

    switch (trace->action) {
        case SYS_clone: {
            if (trace->ret == -1) break;
            unsigned int child_pid = trace->obj.tgid;
            ProcessNode* child = pnode->clone(child_pid);
            Edge::add_edge(pnode, child, SYS_clone);
            break;
        }
        case SYS_exit:
        case SYS_exit_group:
            // exit与exit_group没有返回值,不需要判断
            pnode->exit(trace->ts);
            break;
        case SYS_execve: {
            if (trace->ret == -1) break;
            std::string name;
            name = trace->str_data[0];
            if (trace->str_data[1].size() != 0) {
                name += " ";
                name += trace->str_data[1];
            }
            if (trace->str_data[2].size() != 0) {
                name += " ";
                name += trace->str_data[2];
            }
            filename = name.c_str();
            pnode->execve(filename);
            break;
        }
        case SYS_chdir:
            if (trace->ret == -1) break;
            filename = trace->str_data[0].c_str();
            pnode->chdir(filename);
            break;
        case SYS_read:
        case SYS_write: {
            if (trace->ret == -1) break;
            i_ino = trace->obj.file.i_ino;
            fd = trace->obj.file.fd;
            if (FileNode::have(i_ino)) {
                fnode = FileNode::file_nodes[i_ino];
            } else {
                fnode = (FileNode*)pnode->add_fd_from_proc(fd);
                if (fnode == NULL) {
                    fnode = new FileNode(i_ino, "null");
                    FileNode::file_nodes[i_ino] = fnode;
                    pnode->add_fd(fd, fnode);
                }
            }

            Edge::add_edge(pnode, fnode, trace->action);
            break;
        }
        case SYS_close: {
            if (trace->ret == -1) break;
            i_ino = trace->obj.file.i_ino;
            fd = trace->obj.file.fd;
            if (!FileNode::have(i_ino)) {
                // log_warn("[close], can't find file inode %lu", i_ino);
                return EINVAL;
            }
            fnode = (FileNode*)pnode->get_node_by_fd(fd);
            if (fnode == NULL) {
                log_warn("close fail, fd %d is NULL, inode is %lu", fd, i_ino);
                break;
            }
            pnode->close(fd);
            Edge::add_edge(pnode, fnode, SYS_close);
            break;
        }
        case SYS_dup2: {
            if (trace->ret == -1) break;
            int oldfd = trace->obj.ops_dup.oldfd;
            int newfd = trace->obj.ops_dup.newfd;
            pnode->dup2(oldfd, newfd);
            break;
        }
        case SYS_fcntl: {
            if (trace->ret == -1) break;
            int oldfd = trace->obj.ops_fcntl.fd;
            int cmd = trace->obj.ops_fcntl.cmd;
            pnode->fcntl(oldfd, cmd, trace->ret);
            break;
        }
        case SYS_mkdir: {
            if (trace->ret == -1) break;
            i_ino = trace->obj.file.i_ino;
            filename = trace->str_data[0].c_str();
            fnode = pnode->mkdir(filename, i_ino);
            Edge::add_edge(pnode, fnode, SYS_mkdir);
            break;
        }
        case SYS_open: {
            // 返回值有可能是-2
            if (trace->ret < 0) break;
            i_ino = trace->obj.file.i_ino;
            fd = trace->obj.file.fd;
            filename = trace->str_data[0].c_str();
            fnode = pnode->open(filename, i_ino, fd);
            if (fnode == NULL) {
                log_warn("[open] can't find target file node");
                break;
            }
            Edge::add_edge(pnode, fnode, SYS_open);
            break;
        }
        case SYS_openat: {
            if (trace->ret < 0) break;
            i_ino = trace->obj.file.i_ino;
            dfd = trace->obj.file.dfd;
            fd = trace->obj.file.fd;
            filename = trace->str_data[0].c_str();
            fnode = pnode->openat(dfd, filename, i_ino, fd);
            if (fnode == NULL) {
                log_warn("[openat] can't find target file node");
                break;
            }

            Edge::add_edge(pnode, fnode, SYS_openat);
            break;
        }
        case SYS_copy_file_range: {
            if (trace->ret < 0) break;
            unsigned long i_ino_in = trace->obj.ops_copy_file_range.i_ino_in;
            int fd_in = trace->obj.ops_copy_file_range.fd_in;
            unsigned long i_ino_out = trace->obj.ops_copy_file_range.i_ino_out;
            int fd_out = trace->obj.ops_copy_file_range.fd_out;
            FileNode* fnode_in;
            FileNode* fnode_out;
            if (FileNode::have(i_ino_in)) {
                fnode_in = FileNode::file_nodes[i_ino_in];
            } else {
                fnode_in = (FileNode*)pnode->add_fd_from_proc(fd_in);
                if (fnode_in == NULL) {
                    fnode_in = new FileNode(i_ino_in, "null");
                    FileNode::file_nodes[i_ino_in] = fnode_in;
                    pnode->add_fd(fd_in, fnode_in);
                }
            }
            if (fnode_in == NULL) {
                log_warn("[copy_file_range] can't find fnode_in");
                break;
            }
            if (FileNode::have(i_ino_out)) {
                fnode_out = FileNode::file_nodes[i_ino_out];
            } else {
                fnode_out = (FileNode*)pnode->add_fd_from_proc(fd_out);
                if (fnode_out == NULL) {
                    fnode_out = new FileNode(i_ino_out, "null");
                    FileNode::file_nodes[i_ino_out] = fnode_out;
                }
            }
            if (fnode_out == NULL) {
                log_warn("[copy_file_range] can't find fnode_out");
                break;
            }
            Edge::add_edge(pnode, fnode_in, SYS_read);
            Edge::add_edge(pnode, fnode_out, SYS_write);
            break;
        }
        case SYS_renameat2: {
            if (trace->ret < 0) break;
            unsigned long old_i_ino = trace->obj.ops_rename.old_i_ino;
            int old_dfd = trace->obj.ops_rename.olddfd;
            unsigned long new_i_ino = trace->obj.ops_rename.new_i_ino;
            int new_dfd = trace->obj.ops_rename.newdfd;
            const char* newpath = trace->str_data[1].c_str();
            const char* oldpath = trace->str_data[0].c_str();

            if (old_i_ino == 0 && new_i_ino != 0)
                old_i_ino = new_i_ino;
            else if (new_i_ino == 0 && old_i_ino != 0)
                new_i_ino = old_i_ino;
            else if (old_i_ino == 0 && new_i_ino == 0) {
                log_error("Error i_ino, all 0");
                break;
            }

            fnode = pnode->renameat2(old_dfd, oldpath, new_dfd, newpath, new_i_ino, old_i_ino);
            Edge::add_edge(pnode, fnode, SYS_renameat2);
            break;
        }
        case SYS_utimensat:
        case SYS_fchownat:
        case SYS_fchmodat:
        case SYS_unlink:
        case SYS_unlinkat: {
            if (trace->ret == -1) break;
            i_ino = trace->obj.file.i_ino;
            dfd = trace->obj.file.dfd;
            filename = trace->str_data[0].c_str();

            fnode = pnode->add_filenode_by_dfd(dfd, filename, i_ino);
            Edge::add_edge(pnode, fnode, trace->action);
            break;
        }
        case SYS_connect: {
            if (trace->ret == -1) break;
            fd = trace->obj.ops_connect.fd;
            addr = (struct sockaddr_ipv4*)&trace->obj.ops_connect.addr;
            socknode = pnode->connect(fd, addr);
            Edge::add_edge(pnode, socknode, SYS_connect);
            break;
        }
        case SYS_sendto: {
            if (trace->ret == -1) break;
            fd = trace->obj.ops_send.fd;
            data = trace->str_data[0].c_str();

            socknode = (SocketNode*)pnode->get_node_by_fd(fd);
            if (socknode == NULL) {
                log_error("[sendto] local socket node is NULL, fd:%d", fd);
                break;
            }
            Edge::add_edge(pnode, socknode, SYS_sendto, data);
            break;
        }
        case SYS_recvfrom: {
            if (trace->ret == -1) break;
            fd = trace->obj.ops_recv.fd;
            data = trace->str_data[0].c_str();

            socknode = (SocketNode*)pnode->get_node_by_fd(fd);
            if (socknode == NULL) {
                log_error("[recvfrom] local socket node is NULL, fd:%d", fd);
                break;
            }
            Edge::add_edge(socknode, pnode, SYS_recvfrom, data);
            break;
        }
    }
    return 0;
}

void Repository::stop() {
    set_signal(END_SIGNAL);
}

int Repository::add_root_pid(unsigned int root_pid) {
    time_t now;
    char now_str[PATH_MAX];
    char path[PATH_MAX];
    if (ProcessNode::have(root_pid)) {
        log_error("Process %d has existed", root_pid);
        return -1;
    }

    ProcessNode* pnode = new ProcessNode(root_pid);
    ProcessNode::process_nodes[root_pid] = pnode;

    m_root_graph_id.push_back(pnode->get_graph_id());

    // 初始化输出文件地址，不含后缀
    log_info("add root processs:%d", root_pid);
    now = time(0);
    strftime(now_str, PATH_MAX, "%Y-%m-%d_%H-%M-%S", localtime(&now));
    snprintf(path, PATH_MAX, "%s/%s.cypher", m_config["output_dir"].asString().c_str(), now_str);

    m_cypher_file_path.push_back(path);
    m_cypher_file.push_back(new std::ofstream(path, std::ios::out));
    if (!m_cypher_file.back()->is_open()) {
        log_error("can't open file %s", path);
        return -1;
    }

    snprintf(path, PATH_MAX, "%s/%s.cypher.bak", m_config["output_dir"].asString().c_str(), now_str);
    m_cypher_file_bak.push_back(new std::ofstream(path, std::ios::out));
    if (!m_cypher_file_bak.back()->is_open()) {
        log_error("can't open file %s", path);
        return -1;
    }

    pnode->set_file_id(m_cypher_file_path.size()-1);

    return 0;
}

int Repository::del_root_pid(unsigned int root_pid) {
    if (!ProcessNode::have(root_pid)) {
        log_warn("delete fail, Process %d hasn't existed", root_pid);
        return -1;
    }

    ProcessNode::process_nodes[root_pid]->exit(time(0));
    return 0;
}

int Repository::init(Json::Value config) {
    char path[PATH_MAX];
    char now_str[PATH_MAX];
    std::regex reg("\\d+-\\d+-\\d+-\\d+-\\d+-\\d+\\.[a-z]+");
    DIR* p_dir;
    struct dirent* ptr;
    struct tm tm_file;
    time_t file_time, now;
    std::string dir_path;
    int max_save_time;
    Json::Value syscalls;
    int id;

    m_signal = NO_ACTION;
    m_config = config;
    dir_path = m_config["output_dir"].asString();
    max_save_time = m_config["file_save_time"].asInt() * 3600;

    // 初始化关注的系统调用集合
    syscalls = m_config["concern_syscalls"];
    std::shared_ptr<Manual> book = Manual::get_manual();
    for (auto syscall : syscalls) {
        id = book->get_syscall_id(syscall.asString().c_str());
        if (id < 0) {
            continue;
        }
        Edge::g_risk_syscalls.insert(id);
    }

    // 初始化trace输出文件地址
    now = time(0);
    strftime(now_str, PATH_MAX, "%Y-%m-%d_%H-%M-%S", localtime(&now));
    snprintf(path, PATH_MAX, "%s/%s.trace", dir_path.c_str(), now_str);
    m_trace_file_path = path;
    m_trace_file.open(path, std::ios::out);
    if(!m_trace_file.is_open()) {
        log_error("can't open file %s", path);
        return -1;
    }

    // 检查存储目录是否存在，并删除过期文件
    if (!(p_dir = opendir(dir_path.c_str()))) {
        log_error("output folder %s is missing", dir_path.c_str());
        return -1;
    }

    if (max_save_time == 0) {
        closedir(p_dir);
        return 0;
    }

    while ((ptr = readdir(p_dir)) != 0) {
        if (ptr->d_type != DT_REG) continue;
        if (!std::regex_match(ptr->d_name, reg)) continue;

        strptime(ptr->d_name, "%Y-%m-%d_%H-%M-%S", &tm_file);
        if (tm_file.tm_year == 0) continue;
        file_time = mktime(&tm_file);

        if (difftime(now, file_time) < max_save_time) continue;

        snprintf(path, PATH_MAX, "%s/%s", dir_path.c_str(), ptr->d_name);
        if (remove(path) == 0) {
            log_info("delete expired file:%s", path);
        }
    }
    closedir(p_dir);
    return 0;
}

int Repository::output_part(unsigned int max_output_num) {
    std::map<unsigned int, ProcessNode*>::iterator it_node;
    std::deque<Edge *>* edge_list;
    std::deque<Edge *>::iterator it_edge;   
    ProcessNode* pnode;
    Edge* edge;
    struct Trace* trace;
    char buf[BUF_SIZE];

    size_t output_num = 0;

    for (size_t i = 0; i < max_output_num && m_trace_repo.size() != 0; i++) {
        trace = m_trace_repo.front();
        trace->c_str(buf, sizeof(buf));
        m_trace_file << buf << std::endl;
        delete trace;
        m_trace_repo.pop_front();
        output_num += 1;    
    }

    // 让Monitor先处理完缓存任务。因为之后将释放部分节点与边，防止访问非法地址
    Monitor::get_Monitor()->wait_clean_buf();

    for (it_node = ProcessNode::process_nodes.begin(); it_node != ProcessNode::process_nodes.end();) {
        pnode = it_node->second;
        if (pnode->get_exit_time() == 0) {
            it_node++;
            continue;
        }

        edge_list = pnode->get_edge();
        for (it_edge = edge_list->begin();it_edge != edge_list->end();it_edge++) {
            edge = *it_edge;
            output_edge(edge);
            output_num += 1;
        }

        pnode->to_cypher(buf, BUF_SIZE);
        output_node(pnode, buf);
        output_num += 1;

        ProcessNode::process_nodes.erase(it_node++);
        delete_node(pnode);

        if (output_num >= max_output_num) {
            break;
        }
    }

    return output_num;
}

int Repository::output_all() {

    char buf[BUF_SIZE];
    char path[PATH_MAX];

    // 控制输出速率，防止CPU超标
    while (output_part(m_config["max_output_trace"].asUInt()) != 0) {
        usleep(100);
    }

    for (auto file_node : FileNode::file_nodes) {
        file_node.second->to_cypher(buf, BUF_SIZE);
        output_node(file_node.second, buf);
    }

    for (auto process_node : ProcessNode::process_nodes) {
        process_node.second->to_cypher(buf, BUF_SIZE);
        output_node(process_node.second, buf);
    }

    for (auto socket_node : SocketNode::socket_nodes) {
        socket_node.second->to_cypher(buf, BUF_SIZE);
        output_node(socket_node.second, buf);
    }

    for (auto pipe_node : PipeNode::pipe_nodes) {
        pipe_node.second->to_cypher(buf, BUF_SIZE);
        output_node(pipe_node.second, buf);
    }

    for (auto edge : Edge::edges) {
        output_edge(edge.second);
    }

    for (size_t i = 0; i < m_cypher_file_path.size(); i++) {
        m_cypher_file[i]->close();
        m_cypher_file_bak[i]->close();
        delete m_cypher_file[i];
        delete m_cypher_file_bak[i];
        snprintf(path, PATH_MAX, "%s.bak", m_cypher_file_path[i].c_str());        
        snprintf(buf, BUF_SIZE, "cat %s >> %s", path, m_cypher_file_path[i].c_str());

        if (system(buf)) {
            log_warn("copy edge backup file failed");
        }

        if (remove(path)) {
            log_warn("fail to delete cypher backup file %s", path);
        }        
    }

    m_cypher_file.clear();
    m_cypher_file_bak.clear();
    m_trace_file.close();

    return 0;
}

int Repository::output_node(Node* node, char* buf) {
    std::set<unsigned int>* file_id = node->get_file_id();
    std::set<unsigned int>::iterator it1 = file_id->begin();

    for(it1 = file_id->begin();it1 != file_id->end();it1++) {
        if (*it1 >= m_cypher_file.size()) {
            log_error("file id exceed the size of cypher file");
            continue;
        }
        *m_cypher_file[*it1] << buf << std::endl;
    }
    return 0;
}

int Repository::output_edge(Edge* edge) {
    char buf[BUF_SIZE];
    Node* node = edge->get_first();
    std::set<unsigned int>* file_id = node->get_file_id();
    std::set<unsigned int>::iterator it;
    edge->set_risk_level();
    edge->to_cypher(buf, BUF_SIZE);

    for(it = file_id->begin();it!= file_id->end(); it++) {
        if (*it >= m_cypher_file_bak.size()) {
            log_error("file id exceed the size of cypher backup file");
            continue;
        }
        *m_cypher_file_bak[*it] << buf << std::endl;
    }    
    return 0;
}

void Repository::set_signal(unsigned int signal) {
    m_signal |= signal;
    m_cv.notify_one();
}

void Repository::clear_signal(unsigned int signal) {
    m_signal &=~ signal;
}

void Repository::show_memory(const char* info) {
    unsigned int my_mem;
    malloc_trim(0);
    sleep(1);
    my_mem = get_proc_mem(getpid());
    log_info("%s: %u MB", info, my_mem);
}

int Repository::delete_all() {
    std::map<std::pair<Node*, Node*>, Edge*> edge_map;
    std::map<unsigned int, ProcessNode*> process_map;
    std::map<unsigned long, FileNode*> file_map;

    show_memory("before delete");
    log_info("edge size:%lu", Edge::edges.size());
    Edge::edges.swap(edge_map);
    Edge::edges.swap(edge_map);
    show_memory("swap edge");
    for (auto edge : Edge::edges) {
        delete edge.second;
    }
    Edge::edges.clear();
    show_memory("delete edge node");

    log_info("process size: %lu", ProcessNode::process_nodes.size());
    ProcessNode::process_nodes.swap(process_map);
    ProcessNode::process_nodes.swap(process_map);
    show_memory("swap process");
    for (auto process_node : ProcessNode::process_nodes) {
        delete process_node.second;
    }
    ProcessNode::process_nodes.clear();
    show_memory("clear process_nodes");

    for (auto file_node : FileNode::file_nodes) {
        delete file_node.second;
    }
    show_memory("delete file node");

    for (auto socket_node : SocketNode::socket_nodes) {
        delete socket_node.second;
    }
    show_memory("delete socket node");

    for (auto pipe_node : PipeNode::pipe_nodes) {
        delete pipe_node.second;
    }
    show_memory("delete pipe node");

    for (auto trace : m_trace_buf) {
        delete trace;
    }
    show_memory("delete trace_buf");

    for (auto trace : m_trace_repo) {
        delete trace;
    }

    m_trace_buf.clear();
    m_trace_buf.shrink_to_fit();
    show_memory("clear trace_buf");

    m_trace_repo.clear();
    m_trace_repo.shrink_to_fit();
    show_memory("clear trace_repo");

    FileNode::file_nodes.clear();
    FileNode::file_nodes.swap(file_map);
    show_memory("clear file_nodes");

    SocketNode::socket_nodes.clear();
    PipeNode::pipe_nodes.clear();
    show_memory("clear other nodes");

    return 0;
}

int Repository::swap_map() {
    std::map<std::pair<Node*, Node*>, Edge*> edges;
    std::map<unsigned long, FileNode*> files;
    std::map<unsigned long, PipeNode*> pipes;
    std::map<unsigned int, ProcessNode*> processes;
    std::map<struct sockaddr_ipv4, SocketNode*> sockets;

    Edge::edges.swap(edges);
    FileNode::file_nodes.swap(files);
    PipeNode::pipe_nodes.swap(pipes);
    ProcessNode::process_nodes.swap(processes);
    SocketNode::socket_nodes.swap(sockets);

    Edge::edges = std::move(edges);
    FileNode::file_nodes = std::move(files);
    PipeNode::pipe_nodes = std::move(pipes);
    ProcessNode::process_nodes = std::move(processes);
    SocketNode::socket_nodes = std::move(sockets);

    malloc_trim(0);
    return 0;
}
