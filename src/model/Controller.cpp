#include <mutex>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <functional>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>

#include "model/Controller.h"
#include "model/Monitor.h"
#include "model/Repository.h"
#include "tool/utils.h"
#include "graph/Edge.h"
#include "graph/FileNode.h"
#include "graph/SocketNode.h"
#include "graph/PipeNode.h"
#include "graph/ProcessNode.h"
#include "tool/MessageQueue.h"

static std::shared_ptr<Controller> m_controller = nullptr;
static std::once_flag create_flag;
const char* Controller::m_pid_file_path = "/var/run/Agith.pid";

Controller::Controller() : 
    m_bpf_loader() , 
    m_mq("/Agith_mq", 10) {
    m_signal = NO_ACTION;
    m_log = LoggerFactory::create_logger("Controller");
    m_os_cpu = get_os_cpu_time();
    m_my_cpu = get_proc_cpu_time(getpid());
    m_pid_file_fd = lock();
    p_perf_buffer = NULL;
}

std::shared_ptr<Controller> Controller::get_controller() {
    std::call_once(create_flag, [&] { m_controller = std::shared_ptr<Controller>(new Controller()); });
    return m_controller;
}

int Controller::set_pid_target(pid_t pid) {
    int map_fd, ret;
    char path[PATH_MAX];
    struct AgithMessage msg;

    if (pid <= 0) {
        log_error("aim process %d is invalid", pid);
        return -1;
    }

    if (!is_master()) {
        msg.type = MQType::mq_add_aim;
        msg.pid = pid;
        m_mq.send_message(&msg);
        return 0;
    }

    snprintf(path, PATH_MAX, "/proc/%d", pid);
    if (access(path, F_OK)) {
        log_error("aim process %d doesn't exist", pid);
        return -1;
    }   

    if (std::find(m_root_tgid.begin(), m_root_tgid.end(), pid) != m_root_tgid.end()) {
        log_error("aim process %d exist in target map", pid);
        return -1;
    }

    map_fd = m_bpf_loader.get_map_fd(PID_TARGET_MAP);
    if (map_fd < 0) {
        log_error("Can't find map %s", PID_TARGET_MAP);
        return ENOENT;
    }

    ret = bpf_map_update_elem(map_fd, &pid, &pid, BPF_NOEXIST);
    if (ret) {
        log_error("write initial aim failed, %s", strerror(errno));
        return -1;
    }
    m_root_tgid.push_back(pid);

    ret = Repository::get_repository()->add_root_pid(pid);
    if (ret) {
        log_error("fail to add process %d into Repository", pid);
        m_root_tgid.pop_back();
        return -1;
    }
    return 0;
}

int Controller::clear_target() {
    int map_fd;
    pid_t pid_key, pid_next_key;
    long file_key, file_next_key;

    map_fd = m_bpf_loader.get_map_fd(PID_TARGET_MAP);
    while (bpf_map_get_next_key(map_fd, &pid_key, &pid_next_key) == 0) {
        bpf_map_delete_elem(map_fd, &pid_next_key);
        pid_key = pid_next_key;
    }

    for(auto pid: m_root_tgid) {
        bpf_map_update_elem(map_fd, &pid, &pid, BPF_NOEXIST);
    }

    map_fd = m_bpf_loader.get_map_fd(FILE_TARGET_MAP);
    while (bpf_map_get_next_key(map_fd, &file_key, &file_next_key) == 0) {
        bpf_map_delete_elem(map_fd, &file_next_key);
        file_key = file_next_key;
    }

    return 0;
}

int Controller::clear_repeat_trace_map() {
    int map_fd;
    struct pid_syscall_obj_key repeat_trace_key;
    struct pid_syscall_obj_key next_repeat_trace_key;
    map_fd = m_bpf_loader.get_map_fd(REPEAT_TRACE_MAP);
    while (bpf_map_get_next_key(map_fd, &repeat_trace_key, &next_repeat_trace_key) == 0) {
        bpf_map_delete_elem(map_fd, &next_repeat_trace_key);
        repeat_trace_key = next_repeat_trace_key;
    }
    return 0;
}

void handler(int sig) {
    Controller::get_controller()->set_signal(END_SIGNAL);
}

int Controller::init(Json::Value config) {
    int ret;
    struct rlimit limit;
    struct sigaction sa;

    if (!is_master()) {
        return 0;
    }

    log_info("set interrupt signal handle function");
    sa.sa_flags = 0;
    sa.sa_handler = handler;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        log_error("error in setting interrupt signal");
        return -1;
    }   

    m_root_config = config;
    m_config = m_root_config["Controller"];

    log_info("initializing log module...");
    init_log_module();

    log_info("set memory limit as infinity");
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    ret = setrlimit(RLIMIT_MEMLOCK, &limit); 
    if (ret) {
        log_error("set memory limit failed");
        return ret;
    }

    m_config["cpu_num"] = sysconf(_SC_NPROCESSORS_ONLN);

    log_info("initialize dictionary...");
    ret = Manual::get_manual()->init(m_root_config["Manual"]);
    if (ret) {
        log_error("initialize dictionary fail");
        return ret;
    }

    ret = init_monitor();
    if (ret) {
        log_error("initialize monitor module fail");
        return ret;
    }

    ret = init_repository();
    if (ret) {
        log_error("initialize repository module fail");
        return ret;
    }

    log_info("initialize bpf map...");
    ret = m_bpf_loader.init(m_root_config["BPFLoader"]);
    if (ret) {
        log_error("initialize bpfloader fail");
        return ret;
    }
    ret = m_bpf_loader.load_map();
    if (ret) {
        log_error("load bpf map fail");
        return ret;
    }

    log_info("initialize perf event buffer...");
    ret = init_perf_event();
    if (ret) {
        log_error("initialize perf event buffer fail");
        return ret;
    }

    ret = init_consumer();
    if (ret) {
        log_error("initialize consumer module failed!");
        return ret;
    }

    log_info("Load eBPF Probe...");
    ret = m_bpf_loader.load_all_prog();
    if (ret) {
        log_error("load probe failed!");
        return ret;
    }

    return 0;
}

void handle_perf_event(void* ctx, int flag, void* event, __u32 data_size) {
    Consumer::get_consumer()->notify();
}

int Controller::init_perf_event() {
    m_perf_event_map_fd = m_bpf_loader.get_map_fd(PERF_EVENT_MAP);
    p_perf_buffer = perf_buffer__new(m_perf_event_map_fd, 8, handle_perf_event, nullptr, nullptr, &m_perf_buf_opts);

    if (libbpf_get_error(p_perf_buffer)) {
        log_error("Failed to create perf buffer");
        perf_buffer__free(p_perf_buffer);
        return -1;
    }
    return 0;
}

int Controller::init_consumer() {
    log_info("Initialize Consumer Module...");
    int trace_fd = m_bpf_loader.get_map_fd(TRACE_MAP);
    int trace_ptr_fd = m_bpf_loader.get_map_fd(TRACE_PTR_MAP);
    int str1_fd = m_bpf_loader.get_map_fd(STR1_MAP);
    int str2_fd = m_bpf_loader.get_map_fd(STR2_MAP);
    int str3_fd = m_bpf_loader.get_map_fd(STR3_MAP);

    if (Consumer::get_consumer()->init(trace_fd, trace_ptr_fd, str1_fd, str2_fd, str3_fd)) {
        return -1;
    }

    m_consumer_thread = std::thread(std::bind(&Consumer::start, Consumer::get_consumer()));
    return 0;
}

int Controller::init_monitor() {
    log_info("Initialize Monitor Module...");
    Monitor::get_Monitor()->init(m_root_config["Monitor"]);
    m_monitor_thread = std::thread(std::bind(&Monitor::start, Monitor::get_Monitor()));
    return 0;
}

int Controller::init_repository() {
    log_info("Initialize Repository Module...");
    int ret = Repository::get_repository()->init(m_root_config["Repository"]);
    if (ret) {
        return ret;
    }
    m_repository_thread = std::thread(std::bind(&Repository::start, Repository::get_repository()));
    return 0;
}

int Controller::start() {
    int err = 0;
    struct timespec now = {0, 0};
    struct timespec last_time_check_cpu = {0, 0};
    struct timespec last_time_check_aim = {0, 0};
    struct timespec last_time_clear_map = {0, 0};
    struct timespec last_time_handle_mq = {0, 0};

    if (!is_master()) {
        return 0;
    }

    log_info("Monitor Start, PRESS CTRL+C TO STOP...");
    clock_gettime(CLOCK_MONOTONIC, &now);
    last_time_check_aim = now;
    last_time_check_cpu = now;
    last_time_clear_map = now;
    last_time_handle_mq = now;

    while ((m_signal & END_SIGNAL) == 0) {
        err = perf_buffer__poll(p_perf_buffer, 100 /* time, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            log_info("received Ctrl-C signal, STOP");
            break;
        }
        if (err < 0) {
            log_error("polling perf buffer failed: %d", err);
            break;
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - last_time_check_aim.tv_sec > 1 /*time, s*/) {
            last_time_check_aim = now;
            // 检查目标进程是否存在
            if (check_root_tgid() == 0) {
                log_info("process aim finished, STOP");
                break;
            }
        }

        if (now.tv_sec - last_time_check_cpu.tv_sec > m_config["check_cpu_mem_duration"].asUInt()) {
            last_time_check_cpu = now;
            check_cpu_mem();
        }

        if (now.tv_sec - last_time_clear_map.tv_sec > 1 /* time, s*/) {
            last_time_clear_map = now;
            clear_repeat_trace_map();
        }

        if (now.tv_sec - last_time_handle_mq.tv_sec > 1) {
            last_time_handle_mq = now;
            handle_mq();
        }
    }
    return 0;
}

int Controller::stop() {
    if (!is_master()) {
        return 0;
    }

    if (m_consumer_thread.joinable()) {
        Consumer::get_consumer()->stop();
        m_consumer_thread.join();
    }

    if (m_monitor_thread.joinable()) {
        Monitor::get_Monitor()->stop();
        m_monitor_thread.join();
    }

    if (m_repository_thread.joinable()) {
        Repository::get_repository()->stop();
        m_repository_thread.join();
    }

    if (m_pid_file_fd != -1) {
        m_mq.unlink_mq();
    }

    perf_buffer__free(p_perf_buffer);
    log_info("controller stop");    
    return 0;
}

int Controller::check_cpu_mem() {
    unsigned long os_cpu, my_cpu, my_mem;
    float cpu_ratio;
    int my_tgid = getpid();

    os_cpu = get_os_cpu_time();
    my_cpu = get_proc_cpu_time(my_tgid);
    cpu_ratio = (my_cpu - m_my_cpu) * 100.0 / (os_cpu - m_os_cpu);
    cpu_ratio *= m_config["cpu_num"].asInt();
    m_os_cpu = os_cpu;
    m_my_cpu = my_cpu;

    my_mem = get_proc_mem(my_tgid);

    if (my_mem > m_config["max_memory"].asUInt()) {
        log_info("Performance cpu ratio: %.2f%%, mem: %lu MB, swap memory", cpu_ratio, my_mem);
        Repository::get_repository()->set_signal(SWAP_MEMORY);
    }

    if (cpu_ratio > m_config["max_cpu"].asFloat()) {
        log_info("Performance cpu ratio: %.2f%%, mem: %lu MB, reset initial target", cpu_ratio, my_mem);
        clear_target();
    }
    return 0;
}

int Controller::lock() {
    int ret;
    struct flock lock;    
    int buf_size = LONG_STR_SIZE;
    char buf[buf_size];

    m_pid_file_fd = open(m_pid_file_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (m_pid_file_fd < 0) {
        log_error("can't open pid file:%s", m_pid_file_path);
        return -1;
    }

    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;    
    lock.l_start = 0;
    lock.l_len = buf_size;

    ret = fcntl(m_pid_file_fd, F_SETLK, &lock);
    if (ret) {
        close(m_pid_file_fd);
        m_pid_file_fd = -1;
        return -1;
    }    

    snprintf(buf, buf_size, "%ld\n", (long)getpid());
    write(m_pid_file_fd, buf, buf_size);
    return m_pid_file_fd;    
}

int Controller::unlock() {
    struct flock lock;
    int buf_size = LONG_STR_SIZE;
    int ret;

    if (m_pid_file_fd < 0) {
        return -1;
    }

    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = buf_size;

    ret = fcntl(m_pid_file_fd, F_SETLK, &lock);
    if (ret) {
        log_error("unlock pid file failed!");
        return -1;
    }

    close(m_pid_file_fd);
    m_pid_file_fd = -1;
    remove(m_pid_file_path);
    return 0;
}

int Controller::init_log_module() {
    Edge::m_log = LoggerFactory::create_logger("Edge");
    FileNode::m_log = LoggerFactory::create_logger("FileNode");
    ProcessNode::m_log = LoggerFactory::create_logger("ProcessNode");
    SocketNode::m_log = LoggerFactory::create_logger("SocketNode");
    PipeNode::m_log = LoggerFactory::create_logger("PipeNode");
    MessageQueue::m_log = LoggerFactory::create_logger("MessageQueue");  
    return 0;  
}

int Controller::check_root_tgid() {
    char path[PATH_MAX];
    std::vector<pid_t> tmp_pid;
    for (auto pid: m_root_tgid) {
        snprintf(path, sizeof(path), "/proc/%d", pid);
        if (access(path, F_OK)) {
            Repository::get_repository()->del_root_pid(pid);
        } else {
            tmp_pid.push_back(pid);
        }
    }

    m_root_tgid.clear();
    for(auto pid:tmp_pid) {
        m_root_tgid.push_back(pid);
    }

    return m_root_tgid.size();
}


int Controller::handle_mq() {
    struct AgithMessage msg;
    while(m_mq.recv_message(&msg) > 0) {
        switch (msg.type)
        {
        case MQType::mq_add_aim:
            log_info("receive msg: add process target %d", msg.pid);
            set_pid_target(msg.pid);
            break;
        case MQType::mq_stop:
            log_info("receive msg: stop Agith");
            set_signal(END_SIGNAL);
            break;
        
        default:
            log_info("receive msg: unknown");
            break;
        }
    }
    return 0;
}

int Controller::is_master() {
    if (m_pid_file_fd > 0) {
        return 1;
    } else {
        return 0;
    }
}

void Controller::set_signal(unsigned int signal) {
    struct AgithMessage msg;
    if (is_master()) {
        m_signal |= signal;
        return;
    }

    if (signal & END_SIGNAL) {
        msg.type = MQType::mq_stop;
        m_mq.send_message(&msg);
        return;  
    }    
}

void Controller::clear_signal(unsigned int signal) {
    m_signal &=~ signal;
}
