#include <unistd.h>
#include <iostream>
#include <mutex>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include "model/Consumer.h"
#include "model/Repository.h"

static std::shared_ptr<Consumer> m_consumer = nullptr;
static std::once_flag create_flag;

bool compareTrace(Trace*& v1, Trace*& v2) {
    return v1->ts > v2->ts;
}

Consumer::Consumer() {
    m_signal = NO_ACTION;
    memset(m_last_ptr, 0, sizeof(m_last_ptr));
    m_log = LoggerFactory::create_logger("Consumer");
}

// int Consumer::init(BPFMap *trace_map, BPFMap *trace_ptr_map)
int Consumer::init(int trace_fd, int trace_ptr_fd, int str1_fd, int str2_fd, int str3_fd, int arg_strings_fd) {
    if (trace_fd <= 0 || trace_ptr_fd <= 0 || str1_fd <= 0 || str2_fd <= 0 || str3_fd <= 0) {
        log_error("map fd is less than 0, please check");
        return -1;
    }
    m_trace_map_fd = trace_fd;
    m_trace_ptr_map_fd = trace_ptr_fd;
    m_str1_map_fd = str1_fd;
    m_str2_map_fd = str2_fd;
    m_str3_map_fd = str3_fd;
    m_arg_strings_map_fd = arg_strings_fd;
    return 0;
}

void Consumer::notify() {
    m_cv.notify_one();
}

std::shared_ptr<Consumer> Consumer::get_consumer() {
    std::call_once(create_flag, [&] { m_consumer = std::shared_ptr<Consumer>(new Consumer()); });
    return m_consumer;
}

void Consumer::handle() {
    int store_size = 0;
    read_trace_map();
    store_size = m_trace_buf.size();
    while (store_size > 0) {
        /** trace数据会在repo中根据时序与关联关系补全信息。但是在采集过程
         * 会因为多核机制导致时序的混乱。例如read的trace记录在open之前被读
         * 取。为了防止这种情况，使用优先队列保存连续两轮读取到的trace记录，
         * 并按照时序排序，每次只处理上一轮的trace数目。
         */
        read_trace_map();
        for (int i = 0; i < store_size; ++i) {
            Repository::get_repository()->store_trace(m_trace_buf.top());
            m_trace_buf.pop();
        }
        store_size = m_trace_buf.size();
    }
}

void Consumer::start() {
    std::unique_lock<std::mutex> lock(m_mutex);
    while ((m_signal & END_SIGNAL)==0) {
        m_cv.wait_for(lock, std::chrono::milliseconds(100));
        handle();
    }
    log_info("consumer stop");
}

// 读取字符串信息
int Consumer::fill_trace(struct Trace* trace, int* index) {
    char data[STR_BUF_SIZE];
    data[0] = '\0';
    switch (trace->action) {
        case SYS_chdir:
        case SYS_open:
        case SYS_openat:
        case SYS_mkdir:
        case SYS_fchownat:
        case SYS_fchmodat:
        case SYS_unlinkat:
        case SYS_unlink:
        case SYS_recvfrom:
        case SYS_sendto:
        case SYS_utimensat:
        case SYS_writev:
        case SYS_delete_module:
        case SYS_finit_module:
            // 不要对返回值判断，即使data为null也要添加，否则会引发异常
            bpf_map_lookup_elem(m_str1_map_fd, index, data);
            trace->str_data.push_back(data);
            break;
        case SYS_renameat2:
            bpf_map_lookup_elem(m_str1_map_fd, index, data);
            trace->str_data.push_back(data);

            data[0] = '\0';
            bpf_map_lookup_elem(m_str2_map_fd, index, data);
            trace->str_data.push_back(data);
            break;
        case SYS_execve:
            bpf_map_lookup_elem(m_str1_map_fd, index, data);
            trace->str_data.push_back(data);

            data[0] = '\0';
            bpf_map_lookup_elem(m_str2_map_fd, index, data);
            trace->str_data.push_back(data);

            data[0] = '\0';
            bpf_map_lookup_elem(m_str3_map_fd, index, data);
            trace->str_data.push_back(data);
            // 读取完整命令
            struct cmd_args{
                char inner_str[MAX_ARG_LENGTH];
            } ;
            struct cmd_args value;
            bpf_map_lookup_elem(m_arg_strings_map_fd, index, &value);
            trace->arg_str = value.inner_str;

            break;
        default:
            break;
    }
    return 0;
}

void Consumer::stop() {
    set_signal(END_SIGNAL);
}

int Consumer::read_trace_map() {
    unsigned int trace_ptr;
    struct Trace* trace;
    int index, ret;
    int diff;

    for (int i = 0; i < CPU_NUM; i++) {
        ret = bpf_map_lookup_elem(m_trace_ptr_map_fd, &i, &trace_ptr);
        if (ret) {
            log_warn("read data from trace_ptr map failed, %s", strerror(errno));
            continue;
        }
        // 假设ENTRY_NUM_PER_CPU是10，读取位置m_last_ptr为25，写入位置trace_ptr是38，则调整m_last_ptr为29。防止重复读取。
        diff = trace_ptr - m_last_ptr[i];
        if (diff > ENTRY_NUM_PER_CPU) {
            log_error("lose trace, user ptr: %d, kernel ptr: %d, diff: %d", m_last_ptr[i], trace_ptr, diff);
            m_last_ptr[i] = trace_ptr - ENTRY_NUM_PER_CPU + 1;
        }

        // 处理遗留任务
        std::deque<int>::iterator pos;
        for (pos = m_not_ready_trace[i].begin(); pos != m_not_ready_trace[i].end();) {
            // 丢弃被覆盖的trace
            if (trace_ptr - *pos > ENTRY_NUM_PER_CPU) {
                log_warn("lose not ready trace");
                pos = m_not_ready_trace[i].erase(pos);
                continue;
            }
            trace = new Trace();
            index = i * ENTRY_NUM_PER_CPU + *pos % ENTRY_NUM_PER_CPU;
            ret = bpf_map_lookup_elem(m_trace_map_fd, &index, trace);
            if (ret) {
                log_warn("read trace map failed, %s", strerror(errno));
                delete trace;
                pos++;
                continue;
            }
            if (trace->ready == 0) {
                delete trace;
                pos++;
                continue;
            }
            if (trace->ready == 2) {
                delete trace;
                pos = m_not_ready_trace[i].erase(pos);
                continue;
            }

            fill_trace(trace, &index);
            m_trace_buf.push(trace);
            pos = m_not_ready_trace[i].erase(pos);
        }

        while (m_last_ptr[i] < trace_ptr) {
            // Allocate memory for trace record
            trace = new Trace();
            index = i * ENTRY_NUM_PER_CPU + m_last_ptr[i] % ENTRY_NUM_PER_CPU;
            ret = bpf_map_lookup_elem(m_trace_map_fd, &index, trace);
            if (ret) {
                log_warn("read trace map failed, %s", strerror(errno));
                delete trace;
                m_last_ptr[i] += 1;
                continue;
            }

            if (trace->ready == 0) {
                m_not_ready_trace[i].push_back(m_last_ptr[i]);
                delete trace;
                m_last_ptr[i] += 1;
                continue;
            }

            if (trace->ready == 2) {
                delete trace;
                m_last_ptr[i] += 1;
                continue;
            }

            fill_trace(trace, &index);
            m_trace_buf.push(trace);
            m_last_ptr[i] += 1;
        }
    }
    return 0;
}

void Consumer::set_signal(unsigned int signal) {
    m_signal |= signal;
    m_cv.notify_one();
}

void Consumer::clear_signal(unsigned int signal) {
    m_signal &=~ signal;
}