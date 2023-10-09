#include <mutex>
#include <fstream>
#include <memory>
#include <unistd.h>
#include <json/json.h>
#include "model/Monitor.h"
#include "tool/Manual.h"
#include "tool/utils.h"

static std::shared_ptr<Monitor> m_monitor = nullptr;
static std::once_flag create_flag;

std::shared_ptr<Monitor> Monitor::get_Monitor() {
    std::call_once(create_flag, [&] { m_monitor = std::shared_ptr<Monitor>(new Monitor()); });
    return m_monitor;
}

Monitor::Monitor() {
    m_signal = NO_ACTION;
    m_log = LoggerFactory::create_logger("Monitor");
}

int Monitor::init(Json::Value conf) {
    std::shared_ptr<Manual> book = Manual::get_manual();
    Json::Value syscalls;
    Json::Value maintainer;
    char contact[PATH_MAX];
    int id;

    syscalls = conf["risk_syscalls"];
    for (auto syscall : syscalls) {
        id = book->get_syscall_id(syscall.asString().c_str());
        if (id < 0) {
            continue;
        }
        m_risk_syscalls.insert(id);
    }

    maintainer = conf["maintainer"];
    for (auto item : maintainer) {
        snprintf(contact, sizeof(contact), "name:%s, email:%s", item["name"].asString().c_str(),
                 item["email"].asString().c_str());
        m_contacts.push_back(contact);
    }
    return 0;
}

void Monitor::start() {
    std::unique_lock<std::mutex> lock(m_mutex);
    while ((m_signal & END_SIGNAL) == 0) {
        m_cv.wait(lock);
        while (!m_syscall_buf.empty()) {
            if (m_risk_syscalls.count(m_syscall_buf.front())) {
                send_alert(m_trace_buf.front());
            }
            m_trace_buf.pop_front();
            m_syscall_buf.pop_front();
        }
        
    }
    log_info("monitor stop");
}

void Monitor::stop() {
    set_signal(END_SIGNAL);
}

int Monitor::send_alert(Edge* edge) {
    // TODO
    // Json::Value value;
    // edge->to_json(value);

    // Json::StreamWriterBuilder builder;
    // builder["commentStyle"] = "None";
    // builder["indentation"] = "";

    // std::string output = Json::writeString(builder, value);
    // log_error("risk syscall: %s", output.c_str());
    return 0;
}

int Monitor::analyse_trace(int syscall_id, Edge* edge) {
    if (edge == NULL) {
        log_error("Edge is NULL ,can't analyse");
        return -1;
    }
    m_syscall_buf.push_back(syscall_id);
    m_trace_buf.push_back(edge);
    m_cv.notify_one();
    return 0;
}

void Monitor::wait_clean_buf() {
    while(!m_syscall_buf.empty()) {
        m_cv.notify_one();
        usleep(1);
    }
}

void Monitor::set_signal(unsigned int signal) {
    m_signal |= signal;
    m_cv.notify_one();
}

void Monitor::clear_signal(unsigned int signal) {
    m_signal &=~ signal;
}