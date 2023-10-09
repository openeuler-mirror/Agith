#include <tool/Manual.h>
#include <mutex>
#include <fstream>
#include <json/json.h>
#include "tool/utils.h"

static std::shared_ptr<Manual> m_syscall_helper = nullptr;
static std::once_flag create_flag;

std::shared_ptr<Manual> Manual::get_manual() {
    std::call_once(create_flag, [&] { m_syscall_helper = std::shared_ptr<Manual>(new Manual()); });
    return m_syscall_helper;
}

Manual::Manual() {
    m_log = LoggerFactory::create_logger("Manual");
}

int Manual::init(Json::Value config) {
    std::string path = config["path"].asString();
    std::string syscall_name;
    int begin, end, syscall_id;
    std::ifstream file;
    file.open(path.c_str(), std::ios::in);
    if (!file.is_open()) {
        log_error("no such file %s", path.c_str());
        return -1;
    }
    for (std::string line; std::getline(file, line);) {
        if (line[0] < '0' || line[0] > '9') {
            continue;
        }
        begin = 0;
        end = line.find("\t");
        syscall_id = stoi(line.substr(begin, end - begin));

        begin = end + 1;
        end = line.find("\t", begin);
        if (line.substr(begin, end - begin).compare("x32") == 0) {
            continue;
        }

        begin = end + 1;
        end = line.find("\t", begin);
        syscall_name = line.substr(begin, end - begin);

        if (m_syscall_name.find(syscall_name) == m_syscall_name.end()) {
            m_syscall_name[syscall_name] = syscall_id;
            m_syscall_id[syscall_id] = syscall_name;
        } else {
            log_warn("find same syscall, name: %s, new id: %d, old id: %d", syscall_name.c_str(), syscall_id,
                     m_syscall_name[syscall_name]);
        }
    }
    file.close();

    m_socket_type[1] = "SOCK_STREAM";
    m_socket_type[2] = "SOCK_DGRAM";
    m_socket_type[3] = "SOCK_RAW";
    m_socket_type[4] = "SOCK_RDM";
    m_socket_type[5] = "SOCK_SEQPACKET";
    m_socket_type[6] = "SOCK_DCCP";
    m_socket_type[10] = "SOCK_PACKET";
    m_socket_type[524288] = "SOCK_CLOEXEC";
    m_socket_type[2048] = "SOCK_NONBLOCK";

    m_socket_family[2] = "AF_INET";
    m_socket_family[10] = "AF_INET6";
    m_socket_family[1] = "AF_UNIX";

    m_signal_name[NO_ACTION] = "NO_ACTION";
    m_signal_name[END_SIGNAL] = "END_SIGNAL";
    m_signal_name[SWAP_MEMORY] = "SWAP_MEMORY";
    m_signal_name[OUTPUT_USELESS] = "OUTPUT_USELESS";

    return 0;
}

const char* Manual::get_socket_family_name(unsigned long family) {
    if (m_socket_family.find(family) == m_socket_family.end()) {
        log_warn("socket family %lu not in table", family);
        return NULL;
    }
    return m_socket_family[family].c_str();
}

const char* Manual::get_socket_type_name(unsigned long type) {
    if (m_socket_type.find(type) == m_socket_type.end()) {
        log_warn("socket type %lu not in table", type);
        return NULL;
    }
    return m_socket_type[type].c_str();
}

const char* Manual::get_syscall_name(unsigned int syscall_id) {
    if (m_syscall_id.find(syscall_id) == m_syscall_id.end()) {
        log_warn("syscall id %d not in table!", syscall_id);
        return NULL;
    }
    return m_syscall_id[syscall_id].c_str();
}

const char* Manual::get_signal_name(unsigned int signal) {
    if (m_signal_name.find(signal) == m_signal_name.end()) {
        log_warn("signal %d not in table!", signal);
        return NULL;
    }
    return m_signal_name[signal].c_str();
}

int Manual::get_syscall_id(const char* syscall_name) {
    std::string name = syscall_name;
    if (m_syscall_name.find(name) == m_syscall_name.end()) {
        log_warn("syscall name %s not in table!", syscall_name);
        return -1;
    }
    return m_syscall_name[name];
}

