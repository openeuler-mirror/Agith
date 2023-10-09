#ifndef __SYSCALLHELPER_H__
#define __SYSCALLHELPER_H__

#include <memory>
#include <json/json.h>
#include "tool/Log.h"

#define NO_ACTION       0x00 // (ALL) 无操作
#define END_SIGNAL      0x01 // (ALL) 停止
#define SWAP_MEMORY     0x02 // (Repository) 整理数据结构
#define OUTPUT_USELESS  0x04 // (Repository) 将无用数据输出

class Manual {
public:
    const char* get_syscall_name(unsigned int syscall_id);
    const char* get_socket_family_name(unsigned long family);
    const char* get_socket_type_name(unsigned long type);
    const char* get_signal_name(unsigned int signal);
    int get_syscall_id(const char* syscall_name);
    static std::shared_ptr<Manual> get_manual();
    int init(Json::Value config);

private:
    Manual();
    log4cplus::Logger m_log;
    std::map<std::string, int> m_syscall_name;
    std::map<unsigned int, std::string> m_syscall_id;
    std::map<unsigned long, std::string> m_socket_family;
    std::map<unsigned long, std::string> m_socket_type;
    std::map<unsigned int, std::string> m_signal_name;
    Json::Value m_config;
};

#endif
