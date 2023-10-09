#ifndef __LOG_H
#define __LOG_H

#include <map>
#include <json/json.h>
#include <log4cplus/log4cplus.h>

#define log_debug(...) LOG4CPLUS_DEBUG_FMT(m_log, __VA_ARGS__)
#define log_info(...) LOG4CPLUS_INFO_FMT(m_log, __VA_ARGS__)
#define log_warn(...) LOG4CPLUS_WARN_FMT(m_log, __VA_ARGS__)
#define log_error(...) LOG4CPLUS_ERROR_FMT(m_log, __VA_ARGS__)

class LoggerFactory {
public:
    static log4cplus::Logger create_logger(std::string module_name);
    static void init(Json::Value config);

private:
    static log4cplus::SharedAppenderPtr m_console_appender;
    static log4cplus::SharedAppenderPtr m_file_appender;
    // Initializer必须是全局变量，一旦释放日志出错
    static log4cplus::Initializer m_initalizer;
};

#endif