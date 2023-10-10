#include <log4cplus/log4cplus.h>
#include "tool/utils.h"
#include "tool/Log.h"
#include "tool/Manual.h"
#include "graph/Edge.h"
#include "graph/FileNode.h"
#include "graph/PipeNode.h"
#include "graph/ProcessNode.h"
#include "graph/SocketNode.h"

using namespace log4cplus;
using namespace log4cplus::helpers;

SharedAppenderPtr LoggerFactory::m_console_appender(nullptr);
SharedAppenderPtr LoggerFactory::m_file_appender(nullptr);

void LoggerFactory::init(Json::Value config) {
    std::string log_path = config["path"].asString();
    log4cplus::tstring pattern = LOG4CPLUS_TEXT("%-12c%d %-5p: %m [%l]%n");
    m_console_appender = new ConsoleAppender();
    m_console_appender->setName(LOG4CPLUS_TEXT("console"));
    m_console_appender->setLayout(std::unique_ptr<Layout>(new PatternLayout(pattern)));

    m_file_appender = new RollingFileAppender(LOG4CPLUS_TEXT(log_path.c_str()), 5 * 1024 * 1024, 5, false, true);
    m_file_appender->setName(LOG4CPLUS_TEXT("file"));
    m_file_appender->setLayout(std::unique_ptr<Layout>(new PatternLayout(pattern)));
}

Logger LoggerFactory::create_logger(std::string module_name) {
    Logger logger = Logger::getInstance(LOG4CPLUS_TEXT(module_name.c_str()));
    logger.addAppender(m_console_appender);
    logger.addAppender(m_file_appender);
    logger.setLogLevel(INFO_LOG_LEVEL);
    return logger;
}