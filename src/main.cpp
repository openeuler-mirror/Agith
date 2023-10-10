#include <stdio.h>
#include <functional>
#include <memory>
#include <csignal>

#include <fcntl.h>
#include <unistd.h>
#include <json/json.h>
#include <sys/file.h>
#include "tool/utils.h"
#include "model/Controller.h"
#include "tool/Log.h"

int main(int argn, char** argv) {
    unsigned int tgid = 0;
    char config_file[PATH_MAX];
    std::ifstream file;
    Json::Value config;
    int stop_flag;

    // 读取参数
    parse_opt(argn, argv, &tgid, config_file, PATH_MAX, &stop_flag);

    // 读取配置文件
    file.open(config_file, std::ios::binary);
    if (!file.is_open()) {
        printf("can't find configure file:%s\n", config_file);
        return -1;
    }
    file >> config;
    file.close();

    // 初始化日志模块
    LoggerFactory::init(config["Log"]);

    std::shared_ptr<Controller> p_controller = Controller::get_controller();
    if (stop_flag) {
        p_controller->set_signal(END_SIGNAL);
        return 0;
    }
    if (p_controller->init(config)) {
        goto clean;
    }

    if (tgid > 0 && p_controller->set_pid_target(tgid)) {
        goto clean;
    }

    p_controller->start();

clean:    
    p_controller->stop();
    return 0;
}