#ifndef __OPERATOR_H
#define __OPERATOR_H
#include <unistd.h>
#include <string>
#include <map>

struct Command {
    // 控制位，0：为空，可写；1：不空，可读；-1：程序终止
    int ctrl;
    char cmd[256];
};

class Operator {
public:
    static Operator* hire_operator(std::string name);
    static Operator* call_operator(std::string name);
    static int fire_all();

    pid_t getpid();
    int start();
    int stop();
    int run(std::string cmd);
    const char* getcwd(char* path, size_t size);

private:
    Operator(const char* name);
    int bash();
    int m_pid;
    int m_pipe_fd[2];
    int m_out_fd;
    static std::map<std::string, Operator*> m_contacts;
};

#endif