#include "Operator.h"
#include <sys/wait.h>
#include <fcntl.h>

std::map<std::string, Operator*> Operator::m_contacts = std::map<std::string, Operator*>();

Operator* Operator::hire_operator(std::string name) {
    int ret = 0;
    if (m_contacts.find(name) != m_contacts.end()) {
        return m_contacts[name];
    }

    Operator* op = new Operator(name.c_str());
    ret = op->start();
    if (ret) {
        printf("hire new operator failed!\n");
    }

    m_contacts[name] = op;
    printf("hire operator %s\n", name.c_str());
    return op;
}

Operator* Operator::call_operator(std::string name) {
    if (m_contacts.find(name) != m_contacts.end()) {
        return m_contacts[name];
    } else {
        return nullptr;
    }
}

int Operator::fire_all() {
    std::map<std::string, Operator*>::iterator it;
    for (it = m_contacts.begin(); it != m_contacts.end(); it++) {
        printf("fire operator %s\n", it->first.c_str());
        it->second->stop();
        delete it->second;
    }
    return 0;
}

Operator::Operator(const char* name) {
    int ret = 0;
    char path[100];

    m_pid = 0;

    ret = pipe(m_pipe_fd);
    if (ret < 0) {
        printf("create pipe failed error:%d\n", errno);
    }

    snprintf(path, sizeof(path), "./%s_stdout.txt", name);
    m_out_fd = open(path, O_WRONLY | O_CREAT | O_APPEND);
    if (m_out_fd < 0) {
        printf("create stdout file %s failed error:%d\n", path, errno);
    }
}

int Operator::stop() {
    run("exit");
    waitpid(m_pid, NULL, WNOHANG);

    close(m_pipe_fd[0]);
    close(m_pipe_fd[1]);
    close(m_out_fd);

    return 0;
}

pid_t Operator::getpid() {
    return m_pid;
}

int Operator::start() {
    if (m_pid > 0) {
        printf("operator has started up\n");
        return -1;
    }

    m_pid = fork();
    if (m_pid == 0) {
        bash();
    }
    return 0;
}

int Operator::bash() {
    int ret;
    ret = dup2(m_pipe_fd[0], STDIN_FILENO);
    if (ret == -1) {
        printf("can't duplicate stdin with pipe, error:%d\n", errno);
    }
    ret = dup2(m_out_fd, STDOUT_FILENO);
    if (ret == -1) {
        printf("can't duplicate stdout with file, error:%d\n", errno);
    }
    ret = dup2(m_out_fd, STDERR_FILENO);
    if (ret == -1) {
        printf("can't duplicate stderr with file, error:%d\n", errno);
    }
    ret = execl("/bin/bash", "/bin/bash", NULL);

    // 如果下面的可以运行，说明execl失败了
    printf("create child bash process failed, error:%d\n", ret);
    close(m_pipe_fd[0]);
    close(m_pipe_fd[1]);
    close(m_out_fd);
    exit(-1);
}

int Operator::run(std::string cmd_str) {
    int ret = 0;
    cmd_str += "\n";
    ret = write(m_pipe_fd[1], cmd_str.c_str(), cmd_str.size());
    if (ret < 0) {
        printf("send command failed\n");
        return ret;
    }
    return 0;
}

const char* Operator::getcwd(char* path, size_t size) {
    char buf[1024];
    ssize_t len;
    snprintf(buf, sizeof(buf), "/proc/%d/cwd", m_pid);
    len = readlink(buf, path, size);
    path[len] = 0;
    return path;
}
