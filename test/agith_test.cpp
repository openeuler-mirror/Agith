#include <json/json.h>
#include <iostream>
#include "model/Controller.h"
#include "model/Repository.h"
#include "graph/PipeNode.h"
#include "utils/Operator.h"
#include "agith_test.h"
#include "tool/Manual.h"
#include "graph/Edge.h"
#include "graph/ProcessNode.h"

#define WAIT_TIME 200000  // micro second

AgithTest::AgithTest() : testing::Test() {}

void AgithTest::SetUpTestCase() {
    Json::Value config;
    std::ifstream file;
    char path[1024];
    Operator* mike = Operator::hire_operator("Mike");

    snprintf(path, sizeof(path), "./config/agith.config");
    file.open(path, std::ios::in);
    if (!file.is_open()) {
        printf("fail to open configure file: %s\n", path);
        return;
    }

    file >> config;
    config["Repository"]["max_output_trace"] = 20;
    file.close();

    LoggerFactory::init(config["Log"]);

    if (Controller::get_controller()->init(config)) {
        printf("initalization failed!");
    }

    Controller::get_controller()->set_pid_target(mike->getpid());
}

void AgithTest::TearDownTestCase() {
    Controller::get_controller()->stop();
    Operator::fire_all();
}

void AgithTest::SetUp() {}

void AgithTest::TearDown() {
    Repository::get_repository()->set_signal(OUTPUT_USELESS);
}

TEST_F(AgithTest, mkdir) {
    Edge* edge;
    bool condition = false;
    ProcessNode* pnode;

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }

    mike->run("mkdir test");
    usleep(WAIT_TIME);
    for (auto item : Edge::edges) {
        edge = item.second;
        if (edge->get_syscall_num(SYS_mkdir) > 0) {
            pnode = (ProcessNode*)edge->get_first();
            if (strcmp(pnode->get_cmd(), "/usr/bin/mkdir test") == 0) {
                condition = true;
                break;
            }
        }
    }

    EXPECT_TRUE(condition);
}

TEST_F(AgithTest, chdir) {
    Edge* edge;
    bool condition = false;
    ProcessNode* pnode;
    char path[1024];

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }

    mike->run("cd test");
    usleep(WAIT_TIME);
    mike->getcwd(path, sizeof(path));
    for (auto item : Edge::edges) {
        edge = item.second;
        pnode = (ProcessNode*)edge->get_first();
        if (strcmp(pnode->get_wd(), path) == 0) {
            condition = true;
            break;
        }
    }

    EXPECT_TRUE(condition);
}

TEST_F(AgithTest, utimensat) {
    Edge* edge;
    bool condition = false;
    FileNode* fnode;
    char path[1024];
    char buf[1024];

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }
    mike->getcwd(path, sizeof(path));
    snprintf(buf, sizeof(buf), "%s/test.txt", path);

    mike->run("touch test.txt");
    usleep(WAIT_TIME);
    for (auto item : Edge::edges) {
        edge = item.second;
        if (edge->get_syscall_num(SYS_utimensat) > 0) {
            fnode = (FileNode*)edge->get_second();
            if (strcmp(fnode->get_pathname(), buf) == 0) {
                condition = true;
                break;
            }
        }
    }

    EXPECT_TRUE(condition);
}

TEST_F(AgithTest, clone_execve_exit) {
    Edge* edge;
    bool condition = false;
    ProcessNode* pnode;

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }

    mike->run("ls -al");
    usleep(WAIT_TIME);
    for (auto item : Edge::edges) {
        edge = item.second;
        if (edge->get_syscall_num(SYS_clone) > 0) {
            pnode = (ProcessNode*)edge->get_second();
            if (strcmp(pnode->get_cmd(), "/usr/bin/ls -al") == 0 && pnode->get_exit_time() > 0) {
                condition = true;
                break;
            }
        }
    }

    EXPECT_TRUE(condition);
}

TEST_F(AgithTest, write) {
    Edge* edge;
    bool condition = false;
    FileNode* fnode;
    char path[1024];
    char buf[1024];

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }
    mike->getcwd(path, sizeof(path));
    snprintf(buf, sizeof(buf), "%s/test.txt", path);

    mike->run("echo hello > test.txt");
    usleep(WAIT_TIME);
    for (auto item : Edge::edges) {
        edge = item.second;
        if (edge->get_syscall_num(SYS_write) > 0) {
            fnode = (FileNode*)edge->get_second();
            if (strcmp(fnode->get_pathname(), buf) == 0) {
                condition = true;
                break;
            }
        }
    }

    EXPECT_TRUE(condition);
}

TEST_F(AgithTest, openat_read) {
    Edge* edge;
    bool condition = false;
    FileNode* fnode;
    char path[1024];
    char buf[1024];

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }
    mike->getcwd(path, sizeof(path));
    snprintf(buf, sizeof(buf), "%s/test.txt", path);

    mike->run("cat test.txt");
    usleep(WAIT_TIME);
    for (auto item : Edge::edges) {
        edge = item.second;
        if (edge->get_syscall_num(SYS_openat) > 0 && edge->get_syscall_num(SYS_read) > 0) {
            fnode = (FileNode*)edge->get_second();
            if (strcmp(fnode->get_pathname(), buf) == 0) {
                condition = true;
                break;
            }
        }
    }

    EXPECT_TRUE(condition);
}

TEST_F(AgithTest, copy) {
    Edge* edge;
    bool condition1 = false;
    bool condition2 = false;
    FileNode* fnode;
    ProcessNode* pnode;
    char path[1024];
    char file_path1[1024];
    char file_path2[1024];

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }
    mike->getcwd(path, sizeof(path));
    snprintf(file_path1, sizeof(file_path1), "%s/test.txt", path);
    snprintf(file_path2, sizeof(file_path2), "%s/test.txt.bak", path);

    mike->run("cp test.txt test.txt.bak");
    usleep(WAIT_TIME);
    for (auto item : Edge::edges) {
        edge = item.second;
        if (edge->get_syscall_num(SYS_openat) > 0 && edge->get_syscall_num(SYS_read) > 0) {
            pnode = (ProcessNode*)edge->get_first();
            fnode = (FileNode*)edge->get_second();
            printf("file_path: %s, fnode:%s\n",file_path1, fnode->get_pathname());

            if (strcmp(fnode->get_pathname(), file_path1) == 0 &&
                strcmp(pnode->get_cmd(), "/usr/bin/cp test.txt test.txt.bak") == 0) {
                condition1 = true;
            }
        }
        if (edge->get_syscall_num(SYS_write) > 0 && edge->get_syscall_num(SYS_openat) > 0) {
            pnode = (ProcessNode*)edge->get_first();
            fnode = (FileNode*)edge->get_second();
            printf("fnode:%s\n", fnode->get_pathname());
            // printf("pnode:%s\n", pnode->get_cmd());            
            if (strcmp(fnode->get_pathname(), file_path2) == 0 &&
                strcmp(pnode->get_cmd(), "/usr/bin/cp test.txt test.txt.bak") == 0) {
                condition2 = true;
            }
        }
    }

    EXPECT_TRUE(condition1);
    EXPECT_TRUE(condition2);
}

TEST_F(AgithTest, renameat2) {
    Edge* edge;
    bool condition = false;
    FileNode* fnode;
    char path[1024];
    char buf[1024];

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }
    mike->getcwd(path, sizeof(path));
    snprintf(buf, sizeof(buf), "%s/new_test.txt", path);

    mike->run("mv test.txt.bak new_test.txt");
    usleep(WAIT_TIME);
    for (auto item : Edge::edges) {
        edge = item.second;
        if (edge->get_syscall_num(SYS_renameat2) > 0) {
            fnode = (FileNode*)edge->get_second();
            if (strcmp(fnode->get_pathname(), buf) == 0) {
                condition = true;
                break;
            }
        }
    }

    EXPECT_TRUE(condition);
}

TEST_F(AgithTest, fchmodeat) {
    Edge* edge;
    bool condition = false;
    FileNode* fnode;
    char path[1024];
    char buf[1024];

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }
    mike->getcwd(path, sizeof(path));
    snprintf(buf, sizeof(buf), "%s/test.txt", path);

    mike->run("chmod u+x test.txt");
    usleep(WAIT_TIME);
    for (auto item : Edge::edges) {
        edge = item.second;
        if (edge->get_syscall_num(SYS_fchmodat) > 0) {
            fnode = (FileNode*)edge->get_second();
            if (strcmp(fnode->get_pathname(), buf) == 0) {
                condition = true;
                break;
            }
        }
    }

    EXPECT_TRUE(condition);
}

TEST_F(AgithTest, unlinkat) {
    Edge* edge;
    bool condition = false;
    FileNode* fnode;
    char path[1024];
    char buf[1024];

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }
    mike->getcwd(path, sizeof(path));
    snprintf(buf, sizeof(buf), "%s/test.txt", path);

    mike->run("cd ..");
    mike->run("rm -rf test");
    usleep(WAIT_TIME);
    for (auto item : Edge::edges) {
        edge = item.second;
        if (edge->get_syscall_num(SYS_unlinkat) > 0) {
            fnode = (FileNode*)edge->get_second();
            if (strcmp(fnode->get_pathname(), buf) == 0) {
                condition = true;
                break;
            }
        }
    }

    EXPECT_TRUE(condition);
}

TEST_F(AgithTest, dup2_fcntl) {
    EXPECT_TRUE(true);
}

TEST_F(AgithTest, connect_sendto_recvfrom) {
    Edge* edge_send = NULL;
    Edge* edge_recv = NULL;
    Edge* edge;
    std::map<std::pair<Node*, Node*>, Edge*>::iterator it;

    Operator* mike = Operator::call_operator("Mike");
    if (mike == NULL) {
        FAIL() << "can't find operator\n";
    }

    mike->run("curl www.baidu.com");
    usleep(WAIT_TIME * 5);
    Consumer::get_consumer()->notify();

    for (it = Edge::edges.begin(); it != Edge::edges.end(); it++) {
        edge = it->second;
        if (edge->get_syscall_num(SYS_sendto) > 0) {
            edge_send = edge;
        }
        if (edge->get_syscall_num(SYS_recvfrom) > 0) {
            edge_recv = edge;
        }
    }
    if (edge_send == NULL || edge_recv == NULL) {
        FAIL() << "send or recv edge not found";
    }

    if (edge_send->get_syscall_num(SYS_connect) == 0) {
        FAIL() << "SYS_connect is lost\n";
    }

    if (edge_send->get_first() != edge_recv->get_second()) {
        FAIL() << "send and recv is not pair";
    }

    if (edge_send->get_second() != edge_recv->get_first()) {
        FAIL() << "send and recv is not pair";
    }
    SUCCEED();
}