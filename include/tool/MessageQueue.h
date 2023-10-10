#ifndef __MESSAGEQUEUE_H
#define __MESSAGEQUEUE_H
#include <mqueue.h>
#include "tool/Log.h"

enum MQType{
    mq_add_aim,
    mq_stop,
};

struct AgithMessage {
    MQType type;
    pid_t pid;
};

class MessageQueue {
public:
    static log4cplus::Logger m_log;
    MessageQueue(const char* mq_name, int maxmsg);
    ~MessageQueue();
    int send_message(struct AgithMessage* msg);
    int recv_message(struct AgithMessage* msg);
    int unlink_mq();
private:
    char m_mq_name[256];
    mqd_t m_mqd;
    int m_mq_maxmsg;

    int create_mq();

};

#endif