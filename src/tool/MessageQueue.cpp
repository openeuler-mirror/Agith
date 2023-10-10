#define _USE
#include "stdio.h"
#include "tool/MessageQueue.h"

log4cplus::Logger MessageQueue::m_log;

MessageQueue::MessageQueue(const char *mq_name, int maxmsg) {
    snprintf(m_mq_name, sizeof(m_mq_name), "%s", mq_name);
    m_mq_maxmsg = maxmsg;
    m_mqd = create_mq();
}

int MessageQueue::create_mq() {
    int flag;
    mode_t mode;
    struct mq_attr attr;
    mqd_t mqd;

    attr.mq_maxmsg = m_mq_maxmsg;
    attr.mq_msgsize = sizeof(struct AgithMessage);

    flag = O_RDWR | O_CREAT | O_NONBLOCK;
    mode = S_IRUSR | S_IWUSR;

    mqd = mq_open(m_mq_name, flag, mode, &attr);
    if (mqd == (mqd_t) -1) {
        log_error("fail to create message queue");
        return -1;
    }

    return mqd;
}

MessageQueue::~MessageQueue() {
    if (m_mqd > 0) {
        mq_close(m_mqd);
    }
}

int MessageQueue::unlink_mq() {
    if (m_mqd == -1) {
        log_error("mqd is -1, can't remove message queue");
        return -1;
    }

    mq_close(m_mqd);
    m_mqd = -1;

    if (mq_unlink(m_mq_name) == -1) {
        log_error("fail to remove message queue %s", m_mq_name);
        return -1;
    }

    return 0;
}

int MessageQueue::send_message(struct AgithMessage* msg) {
    int ret;
    
    if (m_mqd == -1) {
        log_error("message queue %s is closed, can't send message", m_mq_name);
        return -1;
    }

    ret = mq_send(m_mqd, (char *)msg, sizeof(struct AgithMessage), 0);
    if (ret) {
        log_error("fail to send message");
        return -1;
    }

    return 0;
}

int MessageQueue::recv_message(struct AgithMessage *msg) {
    int ret;

    if (m_mqd == (mqd_t) -1) {
        log_error("message queue %s is closed, can't receive message", m_mq_name);
        return -1;
    }

    ret = mq_receive(m_mqd, (char *)msg, sizeof(struct AgithMessage), NULL);
    return ret;
}