#!/bin/bash

# 检查当前执行的命令是否是 scp 或 sftp，或者其他不需要触发监控的命令
if [[ "$SSH_ORIGINAL_COMMAND" =~ ^scp.* || "$SSH_ORIGINAL_COMMAND" =~ sftp.* ]]; then
    # 如果是 scp 或 sftp，则直接执行原命令，不启动 Agith
    exec $SSH_ORIGINAL_COMMAND
else
    # 启动 Agith
    sudo bash -c "setsid agith -p $$ &> /usr/lib/agith/output.log &"
    # 手动加载 /etc/profile
    source /etc/profile
    # 启动新的 shell
    exec /bin/bash
fi