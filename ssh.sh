#!/bin/bash
sudo agith -p $$ &   # 启动 Agith
source /etc/profile  # 手动加载 /etc/profile
exec /bin/bash       # 启动新的 shell
