#! /bin/bash
set -e

echo "net test running..."

current_dir=$(dirname $0)
cd $current_dir

beginTime=$(date "+%Y-%m-%d %H:%M:%S")

for((i=1;i<=100;i++))
do   
    curl www.baidu.com
done  

echo "beginTime:" $beginTime
endTime=$(date "+%Y-%m-%d %H:%M:%S")
echo "endtime:" $endTime
 
duration=$(($(date +%s -d "${endTime}")-$(date +%s -d "${beginTime}")));
echo "time diff:" $duration"s"