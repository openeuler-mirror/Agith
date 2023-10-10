#! /bin/bash
set -e

echo "test running..."

current_dir=$(dirname $0)
cd $current_dir

current=$(date "+%Y-%m-%d %H:%M:%S")
timeStamp=`date -d "$current" +%s` 
beginTime=$((timeStamp*1000+10#`date "+%N"`/1000000)) #将current转换为时间戳，精确到毫秒


for((i=1;i<=100;i++))
do   
    filename=example_$i.txt
    content="create file $filename"
    touch $filename
    echo $content >> $filename
    cat $filename
    rm $filename
    curl www.baidu.com
done  

current=$(date "+%Y-%m-%d %H:%M:%S")
timeStamp=`date -d "$current" +%s` 
endTime=$((timeStamp*1000+10#`date "+%N"`/1000000)) 

echo "beginTime:" $beginTime
echo "endtime:" $endTime
 
#duration=$(($(date +%s -d "${endTime}")-$(date +%s -d "${beginTime}")));
duration=$[$endTime-$beginTime]
echo "time diff:" $duration"ms"

duration=$[$duration/1000]
echo  "time diff:" $duration"s"
