#! /bin/bash
set -e

echo "test running..."

current_dir=$(dirname $0)
cd $current_dir

beginTime=$(date "+%Y-%m-%d %H:%M:%S")

for((i=1;i<=5000;i++))
do   
    filename=example_$i.txt
    content="create file $filename"
    touch $filename
    echo $content >> $filename
    cat $filename
    rm $filename
done  

echo "beginTime:" $beginTime
endTime=$(date "+%Y-%m-%d %H:%M:%S")
echo "endtime:" $endTime
 
duration=$(($(date +%s -d "${endTime}")-$(date +%s -d "${beginTime}")));
echo "time diff:" $duration"s"