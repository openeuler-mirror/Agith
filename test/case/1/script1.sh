#! /bin/bash
set -e

echo "script2 running"
current_dir=$(dirname $0)
test_file=example.txt

echo "file test: delete create change write"

cd $current_dir
if [ -e $test_file ];then
    rm -rf $test_file
fi

touch $test_file
echo "kafka.port = 9092" >> $test_file

sed -i 's/port/port.1/' $test_file

rm -rf $test_file

echo "net test: send to baidu.com"
curl www.baidu.com

echo "stop test"

