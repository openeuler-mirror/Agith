#! /bin/bash
set -e

echo "test running..."

current_dir=$(dirname $0)
cd $current_dir
./script1.sh
python3 test.py