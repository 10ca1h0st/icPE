#!/bin/bash

dir_full=`pwd`
dir=`basename $dir_full`
commit=$1
passwd=$2
if [ $# -ne 2 ];then
echo "Usage:$0 commit passwd"
exit
fi

/usr/bin/expect << EOF
set timeout 20
spawn git add .
sleep 2
spawn git commit -m"$commit"
sleep 4
spawn git push https://github.com/wujiaming123/${dir}.git master
expect "'https://github.com':"
send "wujiaming123\n"
expect "'https://wujiaming123@github.com':"
send "${passwd}\n"
expect eof
EOF
