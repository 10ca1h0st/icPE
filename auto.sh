#!/usr/bin/expect

set timeout 20
set name [lindex $argv 0]
set commit [lindex $argv 1]
set passwd [lindex $argv 2]
spawn git add .
spawn git commit -m"$commit"
spawn git push https://github.com/wujiaming123/${name}.git master
expect "'https://github.com':"
send "wujiaming123\n"
expect "'https://wujiaming123@github.com':"
send "${passwd}\n"
expect eof
exit
