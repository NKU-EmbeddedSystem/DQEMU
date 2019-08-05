#!/bin/sh
echo "thread number: $1\n"
echo "running blackscholes_time, $2 input"
time ./arm-linux-user/qemu-arm --offloadmode client --strace  ./a.out $1
#cat log_client.txt
