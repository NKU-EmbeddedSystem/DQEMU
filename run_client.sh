#!/bin/sh
echo "thread number: $1\n"
echo "running blackscholes_time, $2 input"
time ./arm-linux-user/qemu-arm --offloadmode client --strace  ../workload/blackscholes_time $1 ../workload/blackscholes_workload/in_$2.txt prices.txt
#cat log_client.txt
