#!/bin/sh
#time ~/DQEMU/arm-linux-user/qemu-arm --offloadmode client --strace  ~/workload/canneal/canneal $1 15000 2000 ~/workload/canneal/2500000.nets 6000 > log_client.txt
time ~/DQEMU/arm-linux-user/qemu-arm --offloadmode client --strace  ~/workload/canneal/canneal $1 5 100 ~/workload/canneal/10.nets 1 > log_client.txt
cat log_client.txt

