#!/bin/bash
echo "do for 10000 times:\n./arm-linux-user/qemu-arm --offloadmode server --offloadindex $1 ../workload/a.out"
for i in `seq 1 10000`;do
time ./arm-linux-user/qemu-arm --strace --offloadmode server --offloadindex $1 ../workload/a.out; 
echo $i
done

