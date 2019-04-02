#!/bin/sh

for i in `seq 1 16`;do
	echo "number $i time !!"
	time sh run_client.sh $i 2.5M >> log_cc.txt
done
