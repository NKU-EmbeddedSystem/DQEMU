#!/bin/sh

for i in `seq 2 16`;do
	echo "number $i time !!"
	time sh run_client.sh $i 10M
done
