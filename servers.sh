#!/bin/bash
for i in `seq 1 $1`;do
echo $i
bash run_server.sh $i &> /dev/null &
done

