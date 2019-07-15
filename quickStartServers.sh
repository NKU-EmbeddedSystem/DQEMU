#!/bin/bash
for j in `seq 1 $1`; do
	sh run_server.sh $j &>/dev/null &
done

