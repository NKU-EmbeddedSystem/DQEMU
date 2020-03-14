for i in $(seq 1 10000);
do
DQEMU --offloadmode client --n 4 --threadgroup 1 32-elf
done
