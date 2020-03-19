for i in $(seq 1 1000)
do
DQEMU --offloadmode client --n 2 --threadgroup 2 32-elf
done
