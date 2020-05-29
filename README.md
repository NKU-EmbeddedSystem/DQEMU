-----------------------------

DQEMU

------------

DQEMU is a Distributed Dynamic Binary Translator based on QEMU. 



Building

----------------------------

```shell
mkdir build && cd build
bash ../installDepAndBuild.sh
make

or

mkdir build && cd build
../configure --disable-kvm --disable-werror --target-list=arm-linux-user
make
```

Usage

---

We take an example as 1 server. The indexes of servers begin as 1. 

Server 1

```shell
cd build
./arm-linux-user/qemu-arm --offloadmode server --offloadindex 1 path_to_elf
```

Client

The node count should be count of servers + 1. The group means the the number of the threads in a group. 

```shell
cd build
./arm-linux-user/qemu-arm --offloadmode client --node 2 --group 2 path_to_elf
```

The result will be shown in Client's terminal

