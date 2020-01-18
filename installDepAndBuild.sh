#!/bin/bash
sudo apt install build-essential python python3 pkg-config git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev
./configure --diable-kvm --disable-werror --target-list=arm-linux-user
