echo "setting tcp buffer size larger..."
sudo echo 16777216 > /proc/sys/net/core/rmem_max
sudo echo 16777216 > /proc/sys/net/core/wmem_max
sudo echo "4096 873800 16777216" > /proc/sys/net/ipv4/tcp_rmem
sudo echo "4096 873800 16777216" > /proc/sys/net/ipv4/tcp_wmem
sudo echo "3073344 4097792 16777216" > /proc/sys/net/ipv4/tcp_mem
