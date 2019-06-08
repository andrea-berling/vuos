#!/bin/zsh
export LD_LIBRARY_PATH=/home/andrea/Documents/SistemiVirtuali/Project/vuos/vunet_modules/lwipv6/lwip-contrib/ports/unix/proj/lib/build
gcc lwipnc.c -o lwipnc -L ../lwip-contrib/ports/unix/proj/lib/build/ -ldl -llwipv6 -lpthread -g -I../lwip-contrib/ports/unix/include/
nc -l -p 9999
sudo ip route add 192.168.0.150 dev tap
