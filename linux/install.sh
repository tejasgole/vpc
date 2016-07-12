#!/bin/bash

/sbin/rmmod vpcd.ko 2> /dev/null
/sbin/insmod ./vpcd.ko

major=$(grep -w "vpc" /proc/devices | awk '{print $1}')

rm -f /dev/vpc
mknod /dev/vpc c $major 0

echo "Installed Marvell VSA Peer Cache Module"
