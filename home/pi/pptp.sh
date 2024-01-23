#!/bin/bash

sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

sudo pon purevpn

sleep 9

sudo iptables -t nat -A POSTROUTING -o ppp0 -j MASQUERADE

sleep 3

#--to-destination must be changed based on your ip address pattern
sudo iptables -t nat -A PREROUTING -i ppp0 -j DNAT --to-destination 192.168.0.98

sleep 3

sudo iptables -t nat -L -n -v

sudo curl ipinfo.io

exit 0