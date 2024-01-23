#!/bin/bash

sudo killall openvpn

sleep 3

sudo openvpn --config /home/pi/openvpn/New+OVPN+Files/TCP/usla2-ovpn-tcp.ovpn --auth-user-pass pass &

sleep 9

sudo iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE

sleep 3

#--to-destination must be changed based on your ip address pattern
sudo iptables -t nat -D PREROUTING -i tun0 -j DNAT --to-destination 192.168.0.98
sudo iptables -t nat -A PREROUTING -i tun0 -j DNAT --to-destination 192.168.0.98

sudo iptables -t nat -L -n -v

sudo curl ipinfo.io

exit 0
