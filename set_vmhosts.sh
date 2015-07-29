#!/bin/bash
 
ssh -i ~/.ssh/id_rsa an3@192.168.122.10 "sudo ifconfig eth1 10.0.0.1/24 up";
ssh -i ~/.ssh/id_rsa an3@192.168.122.10 "sudo route add -net 10.0.1.0 netmask 255.255.255.0 gw 10.0.0.2 dev eth1";

ssh -i ~/.ssh/id_rsa an3@192.168.122.30 "sudo ifconfig eth2 10.0.1.3/24 up";
ssh -i ~/.ssh/id_rsa an3@192.168.122.30 "sudo route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.1.2 dev eth2";
ssh -i ~/.ssh/id_rsa an2@192.168.122.20 "sudo iptables -I INPUT -i eth2 -m statistic --mode random --probability 0.2 -j DROP"


ssh -i ~/.ssh/id_rsa an2@192.168.122.20 "sudo ifconfig eth1 10.0.0.2/24 up";
ssh -i ~/.ssh/id_rsa an2@192.168.122.20 "sudo ifconfig eth2 10.0.1.2/24 up";
ssh -i ~/.ssh/id_rsa an2@192.168.122.20 "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"
ssh -i ~/.ssh/id_rsa an2@192.168.122.20 "sudo iptables -I FORWARD -i eth1 -j NFQUEUE --queue-num 1"
ssh -i ~/.ssh/id_rsa an2@192.168.122.20 "sudo iptables -I FORWARD -i eth2 -j NFQUEUE --queue-num 1"
