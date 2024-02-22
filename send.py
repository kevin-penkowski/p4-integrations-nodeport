#!/usr/bin/env python3

# Source: https://github.com/nsg-ethz/p4-learning/blob/master/exercises/05-ECMP/send.py

import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP

interface_name = "enp7s0"

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if interface_name in i:
            iface=i
            break
    if not iface:
        print(f"Cannot find {interface_name} interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> <number_of_random_packets>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))

    for _ in range(int(sys.argv[2])):
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt /IP(dst=addr) / TCP(dport=80, sport=random.randint(49152,65535))
        sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
