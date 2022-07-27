#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered_list, _ = scapy.srp(arp_request_broadcast, timeout=1)
    for e in answered_list:
        print(e[1].psrc)
        print(e[1].hwsrc)
        print('-'*80)

scan('10.0.2.2/24')