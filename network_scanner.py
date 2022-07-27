#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered_list, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    print('IP\t\t\t\tMAC_ADDRESS')
    for ele in answered_list:
        print(ele[1].psrc + '\t' * 3 + ele[1].hwsrc)

scan('10.0.2.2/24')