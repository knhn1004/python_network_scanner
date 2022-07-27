#!/usr/bin/env python

import scapy.all as scapy
import argparse

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered_list, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    clients = []

    # print('IP\t\t\t\tMAC_ADDRESS')
    for ele in answered_list:
        clients.append({
            'ip': ele[1].psrc,
            'mac': ele[1].hwsrc
        })

    return(clients)

def print_result(results):
    print('IP' + '\t'*4 + 'MAC_ADDRESS')
    print('-'*80)
    for client in results:
        print(f"{client.get('ip')}\t\t\t{client.get('mac')}")

args = argparse.ArgumentParser()
args.add_argument('-t', '--target', dest='target', help='ip (range) target to scan', required=True)

my_args = args.parse_args()

# scan_results = scan('10.0.2.2/24')
scan_results = scan(my_args.target)
print_result(scan_results)