#!/usr/bin/env python

import scapy.all as scapy

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

scan_results = scan('10.0.2.2/24')
print_result(scan_results)