#!/usr/bin/env python
# For Python, this file uses encoding: utf-8

from scapy.all import *
import sys

ECHO_REPLY = 0
TIME_EXCEEDED = 11


def main(dst):
    ttl = 1
    hops = []
    while True:
        request_pkt = IP(dst=dst, ttl=ttl) / ICMP(type='echo-request')
        a, u = sr(request_pkt, verbose=0)
        received_pkt = a[0][1]
        sended_pkt = a[0][0]
        rtt = int(1000 * (received_pkt.time - sended_pkt.sent_time))
        icmp_layer = received_pkt[ICMP]
        if icmp_layer.type == ECHO_REPLY:
            break
        elif icmp_layer.type == TIME_EXCEEDED:
            hops.append((received_pkt[IP].src, rtt))
        else:
            hops.append('Unknowkn *')
        ttl += 1

    return hops


if __name__ == '__main__':
    hops = main(sys.argv[1])
    for hop in hops:
        print hop
