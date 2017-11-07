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
        reply_pkt = sr1(request_pkt, verbose=0)
        icmp_layer = reply_pkt[ICMP]
        if icmp_layer.type == ECHO_REPLY:
            break
        elif icmp_layer.type == TIME_EXCEEDED:
            hops.append(reply_pkt[IP].src)
        else:
            hops.append('Unknowkn *')
        ttl += 1

    return hops


if __name__ == '__main__':
    hops = main(sys.argv[1])
    for hop in hops:
        print hop
