#!/usr/bin/env python
# For Python, this file uses encoding: utf-8

from scapy.all import *
import sys

ECHO_REPLY = 0
TIME_EXCEEDED = 11

def unknownHop(answered):
    print "entra a unknown"
    received_pkt = answered[0][1]
    icmp_layer = received_pkt[ICMP]
    not_echo_reply = icmp_layer.type != ECHO_REPLY  
    not_time_exceeded = icmp_layer!= TIME_EXCEEDED
    return not_echo_reply and not_time_exceeded

def main(dst):
    ttl = 1
    hops = []
    while True:
        print "entra ciclo principal"
        request_pkt = IP(dst=dst, ttl=ttl) / ICMP(type='echo-request')
        answered, unanswered = sr(
            request_pkt,
            verbose=0,
            timeout=1,
            retry=3
            )

        if len(answered)==0 or unknownHop(answered):    
            hops.append('Unknown *')
        
        else:
            received_pkt = answered[0][1]
            sent_pkt = answered[0][0]
            rtt = received_pkt.time - sent_pkt.sent_time
            icmp_layer = received_pkt[ICMP]
            if icmp_layer.type == ECHO_REPLY:
                break
            elif icmp_layer.type == TIME_EXCEEDED:
                hops.append((received_pkt[IP].src, rtt))
            
        ttl += 1

    return hops

if __name__ == '__main__':
    hops = main(sys.argv[1])
    for hop in hops:
        print " "
        print hop
