#!/usr/bin/env python
# For Python, this file uses encoding: utf-8

from scapy.all import *
from collections import namedtuple
import sys

ECHO_REPLY = 0
TIME_EXCEEDED = 11

REPS_PER_TTL= 30

#"Route = [Hop]"
Hop = namedtuple('Hop', ['rtt','ip_address','international','hop_num'])
HopCandidateInfo = namedtuple('HopCandidate', ['count','rtt_i_mean'])

def updateCandidate(new_rtt, candidate, candidates):
    old_count = hop_candidates[candidate].count
    old_mean = hop_candidates[candidate].rtt_i_mean
    new_count = old_count+1
    new_rtt_i_mean = (old_mean*old_count + new_rtt) / new_count
    candidate_info = HopCandidateInfo(new_count,new_rtt_i_mean)
    hop_candidates[candidate] = candidate_info                    

def noCandidates(candidates):
    return len(candidates)==0

#Pre: Not empty
def bestCandidate(candidates):
    best = candidates.keys()[0]    
    for cand, cand_info in candidates.items():
        if cand_info.count > candidates[best].count:
            best = candidate
    
    return best

def detectIntercontinentalHops(hops):
    for i in range(len(hops)):
        if isIntercontinental(hops[i],hops):
            rtt_i = hop[i].rtt
            ip = hop[i].ip_address
            intercontinental = True
            num = hop[i].hop_num
            hops[i] = Hop(rtt_in,ip,intercontinental,num)

def isIntercontinental(hop, route):
    #Todo Cimbala
    return False
    

def main(dst):
    dest_reached = False
    ttl = 1
    hops = []
    while True: #asumiendo que el dst responde echo reply

        #SACAR ANTES DE ENTREGAR
        sys.stdout.write('Trabajando... %s  \r' % \
                ('TTL_'+str(ttl).zfill(2)))
        sys.stdout.flush()

        request_pkt = IP(dst=dst, ttl=ttl)/ICMP(type='echo-request')
        requests = [request_pkt for i in range(REPS_PER_TTL)]
        answered,unans = sr(request_pkt,verbose=0,timeout=1)
        
        hop_candidates = {}
        for sent_pkt,received_pkt in answered:
            icmp_layer = received_pkt[ICMP]
            if icmp_layer.type == ECHO_REPLY:
                dest_reached = True
                break
            elif icmp_layer.type == TIME_EXCEEDED:            
                candidate = received_pkt[IP].src 
                this_rtt = received_pkt.time - sent_pkt.sent_time

                if candidate in hop_candidates:
                    updateCandidate(this_rtt,candidate,hop_candidates)
                else:
                    hop_candidates[candidate] = HopCandidateInfo(1,this_rtt)

        if dest_reached:
            break 
        elif noCandidates(hop_candidates):
            unk = 'Unknown*'
            hops.append(Hop(unk,unk,unk,ttl))
        else:
            ip = bestCandidate(hop_candidates)
            rtt_i = hop_candidates[ip].rtt_i_mean
            intercontinental = False
            num = ttl
            hops.append(Hop(rtt_i,ip,intercontinental,num))

        ttl += 1

    detectIntercontinentalHops(hops)

    return hops

if __name__ == '__main__':
    hops = main(sys.argv[1])
    for hop in hops:
        print hop
