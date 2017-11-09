#!/usr/bin/env python
# For Python, this file uses encoding: utf-8

from scapy.all import *
from collections import namedtuple
import sys
from math import sqrt

ECHO_REPLY = 0
TIME_EXCEEDED = 11
REPS_PER_TTL= 30
UNKNOWN = 'Unknown*'

tau_values = {
    3:1.1511, 21:1.8891,
    4:1.4250, 25:1.9011,
    5:1.5712, 26:1.9035,
    6:1.6563, 27:1.9057,
    7:1.7110, 28:1.9078,
    8:1.7491, 29:1.9096,
    9:1.7770, 30:1.9114,
    10:1.7984, 31:1.9130,
    11:1.8153, 32:1.9146,
    12:1.8290, 33:1.9160,
    13:1.8403, 34:1.9174,
    14:1.8498, 35:1.9186,
    15:1.8579, 36:1.9198,
    16:1.8649, 37:1.9209,
    17:1.8710, 38:1.9220,
    18:1.8764, 39:1.9230,
    19:1.8811, 40:1.9240,
    20:1.8853, 41:1.9249,
    23:1.8957, 42:1.9257,
    24:1.8985, 43:1.9265,
    }

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
    rtts = [hop.rtt for hop in hops]
    for index in detectOutliers(rtts):
        rtt_i = hops[index].rtt
        ip = hops[index].ip_address
        intercontinental = True
        num = hops[index].hop_num
        hops[index] = Hop(rtt_i,ip,intercontinental,num)

def detectOutliers(sample):
    n = len(sample)
    outlier_indexes = []
    sample_tuples = [(i, sample[i]) for i in range(n) if sample[i]!= UNKNOWN]
    n = len(sample_tuples)
    sample_tuples.sort(key=lambda tup: tup[1])
    sample = [sample_i for i,sample_i in sample_tuples]

    detectOutliersAux(outlier_indexes, n, sample, sample_tuples)
    return outlier_indexes


def detectOutliersAux(outlier_indexes, n, sample, sample_tuples):
    print "entrando a aux con parametros"
    print outlier_indexes
    print n
    print sample 
    print sample_tuples
    if n == 2 :
        return 
    if n > 43 :
        print "Tau value missing for n: "+str(n)

    mean = sum(map(float, sample)) / n
    sd = math.sqrt(
        sum([ (xi - mean)**2 for xi in sample ])/n
        )
    d_1 = abs(sample_tuples[0][1]-mean) 
    d_n = abs(sample_tuples[n-1][1]-mean)
    outlier_candidate = d_1
    index_in_tuples = 0
    if d_n > d_1:
        outlier_candidate = d_n
        index_in_tuples = n-1

    if outlier_candidate > tau_values[n]*sd:
        original_index = sample_tuples[index_in_tuples][0] 
        outlier_indexes.append(original_index)
        sample_tuples.pop(index_in_tuples)
        sample.pop(index_in_tuples)

        detectOutliersAux(outlier_indexes, n-1, sample, sample_tuples )

    else:
        return 

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
            unk = UNKNOWN
            hops.append(Hop(unk,unk,unk,ttl))
        else:
            ip = bestCandidate(hop_candidates)
            rtt_i = hop_candidates[ip].rtt_i_mean
            intercontinental = False
            num = ttl
            hops.append(Hop(rtt_i,ip,intercontinental,num))

        ttl += 1

    #podria ser vacio? si salto a mi router? para mi si hay qe poner el ultimo host
    detectIntercontinentalHops(hops)

    return hops

if __name__ == '__main__':
    hops = main(sys.argv[1])
    for hop in hops:
        print hop
