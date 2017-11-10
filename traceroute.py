#!/usr/bin/env python
# For Python, this file uses encoding: utf-8

from scapy.all import *
from collections import namedtuple, OrderedDict
import sys
from math import sqrt
import json
import numpy as np

ECHO_REPLY = 0
TIME_EXCEEDED = 11
REPS_PER_TTL = 30
ITERS_FOR_ROUTE = 30
UNKNOWN_HOST = 'Unknown_host'
INFINITO = 100000

tau_values = {
    3: 1.1511, 21: 1.8891,
    4: 1.4250, 25: 1.9011,
    5: 1.5712, 26: 1.9035,
    6: 1.6563, 27: 1.9057,
    7: 1.7110, 28: 1.9078,
    8: 1.7491, 29: 1.9096,
    9: 1.7770, 30: 1.9114,
    10: 1.7984, 31: 1.9130,
    11: 1.8153, 32: 1.9146,
    12: 1.8290, 33: 1.9160,
    13: 1.8403, 34: 1.9174,
    14: 1.8498, 35: 1.9186,
    15: 1.8579, 36: 1.9198,
    16: 1.8649, 37: 1.9209,
    17: 1.8710, 38: 1.9220,
    18: 1.8764, 39: 1.9230,
    19: 1.8811, 40: 1.9240,
    20: 1.8853, 41: 1.9249,
    23: 1.8957, 42: 1.9257,
    24: 1.8985, 43: 1.9265,
    }

# "Route = [Hop]"
Hop = namedtuple('Hop', ['rtt', 'ip_address', 'intercontinental', 'hop_num'])

def validType(icmp_layer):
    if icmp_layer.type == ECHO_REPLY:
        return True
    elif icmp_layer.type == TIME_EXCEEDED:
        return True
    else:
        return False

def unknownHost(hop):
    return hop.rtt == UNKNOWN_HOST

def unknownHop(ttl):
    unk = UNKNOWN_HOST
    return Hop(unk, unk, unk, ttl)

def noCandidates(candidates):
    return len(candidates) == 0

def bestCandidate(candidates):
    best = candidates.keys()[0]
    for candidate, count in candidates.items():
        if count > candidates[best]:
            best = candidate
    return best

def getRelativeRTTS(hops):
    relative_rtts = []
    for i in range(len(hops)):
        hop = hops[i]
        if unknownHost(hop):
            relative_rtts.append(UNKNOWN_HOST)
        else:
            if i == 0:
                relative_rtts.append(hop.rtt)
            else:
                rel_rtt = max(0.0, hop.rtt-previousRTT(i,hops))
                relative_rtts.append(rel_rtt)
    return relative_rtts

def unknownsBefore(i, hops):
    count = 0
    rev = list(reversed(hops[:i]))
    for h in rev:
        if unknownHost(h):
            count+=1
        else:
            break
    return count

def unknownsAfter(i, hops):
    count = 0
    afterItems = hops[i+1:len(hops)]
    for h in afterItems:
        if unknownHost(h):
            count+=1
        else:
            break
    return count

def previousRTT(i, hops):
    unks_btw = unknownsBefore(i, hops)
    previous_rtt = 0
    previous_index = i-(unks_btw+1)
    if previous_index >= 0:
        previous_rtt = hops[previous_index].rtt
    return previous_rtt

def nextRTT(i, hops):
    unks_aft = unknownsAfter(i, hops)
    next_rtt = INFINITO
    next_index = i+unks_aft+1
    if next_index < len(hops):
        next_rtt = hops[next_index].rtt
    return next_rtt
#Sacamos los que tardan más que sus sucesores bajo la hipotesis
#de que no priorizan ICMP, pero si datos reales. 

def removeICMPDelayers(hops):
    filtered = [hops[0]]
    oldIndex = {}
    for i in range(1, len(hops)):
        if unknownHost(hops[i]) or hops[i].rtt < nextRTT(i,hops):
            filtered.append(hops[i])
            oldIndex[len(filtered)-1] = i
    return filtered, oldIndex

def keepICMPDelayers(hops):
    filtered = [hops[0]]
    oldIndex = {}
    for i in range(1, len(hops)):
        if unknownHost(hops[i]) or previousRTT(len(filtered),filtered) < hops[i].rtt:
            filtered.append(hops[i])
            oldIndex[len(filtered)-1] = i
    return filtered, oldIndex

def detectIntercontinentalHops(hops):   
    filteredHops, oldIndex = removeICMPDelayers(hops)
    relative_rtts = getRelativeRTTS(filteredHops)
    outlierIndexes = detectOutliers(relative_rtts)
    intercontinentalHops = [oldIndex[i] for i in outlierIndexes]
    
    for index in intercontinentalHops:
        rtt_i = hops[index].rtt
        ip = hops[index].ip_address
        intercontinental = True
        num = hops[index].hop_num
        hops[index] = Hop(rtt_i, ip, intercontinental, num)

def detectOutliers(sample):
    n = len(sample)
    sample_tuples = [(i, sample[i]) for i in range(n)
                     if sample[i] != UNKNOWN_HOST]
    n = len(sample_tuples)
    sample_tuples.sort(key=lambda tup: tup[1])
   
    sample = [sample_i for i, sample_i in sample_tuples]

    return detectOutliersAux(n, sample, sample_tuples)


def detectOutliersAux(n, sample, sample_tuples):
    if n == 2:
        return []
    if n > 43:
        print "Tau value missing for n: "+str(n)

    mean = np.mean(sample)
    sd = np.std(sample)
    d_1 = abs(sample_tuples[0][1]-mean)
    d_n = abs(sample_tuples[-1][1]-mean)
    outlier_candidate = d_1
    index_in_tuples = 0
    
    if d_n > d_1:
        outlier_candidate = d_n
        index_in_tuples = n-1

    if outlier_candidate > tau_values[n]*sd:
        original_index = sample_tuples[index_in_tuples][0]
        sample_tuples.pop(index_in_tuples)
        sample.pop(index_in_tuples)
        
        if outlier_candidate == d_1:
            res = []
        else:
            res = [original_index]

        return res + detectOutliersAux(n-1, sample, sample_tuples)

    else:
        return []


def mostProbableRouteTo(dst):
    dest_reached = False
    ttl = 1
    hosts = []
    while True:  # asumiendo que el dst responde echo reply
        # #SACAR ANTES DE ENTREGAR
        exitIfUnreachable(ttl)
        '''
        sys.stdout.write('Eligiendo ruta mas probable... %s  \r' % \
                ('TTL_'+str(ttl).zfill(2)))
        sys.stdout.flush()
        '''
        requests = [IP(dst=dst, ttl=ttl)/ICMP(type='echo-request')
                        for i in range(REPS_PER_TTL)]
        answered, unans = sr(requests, verbose=0, timeout=1)

        ttli_candidate_count = {}
        for sent_pkt, received_pkt in answered:
            icmp_layer = received_pkt[ICMP]
            if icmp_layer.type == ECHO_REPLY:
                dest_reached = True
            if validType(icmp_layer):
                candidate = received_pkt[IP].src
                if candidate in ttli_candidate_count:
                    ttli_candidate_count[candidate] += 1
                else:
                    ttli_candidate_count[candidate] = 1

        if noCandidates(ttli_candidate_count):
            unk = UNKNOWN_HOST
            hosts.append(unk)
        else:
            hosts.append(bestCandidate(ttli_candidate_count))

        if dest_reached:
            break

        ttl += 1
    return hosts

def exitIfUnreachable(ttl):
    if ttl >=40:
        print 'Host unreachable'
        sys.exit()

def main(dst):
    route = mostProbableRouteTo(dst)
    hops = []

    for i in range(len(route)):
        host = route[i]
        ttl = i+1
        if host == UNKNOWN_HOST:
            hops.append(unknownHop(ttl))
        else:
            requests = [IP(dst=host)/ICMP(type='echo-request')
                        for i in range(ITERS_FOR_ROUTE)]
            answered, unans = sr(requests, verbose=0, timeout=1)
            rtts = []
            if len(answered) == 0:
                hops.append(unknownHop(ttl))
            else:
                for sent_pkt, received_pkt in answered:
                    host_i = received_pkt[IP].src
                    rtt = received_pkt.time - sent_pkt.sent_time
                    rtts.append(rtt)

                ip = host
                rtt_i = np.median(rtts)
                intercontinental = False
                num = ttl
                hops.append(Hop(rtt_i, ip, intercontinental, num))

    detectIntercontinentalHops(hops)

    return hops


def indent(lines):
    return ''.join('    '+line for line in lines.splitlines(True))


if __name__ == '__main__':
    hops = main(sys.argv[1])
    print '['
    for hop in hops:
        json_host = json.dumps(
            OrderedDict([
                ('rtt', None if unknownHost(hop) else hop.rtt*1000 ),
                ('ip_address', None if unknownHost(hop) else hop.ip_address),
                ('salto_intercontinental', None if unknownHost(hop) else hop.intercontinental),
                ('hop_num', None if unknownHost(hop) else hop.hop_num)
            ]),
            indent=4,
            separators=(',', ': ')
        )
        if hop != hops[-1]:
            json_host += ','
        print indent(json_host)

    print ']'
