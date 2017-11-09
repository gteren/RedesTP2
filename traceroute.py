#!/usr/bin/env python
# For Python, this file uses encoding: utf-8

from scapy.all import *
from collections import namedtuple, OrderedDict
import sys
from math import sqrt
import json

ECHO_REPLY = 0
TIME_EXCEEDED = 11
REPS_PER_TTL = 30
ITERS_FOR_ROUTE = 30
UNKNOWN_HOST = 'Unknown_host'

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
Hop = namedtuple('Hop', ['rtt','ip_address','international','hop_num'])
# HopCandidateInfo = namedtuple('HopCandidate', ['count','rtt_i_mean'])


def meanOf(sample):
    return sum(map(float, sample)) / len(sample)


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


def updateCandidate(new_rtt, candidate, candidates):
    old_count = hop_candidates[candidate].count
    old_mean = hop_candidates[candidate].rtt_i_mean
    new_count = old_count+1
    new_rtt_i_mean = (old_mean*old_count + new_rtt) / new_count
    candidate_info = HopCandidateInfo(new_count, new_rtt_i_mean)
    hop_candidates[candidate] = candidate_info


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
    for hop in hops:
        if unknownHost(hop):
            relative_rtts.append(UNKNOWN_HOST)
        else:
            if hop.hop_num == 1:
                relative_rtts.append(hop.rtt)
            else:
                previous_index = hop.hop_num-2
                i = previous_index
                while unknownHost(hops[i]) and i > 0:
                    i -= 1
                rel_rtt = max(0.0, hop.rtt-hops[i].rtt)
                relative_rtts.append(rel_rtt)
    return relative_rtts


def detectIntercontinentalHops(hops):
    relative_rtts = getRelativeRTTS(hops)
    for index in detectOutliers(relative_rtts):
        rtt_i = hops[index].rtt
        ip = hops[index].ip_address
        intercontinental = True
        num = hops[index].hop_num
        hops[index] = Hop(rtt_i, ip, intercontinental, num)


def detectOutliers(sample):
    n = len(sample)
    outlier_indexes = []
    sample_tuples = [(i, sample[i]) for i in range(n) if sample[i] != UNKNOWN_HOST]
    n = len(sample_tuples)
    sample_tuples.sort(key=lambda tup: tup[1])
    sample = [sample_i for i, sample_i in sample_tuples]

    detectOutliersAux(outlier_indexes, n, sample, sample_tuples)
    return outlier_indexes


def detectOutliersAux(outlier_indexes, n, sample, sample_tuples):
    '''
    print "entrando a aux con parametros"
    print outlier_indexes
    print n
    print sample
    print sample_tuples
    '''
    if n == 2:
        return
    if n > 43:
        print "Tau value missing for n: "+str(n)

    mean = meanOf(sample)
    sd = math.sqrt(
        sum([(xi - mean)**2 for xi in sample])/n
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

        detectOutliersAux(outlier_indexes, n-1, sample, sample_tuples)

    else:
        return


def mostProbableRouteTo(dst):
    dest_reached = False
    ttl = 1
    hosts = []
    while True: #asumiendo que el dst responde echo reply

        #SACAR ANTES DE ENTREGAR
        sys.stdout.write('Eligiendo ruta mas probable... %s  \r' % \
                ('TTL_'+str(ttl).zfill(2)))
        sys.stdout.flush()

        request_pkt = IP(dst=dst, ttl=ttl)/ICMP(type='echo-request')
        requests = [request_pkt for i in range(REPS_PER_TTL)]
        answered,unans = sr(request_pkt,verbose=0,timeout=1)

        ttli_candidate_count = {}
        for sent_pkt,received_pkt in answered:
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


def main(dst):
    route = mostProbableRouteTo(dst)
    hops = []
    print "Ruta mas probable..."
    print route
    for i in range(len(route)):

        # SACAR ANTES DE ENTREGAR
        sys.stdout.write('Iteraciones de ttl: %s\%s  \r' %
                        (str(i+1).zfill(2), str(len(route)).zfill(2)))
        sys.stdout.flush()

        host = route[i]
        ttl = i+1
        if host == UNKNOWN_HOST:
            hops.append(unknownHop(ttl))

        else:
            request_pkt = IP(dst=host)/ICMP(type='echo-request')
            requests = [request_pkt for i in range(ITERS_FOR_ROUTE)]
            answered, unans = sr(request_pkt, verbose=0, timeout=1)
            rtts = []
            if len(answered) == 0:
                hops.append(unknownHop(ttl))
            else:
                for sent_pkt, received_pkt in answered:
                    host_i = received_pkt[IP].src
                    assert(host_i == host)
                    rtt = received_pkt.time - sent_pkt.sent_time
                    rtts.append(rtt)

                ip = host
                assert(len(rtts) > 0)
                rtt_i = meanOf(rtts)*1000
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
                ('rtt', hop.rtt),
                ('ip_address', hop.ip_address),
                ('salto_intercontinental', hop.international),
                ('hop_num', hop.hop_num)
            ]),
            indent=4,
            separators=(',', ': ')
        )
        if hop != hops[-1]:
            json_host += ','
        print indent(json_host)

    print ']'
