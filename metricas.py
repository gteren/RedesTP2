#!/usr/bin/env python
# For Python, this file uses encoding: utf-8
from collections import namedtuple
from traceroute import unknownHost,Hop
from incf.countryutils import transformations
import geoip2.database

INTER = 1
LOCAL = 2 
Data = namedtuple('Data', ['tp', 'fp', 'tn', 'fn', 'class_weight'])
DataRoute = namedtuple('DataRoute', ['inter', 'local'])
UNKNOWN_HOST = 'Unknown_host'

def analize(route):
    dataInter = Data(0,0,0,0,0)
    dataLocal = Data(0,0,0,0,0)
    known_hops = [hop for hop in route if not unknownHost(hop)]
    n = len(known_hops)
    for clase in [INTER, LOCAL]:
        truePositive = 0 
        falsePositive = 0
        trueNegative = 0
        falseNegative = 0
        inter = 0
        local = 0

        for i in range(n):
            hop = known_hops[i]
            prev_hop = known_hops[i-1] if i > 0 else hop
            if detectedAs(clase, hop):
                if trulyOfClass(clase, hop, prev_hop):
                    truePositive += 1
                else:
                    falsePositive += 1

            else:
                if trulyOfClass(clase, hop, prev_hop):
                    falseNegative += 1
                else:
                    trueNegative += 1
            
            if hop.intercontinental:
                inter += 1
            else:
                local += 1

        if clase== INTER:
            dataInter = Data(truePositive,falsePositive,trueNegative,falseNegative, float(inter)/n)
        else:
            dataLocal = Data(truePositive,falsePositive,trueNegative,falseNegative, float(local)/n)

    return DataRoute(dataInter,dataLocal)

# 'cuantos de los detectados como tales, 
#son realmente saltos intercontinentales' 
def precision(route):
    data_route = analize(route)
    precisionIntercontinentales = precisionXClase(data_route.inter)
    precisionLocales = precisionXClase(data_route.local)
    inter_weighted = precisionIntercontinentales * data_route.inter.class_weight 
    local_weighted = precisionLocales * data_route.local.class_weight
    return  inter_weighted + local_weighted 

# 'que proporcion detectamos de los que hay'
def recall(route):
    data_route = analize(route)
    recallIntercontinentales = recallXClase(data_route.inter)
    recallLocales = recallXClase(data_route.local)
    inter_weighted = recallIntercontinentales * data_route.inter.class_weight 
    local_weighted = recallLocales * data_route.local.class_weight
    return  inter_weighted + local_weighted 

def accuaracy(route):
    data_route = analize(route)
    accuaracyIntercontinentales = accuaracyXClase(data_route.inter)
    accuaracyLocales = accuaracyXClase(data_route.local)
    inter_weighted = accuaracyIntercontinentales * data_route.inter.class_weight 
    local_weighted = accuaracyLocales * data_route.local.class_weight
    return  inter_weighted + local_weighted 

def accuaracyXClase(classData):
    sumOfAll = classData.tp+classData.tn+classData.fp+classData.fn
    
    if sumOfAll == 0: 
        return 1
    else:
        return float(classData.tp+classData.tn)/ sumOfAll

def precisionXClase(classData):  
    if (classData.tp + classData.fp) == 0: 
        return 1
    else:
        return float(classData.tp)/(classData.tp+classData.fp)

def recallXClase(classData):  
    if (classData.tp + classData.fn) == 0: 
        return 1
    else:
        return float(classData.tp)/(classData.tp+classData.fn)

def detectedAs(clase, hop):
    if clase == INTER:
        return hop.intercontinental
    elif clase == LOCAL:
        return not hop.intercontinental
    else: 
        raise Exception('unknown class in detectedAs')

def trulyOfClass(clase, hop, prev_hop):
    if clase == INTER:
        return not sameContinent(hop.ip_address, prev_hop.ip_address) 
    elif clase == LOCAL:
        return sameContinent(hop.ip_address, prev_hop.ip_address)
    else: 
        raise Exception('unknown class in trulyOfClass')

def sameContinent(ip_1, ip_2):
    continent_1 = 1
    continent_2 = 1
    reader = geoip2.database.Reader('./geodata/GeoLite2-City.mmdb')
    try:
        response_1 = reader.city(ip_1)
        city_1 = response_1.country.iso_code
    except Exception:
        city_1 = 'ar'
    try:
        response_2 = reader.city(ip_2)
        city_2 = response_2.country.iso_code
    except Exception:
        city_2 = 'ar'

    continent_1 = transformations.cca_to_ctn(city_1)
    continent_2 = transformations.cca_to_ctn(city_2)
    
    return continent_1 == continent_2

def printMetrics(hops):
    print 'Precision (tp/tp+fp): '+ str(precision(hops))
    print 'Recall (tp/tp+fn): '+ str(recall(hops))
    print 'Accuaracy (tp+tn/tp+tn+fn+fp): '+ str(accuaracy(hops))