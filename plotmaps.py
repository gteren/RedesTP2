#!/usr/bin/env python
# For Python, this file uses encoding: utf-8

import geoip2.database
import sys
import json
from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt
import numpy as np


def main(hosts):
    reader = geoip2.database.Reader('./geodata/GeoLite2-City.mmdb')

    # make sure the value of resolution is a lowercase L,
    #  for 'low', not a numeral 1
    fig, ax = plt.subplots(figsize=(12, 12))
    my_map = Basemap(projection='robin', lat_0=0, lon_0=-100,
                     resolution='i', area_thresh=1000.0)

    my_map.drawcoastlines()
    my_map.drawcountries()
    my_map.fillcontinents(color='coral')
    my_map.drawmapboundary()

    my_map.drawmeridians(np.arange(0, 360, 30))
    my_map.drawparallels(np.arange(-90, 90, 30))
    points = []
    for host in hosts:
        try:
            response = reader.city(host['ip_address'])
            lat = response.location.latitude
            lon = response.location.longitude
            x, y = my_map(lon, lat)
            my_map.plot(x, y, 'yo', markersize=18)
            points.append((x, y))
        except Exception:
            print 'IP no encontrada'

    for i in range(len(points)-1):
        x1, y1 = points[i]
        x2, y2 = points[i+1]
        ax.annotate("", xytext=(x1, y1), xy=(x2, y2),
                    arrowprops=dict(facecolor='#EE0000'))

    plt.tight_layout()


if __name__ == '__main__':
    basedir = 'Exp comparacion modelos/'
    files = ['CarnegieFiltrado.txt', 'OxfordFiltrado.txt', 'tokyoFiltrado.txt',
             'hiFiltrado.txt']

    for file in files:
        with open(basedir+file) as f:
            lines = f.read()
            hosts = json.loads(lines)

            main(hosts)
            fname, ext = file.split('.')
            plt.savefig('maps/'+fname+'.pdf')
