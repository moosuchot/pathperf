#! /bin/env python
# This product includes GeoLite data created by MaxMind, available from http://www.maxmind.com
# Date: 2014-01-30

import os,sys,string,struct,socket,threading,time,re,maxminddb, MySQLdb
sys.path.append("/home/kun/mnt")
from webcrawl import *
ISOTIMEFORMAT='%Y-%m-%d %X'
#geo = geoip2.database.Reader(os.path.abspath('.')+os.path.sep+'GeoLite2-City.mmdb')
reader = maxminddb.Reader('/home/kun/topology/GeoLite2-City.mmdb')

pm1=MySQLdb.connect(host='127.0.0.1',user='root',db='webserver')
cur1 = pm1.cursor()
cnt = cur1.execute("select distinct ip from mnt.proximity_rtt") 
result = cur1.fetchall()
for ip, in result:
    asn = ip2asn(ip)
    
    start = time.time()
    # ip -> prefix -> web server
    cmd = "select webdomain from ipv4prefix2vantage where start<={0} and end>={0} and asn='{1}'".format(struct.unpack("!I", socket.inet_aton(ip))[0] ,asn[2:])
    cur1.execute(cmd)
    row = cur1.fetchone()
    end = time.time() - start
    print end
    continue
    '''
    start = time.time()
    record = reader.get(ip)
    if(record is None):
        continue
    lat = record['location']['latitude']
    lon = record['location']['longitude']
    relax=5
    while relax<360:
        cmd="select webdomain from ipv4candidate where asn='{0}' and latitude>{1} and latitude<{2} and longitude>{3} and longitude<{4} order by bw desc limit 1".format(asn, lat-relax/2.0,lat+relax/2.0, lon-relax/2.0, lon+relax/2.0)
        cur1.execute(cmd)
        if cur1.rowcount:
            #print cmd
            break
        else:
            relax=relax*2 
    end = time.time() - start
    print end
    '''
