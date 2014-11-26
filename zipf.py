#! /bin/env python
import getopt,sys, socket, struct, random, time
import MySQLdb

pm1=MySQLdb.connect(host='127.0.0.1',user='root',db='webserver')
cur1 = pm1.cursor()
cnt = cur1.execute("select count(*) as num from ipv6server group by asn order by num desc ")
result = cur1.fetchall()
print cnt
for i in result:
    print i[0]
cnt = cur1.execute("select count(*) as num from ipv6server group by longitude,latitude order by num desc")
result = cur1.fetchall()
print cnt
for i in result:
    print i[0]
