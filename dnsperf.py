#! /bin/env python
# [-a"1 2 3"/--aspath="1 2 3"] [-t1/--thread=1] [-q/--quota=2(M/K)] [-h/--help] IPv4/IPv6_addr
# import argparse # new in version 2.7
import getopt,sys, socket, struct, random, time
import IPy, dns.resolver

def dnslookup(querydomain,type='A'):
    #only for IP addr to ASN mapping
    type=type.upper()
    response=[]
    resolver = dns.resolver.Resolver()
    resolver.nameservers=['202.38.101.13']
    try:
        answer=resolver.query(querydomain,type)
    #except dns.exception.DNSException:
    except dns.resolver.NXDOMAIN:
        #Local DNS may return "NXDOMAIN" error, if this happens, pathperf queries authoritative DNS server for answer
        resolver.nameservers=[socket.gethostbyname('ip2.sasm4.net')]
        answer=resolver.query(querydomain,type)
    #dir(answer) 
    if(type=='A' or type=='AAAA'):
        response.append(str(answer.response.answer[0][0]))  #CNAME
        response.append(str(answer.response.answer[1][0]))  #A/AAAA
        return response
    if(type=='TXT'):
        response.append(str(answer.response.answer[0][0]))  #ASN or URL
        return response

def ip2domain(ip, suffix, version=4):
    domain = ''
    if(version==4):
        ip2list = ip.split('.')
        ip2list.reverse()
        domain='.'.join(ip2list)+suffix
    elif(version==6):
        ipt = IPy.IP(ip)
        ipfull = ipt.strFullsize(0)
        ip2list = ipfull.split(':')
        ip2list.reverse()
        domain='.'.join(ip2list)+suffix
    return domain

def ip2asn(ip,version=4):
    if(version==4):
        suffix = '.ip2asn.sasm4.net'
    elif(version==6):
        suffix = '.ip6asn.sasm4.net'
    else:
        return "Wrong IP version"
    domain = ip2domain(ip, suffix, version)
    asn=dnslookup(domain,'txt')
    asn=asn[0].replace('"','')
    return asn.upper()

def ip2webserver(ip,version=4):
    if(version==4):
        suffix = '.ip2server.sasm4.net'
        domain = ip2domain(ip, suffix, version)
        return dnslookup(domain,'A')
    elif(version==6):
        suffix = '.ip6server.sasm4.net'
        domain = ip2domain(ip, suffix, version)
        return dnslookup(domain,'AAAA')
    else:
        return "Wrong IP version"

def ip2url(ip,version=4):
    if(version==4):
        suffix = '.ip2url.sasm4.net'
    elif(version==6):
        suffix = '.ip6url.sasm4.net'
    else:
        return "Wrong IP version"
    domain = ip2domain(ip, suffix, version)
    return dnslookup(domain,'txt')

random.seed()
iplist = []
for i in xrange(1000):
    iplist.append( socket.inet_ntoa(struct.pack("!I", random.randint(2**24,1.75*2**31) ) ) )

tstart = time.time()
for ipaddr in iplist:
    #print ipaddr, ip2asn(ipaddr)
    asn = ip2asn(ipaddr)
print 'Time used: ',time.time() - tstart

tstart = time.time()
for ipaddr in iplist:
    #print ipaddr, ip2webserver(ipaddr)
    webserver = ip2webserver(ipaddr)
print 'Time used: ',time.time() - tstart

tstart = time.time()
for ipaddr in iplist:
    #print ipaddr, ip2url(ipaddr)
    url = ip2url(ipaddr)
print 'Time used: ',time.time() - tstart

    
