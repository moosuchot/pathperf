#! /bin/env python
# -*- coding: utf-8 -*-
#   Copyright [2014] [Kun Yu yukun2005@gmail.com]

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at

#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import os,sys,string,re,threading,subprocess,math,time,socket,logging,getopt,glob,shlex,signal
from urlparse import urlparse
import dns.resolver    #install dnspython first http://www.dnspython.org/

loc_hping3 = '/usr/sbin/hping3'
loc_tcpdump = '/usr/sbin/tcpdump'
loc_tshark = '/usr/sbin/tshark'

def usage():
    print "Estimate path performance from website to this client."
    print "For full description of pathperf, visit http://search.sasm3.net/documentation.html\n"
    print "usage: python",sys.argv[0],"[-h/--help] [-4/--IPv4] [-6/--IPv6] [-v/--verbose] [-i em1/--interface=em1] [-s/--buffer=1024] [-b/bypassCDN] [-c/--crawl] [-q/---quota=2] [-t1/--thread=1] -u URL/IP\n"
    print "-4: Use IPv4"
    print "-6: Use IPv6"
    print "-i: interface tcpdump listens to"
    print "-s: buffer size tcpdump uses to capture packets, in Units of KB"
    print "-b: bypass Local DNS, use DNS provided by pathperf"
    print "-c: use wget as a simple crawler, using tcpdump to estimate bw at the same time"
    print "-q: set download quota for wget in crawler mode, in Units of MB"
    print "-t: number of threads used to download webpage"
    print "-u: provide URL to download"
    print "eg:",sys.argv[0],"-u www.youku.com"
    print "or:",sys.argv[0],"-cvt1 -i eth0 166.111.1.1\n"

def dnslookup(querydomain,type='A'):
    type=type.upper()
    response=[]
    resolver = dns.resolver.Resolver()
    resolver.nameservers=[socket.gethostbyname('ip2.sasm4.net')]
    try:
        answer=resolver.query(querydomain,type)
    #except dns.exception.DNSException:
    except dns.resolver.NXDOMAIN:
        #Local DNS may return "NXDOMAIN" error, if this happens, pathperf queries authoritative DNS server for answer
        resolver.nameservers=[socket.gethostbyname('ip2.sasm4.net')]
        answer=resolver.query(querydomain,type)
    #dir(answer)
    if(type=='A' or type=='AAAA'):
        if( str(answer.response.answer[0][0])[-1]=='.'):    #CNAME
            response.append(str(answer.response.answer[0][0])[:-1])    #CNAME
        else:
            response.append(str(answer.response.answer[0][0]))    #CNAME
        response.append(str(answer.response.answer[1][0]))    #A/AAAA
        return response
    if(type=='TXT'):
        response.append(str(answer.response.answer[0][0]))    #ASN or URL
        return response

def ipv6exp(ip6addr):
    """ipv6 address expanding function

    replace :: in an IPv6address with zeros
    return the list after split(':')
    """
    ast2=ip6addr.count('::')
    if(ast2==0): return ip6addr.split(':')
    ast1=ip6addr.count(':')-2*ast2
    num=7-ast1
    i=1
    pad=':'
    while i<num:
        pad=pad+'0:'
        i=i+1
    ip6full=ip6addr.replace('::',pad)
    if ip6full[-1]==':':ip6full=ip6full+'0'
    if ip6full[0]==':':ip6full='0'+ip6full
    #print ip6full
    return ip6full.split(':')
    
def rttmeasure(domain,version=4):
    # accpet as input both domain and ip address
    succeed=0
    rtt_list = []
    errmsg = ''
    if(version==4):
        ip = '0.0.0.0'
        cmd = loc_hping3+' -S -p 80 -c 5 --fast '+ domain
        p1 = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        p1.wait()
        log = p1.stdout.read()
        if(log.count('Unable to resolve')):
            return (0,'0.0.0.0',-1,'Unable to resolve IP address')  #success, ipaddr, rtt
        m = re.findall('len=.*ip=(.*)\sttl=(\d+)\s.*rtt=(.*)\sms',log)
        if m:
            succeed=1
            rtt_list = [ float(i[2]) for i in m ]
        rtt_list = sorted(rtt_list)
        if(rtt_list and rtt_list[len(rtt_list)/2]==0):
            errmsg += "hping3 failed: "+cmd+'\n'+log+'\n'
            succeed = 0
        if (succeed==0):
            cmd = 'ping -n -c 5 '+ domain
            p1 = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            p1.wait()
            log = p1.stdout.read()
            m = re.findall('\d+ bytes from\s(.*):\s.*ttl=(\d+)\stime=(.*)\sms',log)
            if m:
                succeed=1
                rtt_list = [ float(i[2]) for i in m ]
    if(version==6):
        ip = '::'
        cmd = 'ping6 -n -c 5 '+ domain
        p1 = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        p1.wait()
        log = p1.stdout.read()
        if(log.count('unknown host')):
            return (0,'::',-1,'Unable to resolve IP address')
        m = re.findall('\d+ bytes from\s(.*):\s.*ttl=(\d+)\stime=(.*)\sms',log)
        if m:
            succeed=1
            rtt_list = [ float(i[2]) for i in m ]
    if(succeed): 
        rtt_list = sorted(rtt_list)
        if(rtt_list[len(rtt_list)/2]==0):
            errmsg += "RTT estimation failed: "+cmd+'\n'+log+'\n'
            return (0,ip,-1,errmsg)
        return (1,ip,rtt_list[len(rtt_list)/2], errmsg)
    else:
        return (0,ip,-1, errmsg)
        
def burstdetect(totalpacket,loss):
    Prandom = 1e-4
    if(totalpacket<loss or loss==0):
        return 0
    P = math.factorial(totalpacket)/math.factorial(loss)/math.factorial(totalpacket-loss)*Prandom**loss*(1-Prandom)**(totalpacket-loss)
    if(P<Prandom):
        return 1
    else:
        return 0

class mea_thread(threading.Thread):
    def __init__(self, ip, domain, url, version, verbose, number, bypassCDN, crawl, quota):
        threading.Thread.__init__(self)
        self.ip=ip
        self.domain=domain
        self.url=url
        self.version=str(int(version))
        self.verbose=int(verbose)
        self.bypassCDN=int(bypassCDN)
        self.crawl=int(crawl)
        self.quota=int(quota)
        self.number=int(number)
    def run(self):
        global est_result, realip, name
        realurl=self.url
        realip=self.ip
        realdomain=self.domain
        filepath = name + str(self.number)
        cmd = 'wget -T 10 -t 1 --header="Accept: text/html" --user-agent="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.102 Safari/537.36" '
        if(self.crawl):
            cmd += "-r -e robots=off -Q"+str(self.quota)+"m "
        if(self.bypassCDN):
            #wget --header="Host: ak.buy.com" http://206.132.122.75/PI/0/500/207502093.jpg
            cmd += '--header="Host: '+self.domain+'" '
            cmd += '-'+self.version+' -o '+filepath+'.txt -O /dev/null http://'
            if(self.version=='6'):
                cmd += '['+self.ip+']'
            else:
                cmd += self.ip
        else:
            cmd += '-'+self.version+' -o '+filepath+'.txt -O /dev/null http://'\
            +self.domain
        if not self.crawl:
            cmd += self.url
        logging.info( cmd)
        wgettimeout = 60
        killed = 0
        if self.verbose:    print '-'*70,'\n',cmd
        a = subprocess.Popen(shlex.split(cmd))
        t_beginning = time.time()
        seconds_passed = 0 
        while True:
            if a.poll() is not None:
                break
            seconds_passed = time.time() - t_beginning
            if seconds_passed > wgettimeout:
                a.terminate()
                killed = 1 # killing wget may cause incomplete log, no bw, pagesize info in log 
            time.sleep(2)
        try:
        #print filepath
            with open(filepath+'.txt','r') as fh:
                log=fh.read()
        except :
            logging.error("Reading log failed.\nDownload command: %s",cmd)
            est_result=0
            exit()
        if self.verbose:    print '-'*70,'\nParsing Wget log:\n'
        if(log.count(' saved [')==0):
            logging.error("Wget failed to download any files.")
            est_result=2
        loglist=log.split('\n')
        pagelist = []
        timelist = []
        for linenum,logline in enumerate(loglist):
            #print logline
            if(logline.count('Location: ')):    #HTTP redirect
                #logging.warning('HTTP redirection found.\nThe file may not come from the vantage website designated by pathperf.\nThe result could be inaccuate.')
                if(loglist[linenum+1].count('Warning: ')):
                    nextline=loglist[linenum+2]
                else:
                    nextline=loglist[linenum+1]
                nextlist=nextline.split('  ')
                realurl=nextlist[1]
                try:
                    urlist=urlparse(nextlist[1])
                    realurl=urlist.path
                    logging.warning('Actual URL: %s',nextlist[1])
                except:
                    logging.error("URL extraction error. Wget log:\n%s",logline)
            elif(logline.count('Connecting to ') and logline.count('connected')):
                #print 'con****, ',logline
                if(self.ip=='' or logline.count(self.ip)==0):
                    pattern=re.compile('Connecting to (\S+).*\|(\S+)\|\S+.+connected\.')
                    reout=pattern.search(logline)
                    if reout:
                        realdomain=reout.group(1)
                        realip=reout.group(2)
                    #logging.error('Connection info: %s',logline)
            elif(logline.count('saved [')):
                #print 'save***, ',logline
                a1=logline.split(' saved [')
                a2=a1[1].split(']')
                if(a2[0].count('/')):
                    a7=a2[0].split('/')
                    a2[0]=a7[0]
                pagesize=int(a2[0])
                a3=a1[0].split('\'')
                a4=a3[len(a3)-2].split('`')
    
                a5=a4[0].split('(')
                a6=a5[1].split(')')
        
                if(a6[0].count('MB/s')):
                    a8=a6[0].split(' ')
                    literal=float(a8[0])*1024*1024
                elif(a6[0].count('KB/s')):
                    a8=a6[0].split(' ')
                    literal=float(a8[0])*1024
                else:
                    a8=a6[0].split(' ')
                    literal=float(a8[0])
                pagelist.append(pagesize)
                timelist.append(pagesize/literal)
                bandwidth=a6[0]
                #print ip4[0],'\n',ipnum,'\n',tmp1,'\n',directory,'\n',asn,'\n',pagesize,'\n',bandwidth
            else:
                continue
        if self.verbose:
            print "{0}".format(log)
            print '-'*70
        print "Input website: {0}|{1}|{2}".format(self.domain,self.ip,self.url)
        print "Download from: {0}|{1}|{2}".format(realdomain,realip,realurl)
        if est_result!=2:
            if self.crawl==0:
                print "Download size: {0}, Speed : {1}".format(pagesize,bandwidth)
            else:
                totalsize = sum(pagelist)
                avgbw = round(totalsize/sum(timelist),2)
                print "Download size: {0}, Speed : {1} B/s".format(totalsize,avgbw,)
        print '-'*70
        '''
        if(self.ip==realip):
            print "Estimation succeeds!"
        else:
            print "Estimation fails! Add '-b' and try again."
            est_result=0
        '''
start=time.time()
path= '.'
'''
#test code
estimation=mea_thread('206.132.122.75','ak.buy.com','/db_assets/large_images/093/207502093.jpg',4)    #ip,domain,url,version
estimation.start()
while estimation.isAlive():
    time.sleep(0.5)
exit()
'''
if __name__=='__main__':
    try:
        opts,args = getopt.gnu_getopt(sys.argv[1:],"46hvt:i:s:bcq:u:",["ipv4","ipv6","help", "verbose", "thread=", "interface=",  "buffer", "bypassCDN", "crawl", "quota=", "URL="])
    except getopt.GetoptError as err:
        print "\n",str(err),"\n"
        usage()
        sys.exit(2)
    thread = 1
    multi_speed = 0
    verbose = 0
    bypassCDN = 0
    byurl = 0
    crawl = 0
    quota = 2
    interface='em1'
    buf = 2048
    ipv = 4
    for o, a in opts:
        if o in ("-4", "--IPv4"):
            ipv = 4
        elif o in ("-6", "--IPv6"):
            ipv = 6
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-v", "--verbose"):
            verbose = 1
        elif o in ("-s", "--buffer"):
            buf = int(a)
            if buf<1024:
                buf=1024
            if buf>10240:
                buf= 10240
        elif o in ("-t", "--thread"):
            thread = int(a)
            if thread>5:
                thread = 5
            if thread<0:
                thread=1
        elif o in ("-i", "--interface"):
            interface = a
        elif o in ("-b", "--bypasscdn"):
            bypassCDN = 1
        elif o in ("-c", "--crawl"):
            crawl = 1
            print "Crawl mode"
        elif o in ("-q", "--quota"):
            try:
                quota = int(a)
            except:
                quota = 2
            if quota>10: quota = 10
        elif o in ("-u", "--url"):
            byurl = 1
            bypassCDN = 0 # by URL conflicts with bypass URL
            if a.count('://')==0:
                wholeurl = 'http://'+a
            else:
                wholeurl = a
            urltuple = urlparse(wholeurl)
            domain = urltuple[1]
            _,url = a.split(domain)
            serverip = ''
        else:
            print o,a
            assert False, "unhandled option"
            
    if byurl==0:
        if args:
            ipaddr=args[0]
            try:
                socket.inet_pton(socket.AF_INET6,ipaddr)
                ipv=6
            except:
                try:
                    socket.inet_pton(socket.AF_INET,ipaddr)
                    ipv=4
                except:
                    logging.error("Invaild IP address.")
                    sys.exit(1)
        else:
            logging.error("IP address missing!")
            usage()
            sys.exit(2)
        if ipv==4:
            ip4list=ipaddr.split('.')
            ip4list.reverse()
            #IP address to AS number mapping
            #ip4asn='.'.join(ip4list)+'.ip2asn.sasm4.net'
            #print dnslookup(ip4asn,'txt')
            ip4ser='.'.join(ip4list)+'.ip2server.sasm4.net'
            arg1=dnslookup(ip4ser,'a')
            ip4url='.'.join(ip4list)+'.ip2url.sasm4.net'
            arg2=dnslookup(ip4url,'txt')
        else:
            ip6list=ipv6exp(ipaddr)
            ip6list.reverse()
            #IP address to AS number mapping
            #ip6asn='.'.join(ip6list)+'.ip6asn.sasm4.net'
            #print dnslookup(ip6asn,'txt')
            ip6ser='.'.join(ip6list[4:])+'.ip6server.sasm4.net'
            arg1=dnslookup(ip6ser,'aaaa')
            ip6url='.'.join(ip6list[4:])+'.ip6url.sasm4.net'
            arg2=dnslookup(ip6url,'txt')
    
        if arg1[0] in ('Error.','No-IP-Record.','No-Web-Server-in-that-AS.', 'nowebsite.wind.sasm4.net.'):
            logging.error("website mapping failed: %s",arg1[0])
            logging.error("Please provide URL to download directly")
            sys.exit(3)
        serverip = arg1[1]
        domain = arg1[0]
        url = arg2[0].strip('"')
    thr_list=[]
    name = path+os.path.sep+time.strftime("%Y%m%d%H%M%S-%s")+'.'
    packets = name+'pcap'
    dumplog = name+'tcpdump.log'
    if bypassCDN:
        snippet = serverip
    else:
        snippet = domain
    tcpdump = loc_tcpdump+" -s 120 -i {0} host {1} -w {2} -B {3}".format(interface, snippet, packets, buf)
    #starts tcpdump to capture packets
    if verbose:
        print '-'*70,'\n',tcpdump
    b = subprocess.Popen(shlex.split(tcpdump), stdout=subprocess.PIPE, stderr = open(dumplog,'w'))
    time.sleep(0.5)
    est_result=1
    realip = ''
    for i in range(thread):
        thr_list.append(mea_thread(serverip, domain, url, ipv, verbose, i, bypassCDN, crawl, quota) )    #ip,domain,url,version,verbose,num
    for estimation in thr_list:
        estimation.start()
    for estimation in thr_list:
        while estimation.isAlive():
            time.sleep(0.5)
    end=time.time()

    b.send_signal(signal.SIGINT)
    b.wait()
    if(est_result):
        log = ' '.join([ i.rstrip() for i in open(dumplog,'r').readlines()])
        m = re.search("(\d+) packets captured.*(\d+) packets dropped by kernel",log)
        tshark = 1
        if(m):
            total = int(m.group(1))
            dropped = int(m.group(2))
            if(dropped):
                logging.warning("Tcpdump dropped {0} packets during capture, loss rate may be inaccurate. Try increase tcpdump buffer".format(dropped))
            if(total==0):
                tshark = 0
        else:
            tshark = 0
        if tshark==0:
            logging.warning("Tcpdump failed.")
            logging.warning(tcpdump)
            logging.warning(log)
        else:
            success, _, latency, errmsg = rttmeasure(realip,ipv)
            if success == 0 :
                logging.error('Latency measurement failed.')
            tsharkfile = packets+'.tshark'
            tshark = loc_tshark+" -q -r "+packets+' -z io,stat,100,'
            if ipv==6:
                tshark += '"ipv6.src=={0}","tcp.analysis.retransmission && ipv6.src=={0}"'.format(realip)
            else:
                tshark += '"ip.src=={0}","tcp.analysis.retransmission && ip.src=={0}"'.format(realip)
            if(latency>0):
                if(latency<2):
                    tshark = tshark.replace('io,stat,100','io,stat,0.002')
                else:
                    tshark = tshark.replace('io,stat,100','io,stat,'+str(latency/1000.0))
            else:
                tshark = tshark.replace('io,stat,100','io,stat,0.4')
            if verbose:
                print tshark
            c = subprocess.Popen(shlex.split(tshark), stdout=open(tsharkfile,'w'), stderr = subprocess.PIPE)
            c.wait()
            log = open(tsharkfile,'r').read()
            if verbose:
                print log
            if(log.count("appears to be damaged or corrupt")):
                logging.warning("Damaged pcap file detected. Loss rate calculation failed")
            m = re.search("Interval.*:(.*) secs",log)
            if(m):
                interval = float(m.group(1))
            else:
                interval = 0
                logging.warning("tshark: Unable to determine interval")
            m = re.findall("\d+\.\d+[ -<>]+\d+\.\d+\s.*\s(\d+)\s.*\s(\d+)\s.*\s(\d+)\s.*\s(\d+)\s",log)
            #m = re.search("\d+\.\d+[ -<>]+\d+\.\d+\s.*\s(\d+)\s.*\s(\d+)\s.*\s(\d+)\s.*\s\d+\s",log)
            maxbw = 0
            maxdata = 0 # the maximum data block in one bulk transfer (between two dull intervals)
            curdata = 0 # the current data block
            totaldata = 0
            totalloss = 0
            effloss = -1 #effective loss rate
            actloss = -1 #actual loss rate
            serverslow = 0 # 1: slow, 0 not slow, -1 bursty loss detected -> server fast enough and pagesize large enough
            if(interval and m):
                lossinterval = 0
                lossbeforedull = 0 #boolean
                totalpacket = 0
                nopacket = 0 # # of consective intervals without any data 
                datastart = 0 # the first few packets contain only token such as HTTP 200, 304, start calculating only after data transfer
                for i in xrange(len(m)):
                    packetcount = int(m[i][0])
                    datasize = float(m[i][1])
                    losspacket = int(m[i][2])
                    losssize = float(m[i][3])
                    if((datastart==0 and packetcount == 0) or (datastart==0 and datasize/packetcount<300)):
                        continue
                    else:
                        datastart = 1
                    totaldata += datasize
                    totalloss += losssize
                    curdata += datasize
                    totalpacket += packetcount
                    if(nopacket==0):  # packet loss two intervals ago can cause server timeout
                        if(i>1 and m[i-2][2]!='0'):
                            lossbeforedull = 1
                        else:
                            lossbeforedull = 0
                    if(serverslow != -1 and packetcount==0 and 0==lossbeforedull): # count consective dull intervals only when no packet loss happened two RTT before
                        nopacket += 1
                        if(nopacket>1): # two intervals without data leads to the decision of a slow server
                            serverslow = 1
                            if(curdata>maxdata):
                                maxdata = curdata
                            curdata = 0
                    else:
                        nopacket = 0
                    if(losspacket!=0):
                        lossinterval += 1
                        if(burstdetect(packetcount, losspacket)==1):
                            serverslow = -1
                    bwnow = datasize/interval *1460/1514.0
                    if(bwnow>maxbw):
                        maxbw = bwnow
                if(curdata>maxdata):
                    maxdata = curdata
                if(totalpacket):
                    effloss = round(100.0*lossinterval/totaldata*1514,2)
                    actloss = round(100.0*totalloss/totaldata,2)
                totaldata = int(totaldata *1460 / 1514.0) # payload / packet length
            #return (totaldata, maxdata, maxbw, serverslow, effloss)
            print 'tcpdump statistics: latency:',latency,'ms, download size',totaldata,'B, peak speed:',maxbw,'B/s'
            print 'tcpdump statistics: effective loss rate:',effloss,'%, actual loss rate:',actloss,'%'
    file_list=glob.glob(name+'*')
    for f in file_list:
        #pass
        os.remove(f)
    print "Time used: {0} s".format(round(end-start,2))
