#! /bin/env python

import os,sys,string, math, numpy
timelist = []
with open(sys.argv[1],'r') as fh:
    for line in fh:
        timelist.append(float(line[:-1]))
timelist = sorted(timelist)
print "min max median mean stddev"
print timelist[0], timelist[-1], timelist[len(timelist)/2], sum(timelist)/len(timelist), numpy.std(timelist)
