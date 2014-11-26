#!/bin/bash

unset pid
pid=`ps -ef | grep named | grep -v grep | awk '{print $2}'`
if [ -z "$pid" ]; then
	/usr/local/sbin/named -n 16
	echo "start named at `date`"
fi
