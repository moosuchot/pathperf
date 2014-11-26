ipcs|grep 134217728|grep 0 |awk '{print $2}'|xargs /usr/bin/ipcrm -m
