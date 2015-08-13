# python-tcpsnoop

This is a lightweight, and possibly error riden implementation Berkeley Snoop Protocol (http://daedalus.cs.berkeley.edu/, http://www.sigmobile.org/awards/mobicom1995-student.pdf) using python.  This code relies NetfilterQueue 3.0 (https://pypi.python.org/pypi/NetfilterQueue/0.3), more speicfically it uses fqrouter's fork (https://github.com/fqrouter/python-netfilterqueue) which implements the set_payload() function.

####What is the Berkeley Snoop Protocol?

The Berkeley Snoop Protocol is a protocol for wireless connections which are prone to errors as well as for mobile hosts.  Pre-dating TCP's ingegration of selective acknowledgements (SACKS).  Snoop gives a sender from a fixed host (generally loss free connection) an alternate view of the connection with the mobile host (lossy connection) through a base station.  Snoop will modify TCP packets which transit the base station to and from the fixed and mobile hosts.  The overall modification of certain TCP packets leads the fixed host to be fooled by the Snoop base station essentially spoofing a reliable link.

####How does it work?

The short and simple version is that the base stations caches data packets.  It will also tracked the rtt from the base station to the mobile host, when a timeout occurs, the base station will resend the data packet.  Thats the first part.  For the mobile station, the base station will keep track of duplicate acknowledgements, but not forward duplicate acknowledgements.  Instead the base station will forward the missing data from the cache back to the mobile host until the data is acknowledged.

####Pitfalls?

Instead of deleting already acknoweledged data, this cache just maintains it.  For mainly reasons this is bad, but very quick and easy to implement.
NetfilterQueue limits the throughput to about 2Mb/s (this is dependant on your CPU for handling interrupts, this is the speed for a single CPU).  On top of this limitation, this code also is in the pipeline, so the overall rate through python-tcpsnoop is about 200Kb/s.

####Setup
By default the code is looking at NFQUEUE 1 for both interfaces.  So your iptables may look something like this:
```sudo iptables -I FORWARD -i eth1 -j NFQUEUE --queue-num 1 && sudo iptables -I FORWARD -i eth2 -j NFQUEUE --queue-num 1```
This is assuming that there exists a route between eth1 and eth2.  For an exmaple setup you can look at set_vmhosts.sh which was my shell script to pre-configure my three machines.


Comments, Fixes, Please email me at lthurlow@ucsc.edu
