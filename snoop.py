import logging
import socket
import datetime
import time
import os
import logging
import pprint
import threading
import pdb
import sys
## because it is a shared lib
sys.path.insert(0, "./netfilterlib/")
from netfilterqueue import NetfilterQueue
sys.path.append("scapy")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)20s] %(levelname)10s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s | " % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)

#sudo apt-get install build-essential python-dev libnetfilter-queue-dev
# https://github.com/kti/python-netfilterqueue
## https://github.com/fqrouter/python-netfilterqueue.git
## http://sign0f4.blogspot.com/2015/03/using-nfqueue-with-python-right-way.html
## fqrouter fork has a set_payload implementation compared with kti's kit

## we will want the snoop code to run iptables over the interfaces to snoop on
## which for us, for atleast this first part will be on all interfaces.

## from there it we can either add them all to the same queue, or a queue per interface
## input is for sending out, output is for recieving in.
## sudo iptables -I INPUT -i eth1 -j NFQUEUE --queue-num 1

## Run on snoop host:
## sudo iptables -I INPUT -p tcp -i eth1 -j NFQUEUE --queue-num 1
## grab only tcp packets on interface eth1, and send them to userspace to be handled.
## For debug with ping
## sudo iptables -I OUTPUT -p icmp -i eth1 -j NFQUEUE --queue-num 1


#this function will need to track all the snoop neccesary variables:
# such as if it is tcp, what byte is being acknowledge, what the last byte  ack was
# also need to have 2 queues for normal and high priority
# those queues should be pointers to the packets

# we should drop packets as required, will need to find a way to re-create the pkt
# may need to go back to scapy, and use the copied packet, to generate packet from
# the ground up using scapy

# data cache 
dcache = {}
# ack cache (lazy way)
acache = {}

lastack = {}
lastseq = {}

transmit = {}
dupack = {}

## basic logic for tcp snoop:
"""
snoop_data -> handles communication on reliable side
snoop_ack  -> handles communication on wireless/un-reliable side

FH = Fixed Host (reliable)
MH = Mobile Host (unreliable)
BS = Base Station (snooper)

snoop_data
FH -> BS -> MH
if (tcp) packet is new (not seen before)
  if packet has correct sequence number
    1. Cache the packet, forward to MH
    # normally this would also be timestamped to better predict rtt
  else:
    2. Mark as congestion, Forward to MH
    # break this down
    2a. if the sequence number > last ack seen (we will see that this happens on the MH side)
      # the packet was likely not recieved by MH, so forward on
    2b. if the sequence number < than current sequence number
      # already recieved by MH, means the ack was lost between FH and MH
      Need to send the last recieved ack from MH to FH again.
      # their protocol doesnt do this, but for ease of re-generating an ack, lets just cache acks too.
else:
  3 (also a 2c). Forward to MH, Reset the local retransmission timer
  ## Packet is old, but out of order, so no cache available
  ## mark it as being retransmitted (this will be used by snoop_ack)
"""
# src,dst,sport,dport, seq
# ((src,dst),(sport,dport)) : seq
# if we do it like this, this means that src->dst is different than dst->src

def snoop_data(pkt):
  logger.debug("SNOOP_DATA")
  global dcache
  global lastseq
  global transmit

  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  seqnum = sp["TCP"].getfieldval('seq')
  ## get the timestamp to also check for sequence number overflow
  # ('Timestamp',(Num,0))
  ts = sp["TCP"].getfieldval('options')[2][1][0]
  flow = (ips,ports)

  logger.debug("\tcurrent flow: %s" % flow)
  ## this will be used when access the lastack dict for acks to our seqs
  inv_flow = ((ips[1],ips[0]),(ips[1],ips[0]))

  logger.debug("\tlastack: %s" % lastseq)
  ## start by setting up the flow information
  if flow not in lastseq:
    logger.debug("flow not in lastack.")
    lastseq[flow] = (seqnum,ts)
    ## this also implies 1. as it is first packet in flow, not just not seen
    ## cache it
    dcache[(flow,seqnum)].append(sp)
    logger.debug("pkt added to cache")
    logger.debug("\tdata cache: %s" % dcache)
    ## forward it
    pkt.accept()
  ## we have atleast seen 1 packet recently from source/dst
  else:
    ## case 1
    logger.debug("flow has been seen before")
    if lastseq[flow][0] > seqnum:
      ## we have not recieved an ack from our src/dst, this is bad.
      ## in the 3 way handshake, SYN should hit above logic, SYN/ACK
      if inv_flow in acache:
        ## I think this also will make sure that we accept it in the case
        ## of a tcp seq number overflow
        prev_ack = acache[inv_flow].getfieldval('ack')
        if seqnum > prev_ack or ts > lastseq[flow][1]:
          logger.debug("normal pkt, accept, and cache")
          lastseq[flow] = seqnum
          dcache[(flow,seqnum)] = sp
          pkt.accept()
        else:
          logger.debug("sequence number lower or timestamp less, packet thrown")
      else:
        logger.error("inverse flow is not in a-cache, this is bad.")
        logger.error("logic should prevent this.")
    else:
      ## case 2b
      if sp == dcache[(flow,seqnum)]:
        logger.debug("recieved old data pkt, resending last ack back to sender")
        ## using scapy here to inject our last ack seen back to FH
        #send(lastack[inv_flow])
        #FIXME: need a way to correlate the missing ack in acache
        send(acache[inv_flow])
      ## case 3
      ## there was loss on our FH link, and congestion
      else:
        logger.debug("loss on link, accepting data packet, modifying transmit")
        logger.debug("transmit: %s" % transmit[flow])
        ##FIXME: this needs to be used by snoop_ack
        transmit[flow].append(sp)
        pkt.accept()
  
"""
snoop_ack
MH -> BS -> FH
if (tcp) ack is new:
  1. free buffers (clear cache), update rtt, foward ack to FH
else:
  if ack a duplicate ack:
    if first duplicate ack:
      2. retransmit lost packet (from cache) at high priority
    else:
      3. Drop ack
  else:
    4. Drop ack (spurious ack, rare)
"""
def snoop_ack(pkt):
  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  flow = (ips,ports)
  acknum = sp["TCP"].getfieldval('ack')
  ts = sp["TCP"].getfieldval('options')[2][1][0]

  ## first ack in flow
  if flow not in lastack:
    lastack[flow] = sp
    pkt.accept()
  else:
    lastacknum =  lastack[flow].getfieldval('ack')
    lastackts  =  lastack[flow].getfieldval('options')[2][1][0]
    ## this is a newer ack we have recieved
    ## FIXME: fix seq overflow
    if acknum > lastacknum:
      lastack[flow] = sp
      acache[flow] = sp
      pkt.accept()
    ## lower ack than what we have recieved
    else:
      ## this is a duplicate pkt
      ## FIXME: this should be based on acknum, not the packet itself
      if sp in acache:
        ## case 2
        if (flow,ack) not in dupack:
          dupack[(flow,ack)] = 1
          pkt.drop()
          ##FIXME: insert the correct value for finding the data packet
          send(dcache[inv_flow])
        ## case 3
        else:
          pkt.drop()
      ## case 4
      else:
        pkt.drop()
          


## this function is called when a FIN pack comes through, we will clean
## up the connection from memmory
def snoop_clean(pkt):
  global dcache
  global acache
  global lastseq
  global lastack
  global transmit

  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  flow = (ips,ports)
  ## I will not remove inv_flows, unless I recieve the FIN from that side as well
  if flow in dcache:
    dcache.pop(flow, None)
  if flow in acache:
    acache.pop(flow, None)
  if flow in lastseq:
    lastseq.pop(flow, None)
  if flow in lastack:
    lastack.pop(flow, None)
  if flow in transmit:
    transmit.pop(flow, None)


#now generally this is working one way FH -> MH.
#if the mobile host is sending data and loss is occuring, not much we
#can do to speed up that
def snoop(pkt):
  sp = IP(pkt.get_payload())
  ## if you see a F in flags it means FIN, clean up all connection info.
  if "F" in sp["TCP"].flags:
    snoop_clean(pkt)
  ## if there is a int value > 0 for ack field, it is an ack
  if sp["TCP"].getfieldval('ack') == 0:
    snoop_ack(pkt)
  else:
    snoop_data(pkt)


def print_and_accept(packet):
  print packet
  sp = IP(packet.get_payload())
  packet.accept()

def start_snoop(ilist,qname="NFQUEUE",qval=1):
  for interface in ilist:
    ## if the host is the destination (to forward above ip)
    subprocess.call("sudo iptables -I INPUT -i eth%s -j %s --queue-num %s"\
                    % (interface,qname,int(qval)))
    ## our base station should use this
    subprocess.call("sudo iptables -I FORWARD -i eth%s -j %s --queue-num %s"\
                    % (interface,qname,int(qval)))

  nfqueue = NetfilterQueue()
  nfqueue.bind(qval, snoop)
  try:
    nfqueue.run()
  except Exception,e:
    logger.error("Error in Snoop start: %s" % str(e))

def debug():
  nfqueue = NetfilterQueue()
  nfqueue.bind(1, print_and_accept)
  try:
    nfqueue.run()
  except Exception,e:
    logger.error("Error in Snoop start: %s" % str(e))


debug()
