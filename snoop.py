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
logger.setLevel(logging.INFO)

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
## grab only tcp packets on interface eth1, and send them to userspace to be handled.
## for incoming traffic (from an1)
## sudo iptables -I INPUT -p tcp -i eth1 -j NFQUEUE --queue-num 1
## for outgoing traffic (from an2), if using routes, change to correct interface
## sudo iptables -I OUTPUT -p tcp -o eth1 -j NFQUEUE --queue-num 1
"""
sudo iptables -I INPUT -p tcp -i eth1 -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -p tcp -o eth1 -j NFQUEUE --queue-num 1

sudo iptables -I INPUT -p tcp -i eth1 -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -p tcp -o eth2 -m statistic --mode random --probability 0.2 -j DROP


ANHOST2:
sudo iptables -I FORWARD -p tcp -i eth1 -j NFQUEUE --queue-num 1
sudo iptables -A OUTPUT -p tcp -o eth2 -j NFQUEUE --queue-num 1

sudo iptables -I FORWARD -p tcp -j NFQUEUE --queue-num 1


ANHOST3:
sudo iptables -I INPUT -i eth2 -m statistic --mode random --probability 0.2 -j DROP
"""


#this function will need to track all the snoop neccesary variables:
# such as if it is tcp, what byte is being acknowledge, what the last byte  ack was
# also need to have 2 queues for normal and high priority
# those queues should be pointers to the packets

# we should drop packets as required, will need to find a way to re-create the pkt
# may need to go back to scapy, and use the copied packet, to generate packet from
# the ground up using scapy

first_pkt = {}

# data cache 
dcache = {}
# ack cache (lazy way)
acache = {}

lastack = {}
lastseq = {}

transmit = {}
dupack = {}

rtt = 100 #really around 500us


def check_retransmit(flow,num,sp):
  logger.debug("RETRANSMIT")
  #sleep until rtt
  time.sleep(rtt/1000)
  #if (flow,num) in dcache:
  while (flow,num) in dcache:
    logger.info("\tpacket, not acked yet, resending:%s" % num)
    send(sp)
    time.sleep(3*rtt/1000)

def set_rtt_timer():
  r = datetime.datetime.now()
  r +=  datetime.timedelta(microseconds=10000)
  return r

def accept_packet(pkt,flow,ts,seqnum,acknum,ack_flag):
  global acache
  global dcache
  global lastack
  global lastseq
  global transmit

  logger.debug("ACCEPTING PACKET\n")
  pkt.accept()
  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))

  if ack_flag==1:
    acache[(inv_flow,acknum)] = sp
    lastack[inv_flow] = (acknum,ts)
    ## then clean out data cache thats been acknowledged
    dcache.pop((flow,acknum-1),None)
    if (flow,seqnum) in transmit:
      transmit.pop((flow,acknum-1),None)

  elif ack_flag==2:
    acache[(inv_flow,acknum)] = sp
    lastack[inv_flow] = (acknum,ts)
    dcache.pop((flow,acknum-1),None)
    if (flow,seqnum) in transmit:
      transmit.pop((flow,acknum-1),None)

    dcache[(flow,seqnum)] = sp
    lastseq[flow] = (seqnum,ts)
    ## we could do this for all, but for now assumption is reciever is bad not sender
    transmit[(flow, seqnum)] = set_rtt_timer()
    #t = threading.Thread(target=check_retransmit, args=(flow,seqnum,sp,))
    #t.start()
  else:
    dcache[(flow,seqnum)] = sp
    lastseq[flow] = (seqnum,ts)
    ## we could do this for all, but for now assumption is reciever is bad not sender
    if (flow,seqnum) not in transmit:
      transmit[(flow, seqnum)] = True
      t = threading.Thread(target=check_retransmit, args=(flow,seqnum,sp,))
      t.start()
    else:
      logger.debug("thread still searching for ack: %s" % seqnum)
  
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
  global dcache
  global lastseq
  global transmit

  logger.debug("SNOOP_DATA")

  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  seqnum = int(sp["TCP"].getfieldval('seq'))
  acknum = int(sp["TCP"].getfieldval('ack'))
  ts = int(sp["TCP"].getfieldval('options')[2][1][0])
  flow = (ips,ports)

  logger.debug("\tcurrent flow: %s" % str(flow))
  ## this will be used when access the lastack dict for acks to our seqs
  inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))

  #prev_ack = lastack[inv_flow][0]
  prev_seq = lastseq[flow][0]

  logger.debug("\tlastseq: %s" % prev_seq)
  logger.debug("\tcurrent seq: %s" % seqnum)
  
  ack_flag = 1
  ## while packet may contain data, it could also carry a piggyback ack
  ## as data is checked before acks, data will handle check for piggybacks
  if "A" in sp.sprintf('%TCP.flags%'):
    logger.debug("Piggyback ACK")
    ack_flag = 2

  ## start by setting up the flow information
  if flow not in lastseq:
    logger.debug("flow not in lastack.")
    logger.error("should be handled in snoop_create now.")
    ## forward it
    accept_packet(pkt,flow,ts,seqnum,acknum,ack_flag)
  ## we have atleast seen 1 packet recently from source/dst
  else:
    ## case 3
    ## there was loss on our FH link, and congestion
    if (flow,seqnum) in dcache:
      logger.debug("loss on link, accepting data packet, modifying transmit")
      logger.debug("old transmit: %s" % transmit[(flow,seqnum)])
      transmit[(flow, seqnum)] = set_rtt_timer()
      pkt.accept()
    else:
      ## case 1
      ## if this sequence number is greater than the last we registered.
      ## FIXME: Rollover seqnum
      if seqnum > prev_seq:
        logger.debug("\thigher seqnum, accepting")
        accept_packet(pkt,flow,ts,seqnum,acknum,ack_flag)
      ##seqnum < lastseq[flow][0]
      else:
        ## case 2b
        logger.debug("recieved old data pkt, resending last ack back to sender")
        logger.debug("acache: %s" % acache.keys())
        logger.debug("using: (%s,%s)" % (inv_flow,acknum)) 
        #pdb.set_trace()
        #accept_packet(pkt,flow,ts,seqnum,0)
        send(acache[(inv_flow,acknum)])
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
  logger.debug("SNOOP_ACK")
  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  acknum = int(sp["TCP"].getfieldval('ack'))
  ts = int(sp["TCP"].getfieldval('options')[2][1][0])

  flow = (ips,ports)
  inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))

  logger.debug("\tflow: %s" % str(flow))
  logger.debug("\tack: %s" % str(acknum))

  ## first ack in flow
  if inv_flow not in lastack:
    logger.debug("\tflow first ack")
    accept_packet(pkt,flow,ts,-1,acknum,1)
  else:
    lastacknum =  lastack[inv_flow][0]
    lastackts  =  lastack[inv_flow][1]
    logger.debug("\tlast ack: ack %s, ts: %s" % (lastacknum,lastackts))
    ## this is a newer ack we have recieved
    ## FIXME: fix seq overflow
    if acknum > lastacknum:
      logger.debug("\tupdate-accept")
      accept_packet(pkt,flow,ts,-1,acknum,1)
    ## lower ack than what we have recieved
    else:
      logger.debug("\tacknowledgement out of date")
      ## if we have already seen ack, then it must be a duplicate
      if acknum == lastacknum:
        ## if it is also not in dupack, then it is the first one.
        ## case 2
        ## FIXME: may need to be inv flow
        if (flow,acknum) not in dupack:
          dupack[(flow,acknum)] = 1
          ## need to resend the data
          try:
            send(dcache[(flow,acknum)])
            #transmit[(flow, acknum-1)] = set_rtt_timer()
            pkt.drop()
          except KeyError:
            logger.error("\tERROR-IN RESEND DATA")
            logger.info("dcache: %s" % dcache.keys())
            logger.info("problem using: (%s,%s)" % (flow,acknum)) 
            pkt.drop()
            
        ## if it already has a dup ack, we should drop it
        ## case 3
        else:
          logger.debug("Packet dropped.")
          pkt.drop()
      ## case 4
      else:
        logger.debug("Packet dropped.")
        pkt.drop()
 
def snoop_create(pkt):
  global dcache
  global acache
  global lastseq
  global lastack
  global transmit
  logger.debug("SNOOP_CREATE")

  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  logger.debug("\tIP: %s" % str(ips))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  logger.debug("\tPORTS: %s" % str(ports))
  flow = (ips,ports)
  logger.debug("\tFLOW: %s" % str(flow))
  seqnum = int(sp["TCP"].getfieldval('seq'))
  acknum = int(sp["TCP"].getfieldval('ack'))
  logger.debug("\tseq: %s, ack:%s" % (seqnum,acknum))
  ts = int(sp["TCP"].getfieldval('options')[2][1][0])
  inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))

  ## handle the SYN 
  lastseq[flow] = (seqnum,ts)
  dcache[(flow,seqnum)] = sp
  first_pkt[flow] = True
  ## this will get called if and only if there is an S
  ## so this is a SA packet
  if "A" in sp.sprintf('%TCP.flags%'):
    lastack[inv_flow] = (acknum,ts)
    dcache.pop((inv_flow,acknum),None)

  pkt.accept()
  logger.debug("lastseq: %s" % str(lastseq))
  logger.debug("lastack: %s" % str(lastack))

         
## this function is called when a FIN pack comes through, we will clean
## up the connection from memmory
def snoop_clean(pkt):
  global dcache
  global acache
  global lastseq
  global lastack
  global transmit
  logger.debug("SNOOP_CLEAN")

  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  flow = (ips,ports)
  #inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))

  logger.debug("cleaning information for: %s" % str(flow))
  ## I will not remove inv_flows, unless I recieve the FIN from that side as well
  for k in dcache:
    if flow == k[0]:
      dcache.pop(k, None)
  for k in acache:
    if flow == k[0]:
      acache.pop(k, None)
  if flow in lastseq:
    lastseq.pop(flow, None)
  if flow in lastack:
    lastack.pop(flow, None)
  if flow in transmit:
    transmit.pop(flow, None)

  for k in dupack:
    if flow == k[0]:
      dupack.pop(k, None)

  logger.debug("cleaning done.")
  pkt.accept()

#now generally this is working one way FH -> MH.
#if the mobile host is sending data and loss is occuring, not much we
#can do to speed up that
def snoop(pkt):
  logger.debug("SNOOP")
  sp = IP(pkt.get_payload())
  #logger.info("%s" % str(sp["TCP"].__repr__()))
  seqnum = int(sp["TCP"].getfieldval('seq'))
  acknum = int(sp["TCP"].getfieldval('ack'))

  ##Tear down and create states
  ## if you see a F in flags it means FIN, clean up all connection info.
  logger.info("\tflags: %s, seq: %s, ack: %s" % (sp.sprintf('%TCP.flags%'),seqnum,acknum))
  try:
    logger.debug("ack: %s, seq: %s" % (acknum, lastack[flow][0] ))
    logger.debug("[flow] lack: %s, lseq: %s" % (lastack[flow][0],lastseq[flow][0] ))
    #logger.debug("[invf] lack: %s, lseq: %s" % (lastack[inv_flow][0],lastseq[inv_flow][0] ))
  except:
    logger.debug("")
  if "F" in sp.sprintf('%TCP.flags%') or "R" in sp.sprintf('%TCP.flags%'):
    logger.debug("\tFIN detected, cleaning.")
    snoop_clean(pkt)
    return
  ## create flow information in SYN rather than in ack and data.
  elif "S" in sp.sprintf('%TCP.flags%'):
    logger.debug("\tSYN detected, creating flow.")
    snoop_create(pkt)
    return

  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  flow = (ips,ports)
  inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))
  try:
    ## detecting first ack in tcp trace
    if inv_flow not in lastack:
      logger.debug("FIRST ACK")
      snoop_ack(pkt)
    ## detecting duplicate data
    ## FIXME this should be fast lane resend
    elif (flow,seqnum) in dcache:
      logger.debug("Duplicate data detected")
      logger.debug("dcache: %s" % str(dcache.keys()))
      logger.debug("this key: (%s,%s)" % (flow,seqnum))
      snoop_data(pkt)
    ## detecting duplicate ack
    elif (flow,acknum) in acache:
      snoop_ack(pkt)
    else:
      prev_ack = lastack[inv_flow][0]
      prev_seq = lastseq[flow][0]
      logger.debug("prev ack: %s   | current ack: %s" % (prev_ack,acknum))
      logger.debug("prev seq: %s   | current seq: %s" % (prev_seq,seqnum))
      ## if seqnum is less or greather than previous, we will accept and forward
      if seqnum > prev_seq or seqnum < prev_seq:
        logger.debug("\tData detected")
        ## snoop data will catch the piggys
        snoop_data(pkt)
        return
      ## if the seqnum is the same as previous, as is the ack, then it is the first
      ## packet in the tcp flow. FIXME: if less than, fastlane send.
      elif seqnum == prev_seq and acknum == prev_ack:
        logger.debug("\tFirst Packet")
        ts = int(sp["TCP"].getfieldval('options')[2][1][0])
        first_pkt[flow] = False
        if "A" in sp.sprintf('%TCP.flags%'):
          accept_packet(pkt,flow,ts,seqnum,acknum,2)
          return
        else:
          accept_packet(pkt,flow,ts,seqnum,-1,1)
          return
      ## if the acknum is greater or less than, we will accept greater and reject lower
      elif acknum > prev_ack or acknum < prev_ack:
        logger.debug("\tACK")
        snoop_ack(pkt)
        return
      ## code should no longer hit this sequence
      else:
        inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))
        logger.error("seq: %s, lseq: %s, first:? %s"%(seqnum,lastseq[flow][0],first_pkt[flow]))
        logger.error("ack: %s, lack: %s" % (acknum, lastack[inv_flow][0] ))
        snoop_ack(pkt)
        #pkt.drop()
        return
  except Exception, e:
    logger.error("ERROR IN SNOOP HANDLE")
    logger.error(str(e))
    #pkt.accept()



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
  except KeyboardInterrupt:
    return

def debug():
  nfqueue = NetfilterQueue()
  #nfqueue.bind(1, print_and_accept)
  nfqueue.bind(1, snoop)
  try:
    nfqueue.run()
  except Exception,e:
    logger.error("Error in Snoop start: %s" % str(e))


debug()
