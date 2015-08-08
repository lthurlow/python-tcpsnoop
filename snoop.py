import logging
import socket
import datetime
import time
import os
import threading
import pdb
import sys
import bisect
import traceback

## because it is a shared lib
sys.path.insert(0, "./netfilterlib/")
from netfilterqueue import NetfilterQueue
sys.path.append("scapy")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)10s] %(levelname)7s %(message)s"
class SingleLevelFilter(logging.Filter):
    def __init__(self, passlevel, reject):
        self.passlevel = passlevel
        self.reject = reject

    def filter(self, record):
        if self.reject:
            return (record.levelno != self.passlevel)
        else:
            return (record.levelno == self.passlevel)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

filelog = logging.FileHandler(filename='debug.out',mode='w')
filelog.setFormatter(logging.Formatter(FORMAT))
filelog.setLevel(logging.DEBUG)
logger.addHandler(filelog)

console = logging.StreamHandler(sys.__stdout__)
console.addFilter(SingleLevelFilter(logging.INFO,False))
console.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(console)

"""
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
"""

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
sudo iptables -I FORWARD -i eth1 -j NFQUEUE --queue-num 1
sudo iptables -I FORWARD -i eth2 -j NFQUEUE --queue-num 1

ANHOST3:
sudo iptables -I INPUT -i eth2 -m statistic --mode random --probability 0.2 -j DROP
"""

class Cache:
  cache = {}
  unacked = {}
  def __init__(self):
    self.cache = {}
  ##overwrite the string function for printing cache
  def __str__(self):
    stri = ""
    for f in self.cache:
      for x in self.cache[f]:
        stri+=("%s: %s (%s)\n" % (f,x[0],x[2]))
    ## peel off last newline
    if stri:
      return stri[:-1]
    else:
      return "Object empty"
  ## insert section, due to bisect, will keep the Cache seq's sorted by seq/acknum
  def insert(self, flow, seq, pkt):
    r = datetime.datetime.now()
    if flow not in self.cache:
      self.cache[flow] = [(seq,pkt,r)]
      return 0
    else:
      seq_in = [x[0] for x in self.cache[flow]]
      if seq_in:
        if seq not in seq_in:
          bisect.insort(seq_in,seq)
          ti = seq_in.index(seq)
          self.cache[flow].insert(ti,(seq,pkt,r))
          return ti
      else:
        self.cache[flow] = [(seq,pkt,r)]
        return 0
    return None
  ## remove an element from the cache
  def remove(self,flow,seq):
    if flow in self.cache:
      seq_in = [x[0] for x in self.cache[flow]]
      if seq in seq_in:
        ti = seq_in.index(seq)
        self.cache[flow].remove(self.cache[flow][ti])
        return ti 
    return None
  ## return the cache entry, (seq,pkt,ts)
  def get(self,flow,seq):
    if flow in self.cache:
      seq_in = [x[0] for x in self.cache[flow]]
      if seq in seq_in:
        ti = seq_in.index(seq)
        return self.cache[flow][ti]
    return None
  ## will return all of the flows stored in the cache
  def getkeys(self):
    return self.cache.keys()
  ## will delete a flow from the cache
  def clean(self,flow):
    self.cache.pop(flow,None)
  # will return all of the packets in a flow
  def flush(self,flow):
    ld = []
    for data in self.cache[flow]:
      ld.append(data[1])
    return ld
  ## test if a flow is in a cache
  def getflow(self,flow):
    if flow in self.cache.keys():
      return True
    else:
      return False
  ## will modify the flow to change ts to None if applicable, it will
  ## also return the time since creation, and the udpate call
  def update(self,flow,seq):
    seq_in = [x[0] for x in self.cache[flow]]
    if seq in seq_in:
      ti = seq_in.index(seq)
      r = datetime.datetime.now()
      ts = self.cache[flow][ti][2]
      item = self.cache[flow][ti]
      self.cache[flow][ti] = (item[0],item[1],None)
      if ts:
        return (r-ts).total_seconds()
      else:
        return None
    return None
  ## resend will look at the last 10 packets, and will resend it if the rtt value
  ## passes a threshold over the smoothed rtt value
  def resend(self,flow,rtt):
    r = datetime.datetime.now()
    for x in self.cache[flow][:-10]:
      #pdb.set_trace()
      if x[2] != None:
        if (r-x[2]).total_seconds()*1000 > 3*rtt:
          sendp(Ether(dst="00:00:00:00:00:22")/(x[1])[IP], iface="eth2",verbose=0)
        self.cache[flow][self.cache[flow].index(x)] = (x[0],x[1],r)  
    return
  ## this function will be used to return the first unacked packet
  def unack(self,flow):
    if flow not in self.unacked:
      self.unacked[flow] = -1
    seq_in = []
    if self.unacked[flow] != -1:
      seq_in = [x[0] for x in self.cache[flow][self.unacked[flow]:]]
    else:
      seq_in = [x[0] for x in self.cache[flow]]
    for seq in seq_in:
      if self.cache[flow][seq_in.index(seq)][2] != None:
        ## dont think this will get messed up by insert
        self.unacked[flow] = seq_in.index(seq)
        return self.cache[flow][seq_in.index(seq)][0]
    return None
  def get_prev(self,flow,num):
    seq_in = [x[0] for x in self.cache[flow]]
    try:
      if seq_in.index(num) <= 1:
        seq_want = self.cache[flow][0]
      else:
        seq_want = self.cache[flow][seq_in.index(num)-1]
    except:
      seq_want = self.cache[flow][seq_in.index(unack(flow))]
    return seq_want
    

#this function will need to track all the snoop neccesary variables:
# such as if it is tcp, what byte is being acknowledge, what the last byte  ack was
# also need to have 2 queues for normal and high priority
# those queues should be pointers to the packets

# we should drop packets as required, will need to find a way to re-create the pkt
# may need to go back to scapy, and use the copied packet, to generate packet from
# the ground up using scapy

first_pkt = {}
fin_hand = {}

# data cache 
#dcache = {}
dcache = Cache()
# ack cache (lazy way)
acache = Cache()

## seq, ack
lastseq = {}

transmit = {}
dupack = {}

rtt = 200 #really around 500us

# rtt = (a * old-rtt) + ((1-a)*new-rtt)
def set_rtt(new_rtt):
  global rtt
  ## make it into milliseconds
  logger.debug("old rtt: %s, passed in: %s" % (rtt,new_rtt))
  new_rtt = new_rtt * 1000
  rtt = (.9*rtt) + ((1-.9) * new_rtt)
  logger.debug("updated rtt: %s" % rtt)
  return 

## we will call update on dcache, this both returns us
## the time it has taken since the packet was inserted in the 
## datacache and the current time, for an rtt.
def update_timer(flow,num):
  global dcache
  #if dcache.get(flow,num)[2] != None:
  inv_flow = ((flow[0][::-1]),(flow[1][::-1]))
  try:
    new_rtt = dcache.update(inv_flow,num)
    if new_rtt:
      set_rtt(new_rtt)
    #dcache.resend(inv_flow,rtt)
  except:
    logger.error("Looks like key missing - fine if after FIN")
  return

def print_accept():
  logger.info("ACCEPTED")
  logger.debug("----"*20)
  logger.debug("\n")
def print_drop():
  logger.info("DISCARDED")
  logger.debug("----"*20)
  logger.debug("\n")

## instead of sending out SACKs across good link, send individual ack's
def send_ack(sp,acknum):
  logger.debug("SEND_ACK")
  pkt = IP(version=4L,ihl=5L,tos=0x0,len=52,id=sp[IP].id,flags="DF",frag=0L,ttl=sp[IP].ttl,\
        proto="tcp",src=sp[IP].src,dst=sp[IP].dst,options=[])/\
        TCP(sport=sp[TCP].sport,dport=sp[TCP].dport,seq=sp[TCP].seq,ack=acknum,dataofs=8L,\
        reserved=0L,flags="A",window=0,urgptr=0,options=[('NOP', None), ('NOP', None),\
        sp[TCP].options[2]])
  
  del sp[TCP].chksum
  del sp[IP].chksum
  ## this will re-generate the checksums for IP/TCP
  pkt = pkt.__class__(str(pkt))
  ## FIXME
  sendp(Ether(dst="00:00:00:00:00:01")/pkt[IP], iface="eth1",verbose=0)
  logger.debug("sent ACK: %s" % acknum)
  #logger.debug("pkt:\n%s" % pkt[TCP].__repr__())

def handle_sel_acks(pkt,flow,acks):
  logger.debug("HANDLE SELECTIVE ACKS")
  global acache
  global dcache
  inv_flow = ((flow[0][::-1]),(flow[1][::-1]))
  sp = IP(pkt.get_payload())
  found = False
  logger.debug("\tselective acks recieved: %s" % acks)
  for acknum in acks:
    if not acache.get(flow,acknum):
      logger.debug("unique: %s" % acknum)
      acache.insert(flow,acknum,sp)
      update_timer(flow,acknum)
      send_ack(sp,acknum)

  logger.info("Duplicate Ack: SACKS")
  pkt.drop()
  logger.debug("\tdcache updated:\n%s" % dcache)
  logger.debug("\tacache updated:\n%s" % acache)


def accept_packet(pkt,flow,seqnum,acknum,ack_flag):
  global lastseq

  logger.debug("ACCEPT PACKET")
  pkt.accept()
  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))

  lastseq[flow] = (seqnum,acknum)
  if ack_flag==1:
    acache.insert(flow,acknum,sp)
    update_timer(flow,acknum)
    #dcache.remove(inv_flow,acknum)

  elif ack_flag==2:
    #dcache.remove(inv_flow,acknum)
    acache.insert(flow,acknum,sp)
    dcache.insert(flow,seqnum,sp)
    update_timer(flow,acknum)
    #try:
    #except Exception,e:
    #  logger.error("piggyback not working")
    #  logger.error(traceback.format_exc())
      
    ## we could do this for all, but for now assumption is reciever is bad not sender
    """
    if (flow,seqnum) not in transmit:
      transmit[(flow, seqnum)] = set_rtt_timer()
      t = threading.Thread(target=check_retransmit, args=(flow,seqnum,))
      t.start()
    """
  else:
    dcache.insert(flow,seqnum,sp)
    """
    if (flow,seqnum) not in transmit:
      transmit[(flow, seqnum)] = set_rtt_timer()
      t = threading.Thread(target=check_retransmit, args=(flow,seqnum,))
      t.start()
    """
  logger.debug("dcache:\n%s" % dcache)
  logger.debug("acache:\n%s" % acache)
  logger.debug("rtt: %s"% str(rtt))
  print_accept()
  
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
  global transmit

  logger.debug("SNOOP_DATA")

  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  seqnum = int(sp["TCP"].getfieldval('seq'))
  acknum = int(sp["TCP"].getfieldval('ack'))
  flow = (ips,ports)

  logger.debug("\tcurrent flow: %s" % str(flow))
  inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))

  prev_seq = lastseq[flow][0]
  prev_ack = lastseq[flow][1]
  logger.debug("\tlastseq: %s" % prev_seq)
  logger.debug("\tcurrent seq: %s" % seqnum)
  
  ack_flag = 0
  ## while packet may contain data, it could also carry a piggyback ack
  ## as data is checked before acks, data will handle check for piggybacks
  if acknum > prev_ack:
    logger.debug("\tPiggybacked ACK")
    ack_flag = 2

  ## case 2
  ## there was loss on our FH link, and congestion
  #if (flow,seqnum) in dcache:
  if dcache.get(flow,seqnum):
    ## first lets see if we already acked it
    ## Case 2b
    if acache.get(inv_flow,seqnum):
      ##FIXME
      sendp(Ether(dst="00:00:00:00:00:22")/sp[IP], iface="eth2",verbose=0)
      pkt.drop()
      print_drop()
    else:
      logger.debug("loss on link, accepting data packet, modifying transmit")
      pkt.accept()
      print_accept()
  else:
    ## case 1
    ## if this sequence number is greater than the last we registered.
    ## FIXME: Rollover seqnum
    if seqnum > prev_seq:
      logger.debug("\thigher seqnum, accepting")
      accept_packet(pkt,flow,seqnum,acknum,ack_flag)
    ## out of order data packet
    ## case 3
    else:
      logger.debug("recieved old packet")
      logger.debug("using: (%s,%s)" % (inv_flow,seqnum)) 
      dcache.insert(flow,seqnum,sp)
      pkt.accept()
      logger.debug("resend out of date data - sending ack: %s" % seqnum)
      print_accept()
  
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
  global first_pkt

  logger.debug("SNOOP_ACK")
  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  acknum = int(sp["TCP"].getfieldval('ack'))
  seqnum = int(sp["TCP"].getfieldval('seq'))

  flow = (ips,ports)
  inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))

  logger.debug("\tflow: %s" % str(flow))
  logger.debug("\tack: %s" % str(acknum))

  lastacknum =  lastseq[flow][1]
  logger.debug("\tlast ack: ack %s" % (lastacknum))
  ## this is a newer ack we have recieved
  if acknum > lastacknum:
    logger.debug("\tupdate-accept")
    accept_packet(pkt,flow,seqnum,acknum,1)
  ## lower ack than what we have recieved
  else:
    logger.debug("pkt:\n%s" % sp["TCP"].__repr__())
    ## check for SAck in packet
    ## this would be duplicate acks
    sackfield = sp["TCP"].getfieldval("options")[-1]
    if sackfield[0] == "SAck":
      acks = [x for x in sackfield[1]]
      handle_sel_acks(pkt,flow,acks)
      ## if it is also not in dupack, then it is the first one.
      ## case 2
      if (flow,acknum) not in dupack:
        dupack[(flow,acknum)] = 1
        missed = dcache.get_prev(inv_flow,acknum)
        logger.debug("resending data: %s" % missed[0])
        sendp(Ether(dst="00:00:00:00:00:22")/missed[1][IP], iface="eth2",verbose=0)
    ## normal dup ack
    elif acknum == lastacknum and seqnum == lastseq[flow][0]:
      if (flow,acknum) not in dupack:
        dupack[(flow,acknum)] = 1
        missed = dcache.get_prev(inv_flow,acknum)
        logger.debug("resending data: %s" % missed[0])
        sendp(Ether(dst="00:00:00:00:00:22")/missed[1][IP], iface="eth2",verbose=0)
    ## case 3.5/4
    ## current ack < last seen ack
    elif acache.get(flow,acknum):
      pkt.drop()
      print_drop()
    else:
      ## out of order ack.
      if dcache.get(inv_flow,acknum):
        accept_packet(pkt,flow,seqnum,acknum,1)
      ## more case 4
      else:
        pkt.drop()
        print_drop()
        
 
def snoop_create(pkt):
  global dcache
  global acache
  global lastseq
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
  inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))

  logger.debug("\tseq: %s, ack:%s" % (seqnum,acknum))

  ## handle the SYN 
  lastseq[flow] = (seqnum,acknum)

  #if "S" in sp.sprintf('%TCP.flags%'):
  #  dcache.insert(flow,seqnum,sp)

  ## this will get called if and only if there is an S
  ## so this is a SA packet
  if "A" in sp.sprintf('%TCP.flags%'):
    ##verify
    #dcache.remove(inv_flow,acknum-1)
    #acache.insert(flow,acknum,sp)
    lastseq[inv_flow] = (acknum,seqnum)

  fin_hand[flow] = False
  fin_hand[inv_flow] = False

  pkt.accept()
  logger.debug("lastseq: %s" % str(lastseq))
  logger.debug("dcache:\n%s" % dcache)
  print_accept()

         
## this function is called when a FIN pack comes through, we will clean
## up the connection from memmory
def snoop_clean(pkt):
  global dcache
  global acache
  global lastseq
  global transmit
  logger.debug("SNOOP_CLEAN")
  pkt.accept()

  sp = IP(pkt.get_payload())
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  flow = (ips,ports)
  #inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))

  logger.debug("cleaning information for: %s" % str(flow))
  ## I will not remove inv_flows, unless I recieve the FIN from that side as well

  dcache.clean(flow)
  acache.clean(flow)
  
  if flow in lastseq:
    lastseq.pop(flow, None)

  if flow in transmit:
    transmit.pop(flow, None)
  
  """
  for k in dupack:
    if flow == k[0]:
      dupack.pop(k, None)
  """

  logger.debug("cleaning done.")
  print_accept()

#now generally this is working one way FH -> MH.
#if the mobile host is sending data and loss is occuring, not much we
#can do to speed up that
def snoop(pkt):
  global first_pkt
  logger.debug("SNOOP")
  sp = IP(pkt.get_payload())
  seqnum = int(sp["TCP"].getfieldval('seq'))
  acknum = int(sp["TCP"].getfieldval('ack'))
  ips = (sp["IP"].getfieldval('src'),sp["IP"].getfieldval('dst'))

  ##Tear down and create states
  ## if you see a F in flags it means FIN, clean up all connection info.
  logger.info("\tflags: %3s | src:%s dst:%s | seq:%s ack:%s" %\
     (sp.sprintf('%TCP.flags%'),str(ips[0]),str(ips[1]),seqnum,acknum))

  if "F" in sp.sprintf('%TCP.flags%') or "R" in sp.sprintf('%TCP.flags%'):
    logger.debug("\tFIN detected, cleaning.")
    #snoop_clean(pkt)
    pkt.accept()
    return
  ## create flow information in SYN rather than in ack and data.
  elif "S" in sp.sprintf('%TCP.flags%'):
    logger.debug("\tSYN detected, creating flow.")
    snoop_create(pkt)
    return
  
  ports = (sp["TCP"].getfieldval('sport'),sp["IP"].getfieldval('dport'))
  flow = (ips,ports)
  inv_flow = ((ips[1],ips[0]),(ports[1],ports[0]))
  ## handle the last ACK in 3-way handshake
  if not fin_hand[flow]:
    snoop_create(pkt)
    fin_hand[flow] = True
    fin_hand[inv_flow] = True
    first_pkt[flow] = True
    first_pkt[inv_flow] = True
    return

  try:
    prev_seq = lastseq[flow][0]
    prev_ack = lastseq[flow][1]
    logger.debug("\tprev ack: %s   | current ack: %s" % (prev_ack,acknum))
    logger.debug("\tprev seq: %s   | current seq: %s" % (prev_seq,seqnum))

    ## if seqnum is less or greather than previous, we will accept and forward
    if seqnum > prev_seq:
      logger.debug("\tData detected")
      first_pkt[flow] = False
      ## snoop data will catch the piggys
      snoop_data(pkt)
      return
    elif acknum > prev_ack:
      logger.debug("\tACK")
      first_pkt[flow] = False
      snoop_ack(pkt)
      return
    ## if the acknum is greater or less than, we will accept greater and reject lower
    else:
      if flow in first_pkt and first_pkt[flow]:
        ##FIXME, this packet never gets acked.
        logger.debug("\tFirst Packet")
        first_pkt[flow] = False
        if first_pkt[inv_flow]:
          accept_packet(pkt,flow,seqnum,acknum,0)
        else:
          accept_packet(pkt,flow,seqnum,acknum,1)
        return
      else:
        logger.debug("Out of date.")
        if dcache.get(flow,seqnum):
          logger.debug("\t\tflow: %s, in dcache: %s, DATA" % (flow,dcache.get(flow,seqnum)))
          snoop_data(pkt)
        elif acache.get(flow,acknum):
          logger.debug("\t\tflow: %s, in acache: %s, ACK" % (flow,acache.get(flow,acknum)))
          snoop_ack(pkt)
        ## again our assumptions are that the data link side is not lossy, ack side is with iperf.
        else:
          logger.error("flow: %s, inv_flow: %s" % (flow,inv_flow))
          logger.error("seq: %s, ack: %s" % (seqnum,acknum))
          if dcache.get(inv_flow,acknum):
            snoop_ack(pkt)
          else:
            snoop_data(pkt)


  except Exception, e:
    logger.error("ERROR IN SNOOP HANDLE")
    logger.error(str(e))
    logger.error(traceback.format_exc())
    #pkt.accept()



def print_and_accept(packet):
  #print packet
  #pdb.set_trace()
  sp = IP(packet.get_payload())
  logger.debug("%s:%s -> %s:%s" % (sp[IP].src,sp[TCP].sport,sp[IP].dst,sp[TCP].dport))
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
    logger.error(traceback.format_exc())
  logger.info("stopped.")


debug()
