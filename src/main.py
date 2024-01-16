import logging
import tomlkit
import re
import sys
from intervaltree import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

TRIM_WINDOW_SIZE=12000

class AttackDB:

    def __init__(self, signatures):
        self.signatures = signatures
        self.sequences = dict()

    def timeoutFlows(self, currTime):
        temp=list()
        for k,v in self.sequences.items()
          if (currTime - v.lastPacketTime) > v.ttl:
             temp.append(k)
        for x in temp:
             self.sequences.pop(x)
          
    def verifyChecksum(self, p:Packet):
        prevSum = p.chksum
        del p.chksum
        newCheckSum=p.__class__(raw(p)).chksum
        if prevSum==newCheckSum:
            return True
        return False

class Session:
    def __init__(self, init_seqNum, wscale, pkt_time=0, pkt_ttl=60):
        self.init_seq = init_seqNum
        self.stream = IntervalTree()
        self.status = False #If True session is active else session is inactive
        self.A = False #ACK Flag check
        self.wScaleFactor = 2**wscale
        self.lastPacketTime = pkt_time
        self.ttl = pkt_ttl

    def insertStream(self, start, end, payload):
        overlappedPacks=self.stream.overlap(start,end)
        insertFlag=False
        if len(overlappedPacks)==0:
            self.stream.addi(start,end,payload)
            insertFlag=True
        else:
            overlappedPacks=sorted(overlappedPacks)
            for currInt in overlappedPacks:
                if start < currInt.begin:
                    self.stream.addi(start,currInt.begin,payload[start:currInt.begin])
                    start=currInt.end
                    insertFlag=True
                elif start >= currInt.begin and start < currInt.end:
                    if end >= currInt.end:
                        start=currInt.end
                if end < currInt.end and end >= currInt.begin:
                    if start < currInt.begin:
                        end=currInt.begin
            if start < end:
                self.stream.addi(start,end, payload[start:end])
                insertFlag=True
        if insertFlag:
            self.mergeStream()
        
        return insertFlag

    def mergeStream(self):
        s=sorted(self.stream)
        startInt=s[0]
        for i in range(1,len(s)):
            currInt=s[i]
            if(startInt.end == currInt.begin):
                self.stream.discard(startInt)
                self.stream.discard(currInt)
                currInt=Interval(startInt.begin, currInt.end, startInt.data+currInt.data)
                self.stream.add(currInt)
            startInt=currInt
    
    def detectAttack(self, attckDB: AttackDB):
        initInter=list(self.stream[self.stream.begin()])[0]
        for i, sig in enumerate(attckDB.signatures):
            if(sig.search(initInter.data)):
                self.status=False
                return i
        return -1            

    def clean(self):
        self.status = False
        self.SA = False
        del self.stream
        self.stream = IntervalTree()
      
    def trimming(self):
        initInter=list(self.stream[self.stream.begin()])[0]
        if len(initInter.data) > TRIM_WINDOW_SIZE:
            newInter = Interval(initInter.begin, initInter.end, initInter.data[0:(TRIM_WINDOW_SIZE*int(len(initInter.data)/TRIM_WINDOW_SIZE))])            
            self.stream.discard(initInter)
            self.stream.add(newInter)

    def setRecentPacket(self, currTime, ttl):
        self.ttl = ttl
        self.lastPacketTime = currTime

    def logDetection(tv_sec, tv_usec, src_ip, src_port, dst_ip, dst_port, attackId):
       d = {
          'tv_sec': tv_sec,
          'tv_usec': tv_usec,
          'source': {
             'ipv4_address': src_ip,
             'tcp_port': src_port
          },
          'target': {
              'ipv4_address': dst_ip,
              'tcp_port': dst_port
          },
          'attack': attackId
       }
      print(d)

def processPackets(attckDB:AttackDB, p:Packet):
    ip = p[IP]
    if not attckDB.verifyChecksum(ip):
        return

    if TCP in ip:
        tcp = p[TCP]

        if not attckDB.verifyChecksum(tcp):
            return

        flow = (ip.src, ip.sport, ip.dst, ip.dport)
        invflow = (ip.dst, ip.dport, ip.src, ip.sport)
        
        if tcp.flags.S:
            Wscale=0
            for i in tcp.options:
                if i[0]=="WScale":
                    Wscale=i[1]
                    break
            session = Session(tcp.seq, Wscale, p.time, ip.ttl)
            attckDB.sequences[flow]=session


            if tcp.flags.A:
                session = attckDB.sequences.get(invflow)
                if session:
                    session.status=True
        
        elif tcp.flags.P and tcp.flags.A:
            payload = raw(tcp.payload)
            if(len(payload) > 0):
                session = attckDB.sequences.get(flow)
                if session and session.status and (len(payload) < (tcp.window * session.wScaleFactor)):
                    if session.insertStream((tcp.seq - session.init_seq), ((tcp.seq - session.init_seq)+len(payload)), payload):
                        session.setRecentPacket(p.time,ip.ttl)
                        attackId=session.detectAttack(attckDB) 
                        if attackId != -1:
                            logDetection(int(p.time), int((p.time - int(p.time))* (10**6)), ip.src, ip.sport, ip.dst, ip.dport, attackId)
                            session.clean()
                            attckDB.sequences.pop(flow)
                        else:
                            session.trimming()

        elif (tcp.flags.F and tcp.flags.A) or tcp.flags.R:
            session = attckDB.sequences.get(flow)
            if session:
                attckDB.sequences.pop(flow)

        elif tcp.flags.A:
            session = attckDB.sequences.get((invflow))
            if session:
                if session.status == False:
                    session.status = True
        attckDB.timeoutFlows(p.time)

    else:
        payload=raw(ip.payload)
        if(len(payload) > 0):
            for i, sig in enumerate(attckDB.signatures):
                if(sig.search(payload)):
                    logDetection(int(p.time), int((p.time - int(p.time))* (10**6)), ip.src, ip.sport, ip.dst, ip.dport, i)
                    break
       
                
def main():
    attackRuleFile = sys.argv[1]
    packetSniffFile = sys.argv[2]

    attackSignatures = [re.compile(x.encode()) for x in tomlkit.load(open(attackRuleFile,'r'))['signatures']]
    attackDB = AttackDB(attackSignatures)
    
    sniff(offline=packetSniffFile, store=False, quiet=True, prn=lambda x: processPackets(attackDB,x))

if __name__ == "__main__":
    main()
