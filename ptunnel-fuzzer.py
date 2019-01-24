#!/usr/bin/env python

from scapy.all import *
from ptunnel_pkt import PTunnel
from threading import Thread
import random
import struct
import binascii
import sys

conf.L3socket = L3RawSocket
conf.verb = 3

def encode_magic(magic):
    return struct.unpack("!I",binascii.unhexlify(magic))[0]

def gen_pkt(ip, magic):
    print ip, magic
    magic = encode_magic(magic)
    rand_id = random.randint(0,65535)
    pkt = IP(dst=ip)/ICMP(id=rand_id,seq=0)/fuzz(PTunnel(magic=magic,dst="127.0.0.1",dport=22,from_user=0,from_proxy=1,state=0,id=rand_id,seq=0,ack=65535))
    return pkt


class Sniffer(Thread):
    def __init__(self, interface):
        Thread.__init__(self)
        self.interface = interface
        self.found = []
    def run(self):
        sniff(iface=interface,filter="icmp", prn=self.pkt_handler)
        pass

    def pkt_handler(self, pkt):
        if PTunnel in pkt and pkt[PTunnel].from_user == 1 and pkt[PTunnel].from_proxy == 0 and pkt[IP].src not in self.found:
            print "Found ptunnel ip=%s magic=%s" % (pkt[IP].src, pkt[PTunnel].magic)
            self.found.append(pkt[IP].src)
            print pkt.show()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print "usage: %s network/mask interface magic" % sys.argv[0]
        print "\tdefault magic for ptunnel is d5200880"
        print "\tdefault magic for ptunnel-ng is deadc0de"
        sys.exit()
    
    target = sys.argv[1]
    interface = sys.argv[2]
    magic = sys.argv[3]
    print "Starting sniffer on interface %s" % interface
    sniffer = Sniffer(interface)
    sniffer.start()
    print "Sending packets to %s with magic %s" % (target, magic)
    pkt = gen_pkt(target, magic)
    send(pkt, iface=interface, loop=1)
