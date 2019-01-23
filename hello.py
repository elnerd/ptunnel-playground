#!/usr/bin/env python

from scapy.all import *
from ptunnel_pkt import PTunnel, PTunnelChallenge, PTunnelChallengeResponse, calc_challenge_response
import random

conf.L3socket=L3RawSocket
conf.verb = 3
global seq
seq = 0
myid = random.randint(0,65535)


def encode_magic(magic_hexstr):
    return struct.unpack("!I", binascii.unhexlify(magic_hexstr))[0]


def send_hello(ip, magic):
    global seq
    magic = encode_magic(magic)
    pkt = IP(dst=ip)/ICMP(id=myid,seq=seq)/PTunnel(magic=magic,dst="127.0.0.1",dport=22,from_user=0,from_proxy=1,state=0,id=myid, seq=0, ack=65535)
    seq += 1 # One for sent packet
    res = sr1(pkt)
    return res

def send_challenge_response(ip, magic, challenge_response):
    global seq
    magic = encode_magic(magic)
    pkt = IP(dst=ip)/ICMP(id=myid,seq=seq)/PTunnel(magic=magic,dst="127.0.0.1",seq=seq,dport=22,ack=0,from_user=0,from_proxy=1,state=4,data_len=32,id=myid)/PTunnelChallengeResponse(data=challenge_response)
    print pkt.show()
    res = sr1(pkt,timeout=3, filter="icmp")
    seq += 1 # one for sent packet
    return res

    return res
def fuzz_data(ip, magic, data, data_len):
    global seq
    pkt = IP(dst=ip)/ICMP(id=myid, seq=seq)/PTunnel(magic=magic,dst="127.0.0.1",dport=22,from_user=0,from_proxy=1,seq=seq,ack=random.randint(0,65535),state=2,data_len=data_len,id=myid)/Raw(data)
    print "Sending"
    print pkt.show()
    res = sr1(pkt, timeout=3, filter="icmp")
    seq+=1

    return res

ip = sys.argv[1]
magic = "deadc0de"

res = send_hello(ip,magic)
print res.show()
if res[PTunnel].state == 4 and PTunnelChallenge in res:
    print "Received a challenge!"

    challenge = res[PTunnelChallenge]
    res = send_challenge_response(ip,magic,challenge.calc_response("mypassword"))
    print res.show()
    #res = fuzz_data(ip,magic,"hello world\n",len("hello world\n"))
    res = fuzz_data(ip,magic,"hello world\n",len("hello world\n"))
    print res.show()
else:
    print "No challenge?!"

