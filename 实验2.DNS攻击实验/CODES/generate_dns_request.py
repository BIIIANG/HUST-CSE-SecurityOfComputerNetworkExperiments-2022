#!/usr/bin/python3
from scapy.all import *

# Notice: If the DNS server is configured to only
#         respond to requests from loacl machines,
#         the src_ip should be in the same network
#         as the dst_ip.

# To be modified: Qdsec[qname]

dst_pt = 53						# DNS Server
src_pt = 11803					# Any Free Port
dst_ip = '172.18.0.3'			# DNS Server
src_ip = '172.18.0.27'			# Any Address
domain = 'biang.hust.edu.cn'	# Be modified by C code

# Construct the DNS header and payload
Qdsec = DNSQR(qname=domain)
dns   = DNS(id=0xAAAA, qr=0, qdcount=1, qd=Qdsec)

# Construct the IP, UDP headers, and the entire packet
ip  = IP(dst=dst_ip, src=src_ip, chksum=0)
udp = UDP(dport=dst_pt, sport=src_pt, chksum=0)
pkt = ip/udp/dns

# Save the packet to a file
with open('dns_request.bin', 'wb') as f:
	f.write(bytes(pkt))