#!/usr/bin/env python

from scapy import all
from scapy.layers.inet import IP,TCP
from scapy.all import conf,sniff

def analyse(pkt):
    if TCP in pkt:
        if pkt[TCP].dport == 6969:
            print "got a packet"
            print "pkt[TCP].dport is %s" % pkt[TCP].dport
            print "pkt[IP].src %s" % pkt[IP].src
            print "pkt[IP].dst %s" % pkt[IP].dst
   
def main():
    running = True
    while running:
        try:
            filter = "tcp dst port 6969"
            sniff(filter = filter,prn=analyse,count=10,store=0)
        except KeyboardInterrupt:
            running = False


if __name__ == "__main__":
    conf.iface = "eth0.200"
    main()

