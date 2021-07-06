#!/usr/bin/env python3
# Software License Agreement (BSD License)
#
# Copyright (c) 2018, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>

#Keyboard
import sys
import tty
import termios
 
def readchar():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch
 
def readkey(getchar_fn=None):
    getchar = getchar_fn or readchar
    c1 = getchar()
    if ord(c1) != 0x1b:
        return c1
    c2 = getchar()
    if ord(c2) != 0x5b:
        return c1
    c3 = getchar()
    return chr(0x10 + ord(c3) - 65)

"""CDBUS IAP Tool

examples:

read config:
  ./cdbus_iap.py --out-file conf.bin --addr=0x0801F800 --size=30

write config:
  ./cdbus_iap.py --in-file conf.bin --addr=0x0801F800

read fw:
  ./cdbus_iap.py --out-file fw.bin --addr=0x0800c000 --size=xxx
  
write fw:
  ./cdbus_iap.py --in-file fw.bin --addr=0x0800c000
"""

R_conf_ver = 0x0002 # len: 2
R_conf_from = 0x0004 # len: 1
R_do_reboot = 0x0005 # len: 1
R_keep_in_bl = 0x0006 # len: 1
R_save_conf = 0x0007 # len: 1

import sys, os
import struct
import _thread
import re
from argparse import ArgumentParser
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), './pycdnet'))

from cdnet.utils.log import *
from cdnet.utils.cd_args import CdArgs
from cdnet.dev.cdbus_serial import CDBusSerial
from cdnet.dev.cdbus_bridge import CDBusBridge
from cdnet.dispatch import *

args = CdArgs()
direct = args.get("--direct") != None
local_mac = int(args.get("--local-mac", dft="0xaa" if direct else "0x00"), 0)
dev_str = args.get("--dev", dft="ttyUSB0")
baud = int(args.get("--baud", dft="115200"), 0)
motor_addr = args.get("--m-a", dft="80:00:55" if direct else "80:00:fe")
dd_addr = args.get("--d-a", dft="80:00:55" if direct else "80:00:02")


sub_size = 128

if args.get("--help", "-h") != None:
    print(__doc__)
    exit()

if args.get("--verbose", "-v") != None:
    logger_init(logging.VERBOSE)
elif args.get("--debug", "-d") != None:
    logger_init(logging.DEBUG)
elif args.get("--info", "-i") != None:
    logger_init(logging.INFO)


dev = CDBusSerial(dev_str, baud=baud)
CDNetIntf(dev, mac=local_mac)
sock = CDNetSocket(('', 0xcdcd))
sock_dbg = CDNetSocket(('', 9))


def dbg_echo():
    while True:
        rx = sock_dbg.recvfrom()
        #print('\x1b[0;37m  ' + re.sub(br'[^\x20-\x7e]',br'.', rx[0][5:-1]).decode() + '\x1b[0m')
        print('\x1b[0;37m  ' + re.sub(br'[^\x20-\x7e]',br'.', rx[0]).decode() + '\x1b[0m')

_thread.start_new_thread(dbg_echo, ())

def csa_write_info(addr):
    sock.sendto(b'\x00', (addr, 1))
    ret, _ = sock.recvfrom(timeout=1)
    if ret == None or ret[0] != 0x80:
        print(f'write info error')
    return ret
    
def csa_read_info(addr):
    sock.sendto(b'\x00', (addr, 1))
    ret, sec = sock.recvfrom(timeout=1)
    print(f'ret = {ret}')
    print(f'sec = {sec}')
    
    if ret == None or ret[0] != 0x80:
        print(f'csa_read error at: 0x{offset:x}, len: {len_}')
    return ret

def csa_write(offset, dat, addr):
    sock.sendto(b'\x20' + struct.pack("<H", offset) + dat, (addr, 5))
    ret, _ = sock.recvfrom(timeout=1)
    if ret == None or ret[0] != 0x80:
        print(f'csa_write error at: 0x{offset:x}: {dat.hex()}')
    return ret
    
def csa_read(offset, len_):
    sock.sendto(b'\x00' + struct.pack("<HB", offset, len_), (addr, 5))
    ret, sec = sock.recvfrom(timeout=1)
    print(f'ret = {ret}')
    print(f'sec = {sec}')
    
    if ret == None or ret[0] != 0x80:
        print(f'csa_read error at: 0x{offset:x}, len: {len_}')
    return ret

#bailey
def work_thread():
    import time
    i = 1
    while True:
        print(i) # 输出i
        i += 1
        time.sleep(1)

csa_write_info(dd_addr)
csa_read_info(dd_addr)

_thread.start_new_thread(work_thread, ())

#lock
csa_write(0x00d6, b'\x01\x00', motor_addr)

def main_thread():
    global run_flag
    while True:
        key=readkey()
        if run_flag==0:
            if key=='w':
                print('w')
                csa_write(0x00b1, b'\x01\x00', motor_addr)
                csa_write(0x00bc, b'\x40\x06\x00\x00', motor_addr)
            if key=='W':
                print('W')
                csa_write(0x00b1, b'\x01\x00', motor_addr)
                csa_write(0x00bc, b'\x40\x1f\x00\x00', motor_addr)
            if key=='s':
                print('s')
                csa_write(0x00b1, b'\x01\x00', motor_addr)
                csa_write(0x00bc, b'\xc0\xf9\xff\xff', motor_addr)
            if key=='S':
                print('S')
                csa_write(0x00b1, b'\x01\x00', motor_addr)
                csa_write(0x00bc, b'\xc0\xe0\xff\xff', motor_addr)
        
        if key=='r':
            print('r')
            run_flag = int(not run_flag)
        if key=='q':
            print('Quit.')
            break
    
#main
run_flag = 0
main_thread()

"""
home 00b1
state 00d6
"""

