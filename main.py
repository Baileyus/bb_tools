#!/usr/bin/env python3
# Software License Agreement (BSD License)
#
# Copyright (c) 2018, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>

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
target_addr = args.get("--target-addr", dft="80:00:55" if direct else "80:00:fe")


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


def csa_write(offset, dat):
    sock.sendto(b'\x20' + struct.pack("<H", offset) + dat, (target_addr, 5))
    ret, _ = sock.recvfrom(timeout=1)
    if ret == None or ret[0] != 0x80:
        print(f'csa_write error at: 0x{offset:x}: {dat.hex()}')
    return ret

def csa_read(offset, len_):
    sock.sendto(b'\x00' + struct.pack("<HB", offset, len_), (target_addr, 5))
    ret, sec = sock.recvfrom(timeout=1)
    print(f'ret = {ret}')
    print(f'sec = {sec}')
    
    if ret == None or ret[0] != 0x80:
        print(f'csa_read error at: 0x{offset:x}, len: {len_}')
    return ret

#bailey
csa_write(0x00d6, b'\x01\x00')

while 1:   
    aa = int(input("please enter a: "))
    if aa == 0:
        csa_write(0x00bc, b'\x00\x00')
    elif aa == 1:
        csa_write(0x00bc, b'\x00\x19')

print('done.')


"""
home 00b1
state 00d6
"""

