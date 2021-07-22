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
        #tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
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
motor_addr = args.get("--m-a", dft="80:00:55" if direct else "80:00:fd")
dev_addr = args.get("--d-a", dft="80:00:55" if direct else "80:00:fe")
adv_addr = "80:00:ff"

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
    
def read_info(addr):
    sock.sendto(b'\x00', (addr, 1))
    # Get name in ret.
    ret, sec = sock.recvfrom(timeout=1)
    #print(ret)
    #print(sec)
    
    #if ret == None or ret[0] != 0x80:
        #print(f'read_info error')
    return ret, sec

def csa_write(offset, dat, addr):
    sock.sendto(b'\x20' + struct.pack("<H", offset) + dat, (addr, 5))
    ret, _ = sock.recvfrom(timeout=1)
    #if ret == None or ret[0] != 0x80:
        #print(f'csa_write error at: 0x{offset:x}: {dat.hex()}')
    return ret
    
def csa_read(offset, len_, addr):
    sock.sendto(b'\x00' + struct.pack("<HB", offset, len_), (addr, 5))
    ret, sec = sock.recvfrom(timeout=1)
    #print(f'ret = {ret}')
    #print(f'sec = {sec}')
    
    #if ret == None or ret[0] != 0x80:
        #print(f'csa_read error at: 0x{offset:x}, len: {len_}')
    return ret

def get_dev_name():
    global dev_name
    dev_name = str(read_info(dev_addr)[0]).split(';')[0].split(' ')[1]
    
def get_dst():
    #csa_read(0x0010, 44, dev_addr) #buf
    dst = struct.unpack("h", csa_read(0x0050, 2, dev_addr)[1:])[0] #dst
    if dst == -32768:
        print("\033[1;31;40m  --- 没有检测到金属 QAQ ---  \033[0m")
    else:
        #dst_s = dst[0] + "." + dst[1:] + "mm" 
        print("\033[1;32;40m DST = %s \033[0m" %dst)
    

def find_dev():
    global dev_addr, time_cut
    print("\033[1;29;40m   %d   \033[0m" %time_cut)
    time_cut += 1
    ret_g, sec_g = read_info(adv_addr)
    if ret_g is None or sec_g is None:
        print("\033[1;31;40m没有找到设备 x_x \033[0m")
    else:
        #get_dst()
        print("\033[1;32;40m已找到设备 ^_^ \033[0m")
        
        if ret_g is not None:
            try:
                ret_g = str(ret_g[1:], encoding = "utf-8").split(';')[0].split(' ')[1]
            except:
                ret_g = 'Null'
                
            print("\033[1;32;40m设备名称: %s \033[0m" %ret_g)
            if ret_g == "bb_dd":
                dd_flag = 1
            else:
                dd_flag = 0
                    
        if sec_g is not None:
            try:
                sec_g = sec_g[0]
            except:
                sec_g = 'Null'
           
            print("\033[1;32;40m设备地址: %s \033[0m" %sec_g)
            dev_addr = sec_g
        
        if dd_flag == 1:
            get_dst()

#bailey
import time
def work_thread():
    global run_flag, stop_flag
    sleep_cut = 0
    
    while True:
        time.sleep(1)
        if run_flag:
            # set address of device.
            get_dev_name()
            if dev_num != 0:
                if dev_name == 'bb_hs':
                    print('Device is hs.')
                    dd_flag = 0;
                    addr_num = (int(dev_num) + 0x10)
                elif dev_name == 'bb_dd':
                    print('Device is dd.')
                    dd_flag = 1;
                    addr_num = (int(dev_num) + 0x20)
            
            # calibration & testing
            # calibration for dd.
            csa_write(0x00b1, b'\x01\x00', motor_addr)
            for i in range(11):
                d_v = struct.pack("i", (0x0640*i))
                print("第 %d 步" %i)
                csa_write(0x00bc, d_v, motor_addr)
                time.sleep(2)
                get_dst()
                print("")
                if dev_num != 0:
                    csa_write(0x0052, struct.pack("b", i), dev_addr) #set
                time.sleep(0.2)
                if stop_flag:
                    stop_flag = 0
                    break   
            time.sleep(1.5)                        
            
            # print address infomation.
            # set and save.
            if dev_num != 0:
                print('addr = %#x' %addr_num)
                addr_num = addr_num.to_bytes(1, byteorder = 'little')
                print("save!")            
                csa_write(0x0009, addr_num, dev_addr) #mac
                csa_write(0x0007, b'\x01', dev_addr) #save
            # motor go home
            csa_write(0x00bc, b'\x00\x00\x00\x00', motor_addr)
            # reboot
            time.sleep(0.5)
            csa_write(0x0005, b'\x01', dev_addr) # reboot
            # Over.    
            print('***Program is over.***\n------------\n')
            run_flag=0
            
            
                
        else:
            if sleep_cut == 0:
                # loop
                sleep_cut += 1
                # cLear for linux
                import os
                os.system("clear")
                # get device infomation
                find_dev()
                #if dst_flag:
                    
                # get dst
                                
            if sleep_cut == 1:
                sleep_cut = 0


def main_thread():
    #lock
    csa_write(0x00d6, b'\x01\x00', motor_addr)
    csa_write(0x00b1, b'\x01\x00', motor_addr)
    global run_flag, dev_num, stop_flag, dst_flag
    while True:
        key = readkey()
        if run_flag == 0:
            #control
            if key == 'w':
                print('w')
                csa_write(0x00b1, b'\x01\x00', motor_addr)
                csa_write(0x00bc, b'\x40\x06\x00\x00', motor_addr)
            if key == 'W':
                print('W')
                csa_write(0x00b1, b'\x01\x00', motor_addr)
                csa_write(0x00bc, b'\x40\x1f\x00\x00', motor_addr)
            if key == 'f':
                print('s')
                csa_write(0x00b1, b'\x01\x00', motor_addr)
                csa_write(0x00bc, b'\xa0\xfe\xff\xff', motor_addr)
            if key == 's':
                print('s')
                csa_write(0x00b1, b'\x01\x00', motor_addr)
                csa_write(0x00bc, b'\xc0\xf9\xff\xff', motor_addr)
            if key == 'S':
                print('S')
                csa_write(0x00b1, b'\x01\x00', motor_addr)
                csa_write(0x00bc, b'\xc0\xe0\xff\xff', motor_addr)
            if key == 'd':
                print('d')        
                d_flag = not d_flag
            #number
            if key == '1':
                print('1')
                dev_num = 1
                run_flag = 1
            if key == '2':
                print('2')
                dev_num = 2
                run_flag = 1
            if key == '3':
                print('3')
                dev_num = 3
                run_flag = 1
            if key == '4':
                print('4')
                dev_num = 4
                run_flag = 1
            if key == '5':
                print('5')
                dev_num = 5
                run_flag = 1
            if key == '6':
                print('6')
                dev_num = 6
                run_flag = 1
            if key == '7':
                print('7')
                dev_num = 7
                run_flag = 1
            if key == '8':
                print('8')
                dev_num = 8
                run_flag = 1
            if key == '0':
                print('0')
                dev_num = 0
                run_flag = 1
        
        elif run_flag:
            if key == ' ':
                print('Stop.')
                stop_flag = 1
                
        if key == 'q':
            print('Quit.')
            csa_write(0x00d6, b'\x00\x00', motor_addr)
            break

#main
#flag
run_flag = 0
dd_flag = 0
stop_flag = 0
d_flag = 0
#num
dev_num = 0
time_cut = 0
dev_name = ''

_thread.start_new_thread(work_thread, ())
main_thread()


"""
mac  0009
set  0052
dst  0050
buf  0010
save 0007
home 00b1
state 00d6
"""

