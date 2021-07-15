#! /usr/bin/env bash

tty -s; if [ $? -ne 0 ]; then xfce4-terminal -e "\"$0\""; exit; fi
if [ $UID -ne 0 ]; then echo "restart as root"; sudo "$0"; exit; fi

python3 ./a_main.py
