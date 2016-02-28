#!/usr/bin/env python
import sys

def wdc(password):
    password = "WDC." + password
    password = password.encode("utf-16")[2:]
    from hashlib import sha256
    for i in range(1000):
        password = sha256(password).digest()
    return password

def hdparm(password):
    if password == 'NULL':
        password = ''
    return password.ljust(32, '\0').encode('ascii')

def main(password, method, cmd):
    if method == 'hdparm':
        password = hdparm(password)
    elif method == 'wdc':
        password = wdc(password)

    if cmd == 'unlock':
        field = '00'
    else:
        password = password + password
        if cmd == 'unset':
            field = '10'
        if cmd == 'set':
            field = '01'

    header = '450000' + field + '00000020'
    header = bytes.fromhex(header)
    #header = header.decode("hex")

    sys.stdout.buffer.write(header + password)
    #sys.stdout.write(header + password)

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("passwd", type=str)
parser.add_argument("--hdparm", action="store_true")
group = parser.add_mutually_exclusive_group()
group.add_argument("--unset", action="store_true")
group.add_argument("--set", action="store_true")

args = parser.parse_args()

if args.hdparm:
    if len(args.passwd) > 32:
        sys.exit('Password length cannot be larger than 32!')
    method = 'hdparm'
else:
    method = 'wdc'

if args.unset:
    # sg_raw -s 72 -i OUTPUT_FILE DEVICE c1 e2 00 00 00 00 00 00 48 00
    cmd = 'unset'
elif args.set:
    # sg_raw -s 72 -i OUTPUT_FILE DEVICE c1 e2 00 00 00 00 00 00 48 00
    cmd = 'set'
else:
    # sg_raw -s 40 -i OUTPUT_FILE DEVICE c1 e1 00 00 00 00 00 00 28 00
    cmd = 'unlock'

main(args.passwd, method, cmd)
