#!/usr/bin/env python

from __future__ import print_function
from hashlib import sha256
import sys

def main(password):
    """Print the data block required to unlock the drive"""
    password = "WDC." + password
    password = password.encode("utf-16")[2:] # remove fffe
    for i in range(1000):
        password = sha256(password).digest()

    header = "45" # Signature
    header = header + "0000000000" # Reserved
    header = header + "0020" # Password Length
    header = header.decode("hex")

    sys.stdout.write(header + password)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {0} <password>".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
