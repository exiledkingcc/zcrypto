#!/usr/bin/python3

import base64
import random
import sys

def generate(limit=1000):
    n = random.randint(limit / 4, limit)
    dd = bytes(bytearray(random.randint(0, 255) for _ in range(n)))
    bb = base64.b64encode(dd).decode("ascii")
    hh = "".join("{:02x}".format(x) for x in dd)
    print("H", hh)
    print("B", bb)

for _ in range(10000):
    generate()

