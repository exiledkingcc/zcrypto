#!/usr/bin/python3

import random
from Crypto.PublicKey import RSA


K = 2048
LEN = K // 8
key = RSA.generate(K)
pkey = key.publickey()

print("## keys:")
print("E =", hex(pkey.e))
n = hex(pkey.n)
n = "0x" + "0" * (LEN * 2 + 2 - len(n)) + n[2:]
print("N =", n)
print()

print("## tests:")
for i in range(100):
    m = "0x00" + "".join(["{:02x}".format(random.randint(0, 255)) for _ in range(LEN - 1)])
    c = key.encrypt(int(m, 16), "")
    c = hex(c[0])
    c = "0x" + "0" * (LEN * 2 + 2 - len(c)) + c[2:]
    print("M =", m)
    print("C =", c)
