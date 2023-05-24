#!/usr/bin/python3

import string
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


if len(sys.argv) <= 1:
    print("rsa_oaep_test.py gen | verify")
    sys.exit(0)

cmd = sys.argv[1]
if cmd != "gen" and cmd != "verify":
    print("rsa_oaep_test.py gen | verify")
    sys.exit(0)

if cmd == "gen":
    K = 2048
    LEN = K // 8
    key = RSA.generate(K)
    kk = key.exportKey()
    print(kk.decode("utf-8"))
    print()
    pubKey = key.publickey()
    print("E =", hex(pubKey.e))
    n = hex(pubKey.n)
    n = "0x" + "0" * (LEN * 2 + 2 - len(n)) + n[2:]
    print("N =", n)
    print()

elif cmd == "verify":
    text = sys.stdin.read()
    p = text.find("\n\n")
    keydata = text[:p]
    key = RSA.importKey(keydata)
    oaepCipher = PKCS1_OAEP.new(key, SHA256)

    def _hex2num(hh):
        if hh in string.digits:
            return ord(hh) - ord('0')
        else:
            return 10 + ord(hh) - ord('a')

    def hex_decode(hh):
        aa = [hh[i:i + 2] for i in range(0, len(hh), 2)]
        bb = [_hex2num(a[0]) * 16 + _hex2num(a[1]) for a in aa]
        return bytes(bytearray(bb))

    lines = text[p:].splitlines()
    msg = [x.strip("msg:").strip() for x in lines if x .startswith("msg:")][0]
    dd = [x.strip() for x in lines if x.startswith("len:")]
    err = 0
    for d in dd:
        x = d.split()
        ll, cc = int(x[1]), hex_decode(x[3])
        try:
            pp = oaepCipher.decrypt(cc).decode("utf-8")
        except ValueError as e:
            err += 1
            print("FAIL", e)
            continue
        if pp != msg[:ll]:
            err += 1
            print("FAIL")
    print("ERROR:", err)
