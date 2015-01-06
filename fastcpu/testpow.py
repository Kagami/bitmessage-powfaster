#!/usr/bin/env python

import binascii
import ctypes
import hashlib
import sys
from struct import unpack, pack
import time


bitmsglib = './bitmsghash.so'
if "win32" == sys.platform:
	bitmsglib = 'BitMsgHash.dll'
bso = ctypes.CDLL(bitmsglib)
bmpow = bso.BitmessagePOW
bmpow.restype = ctypes.c_ulonglong


def _doCPoW(target, initialHash):
    h = initialHash
    m = target
    out_h = ctypes.pointer(ctypes.create_string_buffer(h, 64))
    out_m = ctypes.c_ulonglong(m)
    start = time.time()
    nonce = bmpow(out_h, out_m)
    end = time.time()
    trialValue, = unpack('>Q',hashlib.sha512(hashlib.sha512(pack('>Q',nonce) + initialHash).digest()).digest()[0:8])
    print "Done in {}s: nonce = {} with trial value {} < {} target".format(end-start, nonce, trialValue, target)
    return [trialValue, nonce]


def run(target, initialHash):
    return _doCPoW(target, initialHash)


if __name__ == '__main__':
    print "Run test POW for ~10-60 seconds, please be patient"
    print "Result nonce should be equal to 45833041"
    run(309503935734, binascii.unhexlify('c9653e53abf582d69d3d2c4506457ebc99d2e4ce0145dfcdd37d33658697ad20f73ff07219dadd5102ec1d286e0073df3bce1368e0be76b55ffbf951f5af87cc'))
