from math import floor, ceil, log2
from Crypto.Util.number import bytes_to_long
import os
from hashlib import shake_128
from ast import literal_eval
from pwn import *

def pack(num: int, length: int, base: int) -> list[int]:
    packed = []
    while num > 0:
        packed.append(num % base)
        num //= base
    if len(packed) < length:
        packed += [0] * (length - len(packed))
    return packed

def get_d(digest, m = 256, w = 21):
    l1 = ceil(m / log2(w))
    l2 = floor(log2(l1*(w-1)) / log2(w)) + 1
    l = l1 + l2
    d1 = pack(bytes_to_long(digest), l1, w)
    checksum = sum(w-1-i for i in d1)
    d2 = pack(checksum, l2, w)
    d = d1 + d2
    return d

# io = process(["python3", "chall.py"])
io = remote("literal-eval.chals.sekai.team", 1337, ssl=True)
io.recvuntil(b"public key:")
root = bytes.fromhex(io.recvline().strip().decode())
k = 255

def send(msg):
    io.recvuntil(b"input:")
    io.sendline(str(msg).encode())
    ret = io.recvline().decode()
    if "Traceback" in ret:
        io.interactive()
    return literal_eval(ret)

msgs = [os.urandom(32) for _ in range(k)]
disgests = [shake_128(b"\x00" + msg).digest(32) for msg in msgs]
ds = [get_d(digest) for digest in disgests]
sigs = send({
    "type": "sign",
    "num_sign": k,
    "inds": {i: 0 for i in range(k)},
    "messages": msgs,
})

target_digest = shake_128(b"\x00" + b"Give me the flag").digest(32)
target = get_d(target_digest)

wots_sign = []
for i in range(len(target)):
    find = False
    for dd, sig in zip(ds, sigs):
        if dd[i] == target[i]:
            wots_sign.append(sig[0][i])
            find = True
            break
    assert find

forged_sig = [wots_sign] + sigs[0][1:]
print(send({
    "type": "get_flag",
    "sig": [forged_sig],
}))

