from ptrlib import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import *

from tqdm import tqdm
import os
from montgomery_isogenies.kummer_line import KummerLine
from montgomery_isogenies.kummer_isogeny import KummerLineIsogeny

proof.arithmetic(False)

MI = 3
KU = 9
MIKU = 39

ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(ells) - 1

Fp = GF(p)
F = GF(p**2, modulus=x**2 + 1, names='i')
i = F.gen(0)
E0 = EllipticCurve(F, [1, 0])
E0.set_order((p + 1)**2)
_E0 = KummerLine(E0)


def group_action(_C, priv, G):
    es = priv[:]
    while any(es):
        x = Fp.random_element()
        P = _C(x)
        A = _C.curve().a2()
        s = 1 if Fp(x ^ 3 + A * x ^ 2 + x).is_square() else -1

        S = [i for i, e in enumerate(es) if sign(e) == s and e != 0]
        k = prod([ells[i] for i in S])
        Q = int((p + 1) // k) * P
        for i in S:
            R = (k // ells[i]) * Q
            if R.is_zero():
                continue

            phi = KummerLineIsogeny(_C, R, ells[i])
            _C = phi.codomain()
            Q, G = phi(Q), phi(G)
            es[i] -= s
            k //= ells[i]

    return _C, G


def oracle():
    final_a2 = int(io.recvlineafter(b"= ").decode())
    final_G = eval(io.recvlineafter(b"=").decode().replace(":", ","))
    final_E = EllipticCurve(F, [0, final_a2, 0, 1, 0])
    final_E.set_order((p + 1)**2)
    _final_E = KummerLine(final_E)
    _final_G = _final_E(final_G)

    return _final_E, _final_G




def BEAM_solver(io):
    privs = []
    alice_priv = [0] * len(ells)

    for _ in tqdm(range(MI + KU)):
        _final_E1, _final_G = oracle()
        priv = [-1] * len(ells)
        alice_priv = [pi + ai for pi, ai in zip(priv, alice_priv)]
        io.sendlineafter(b">", str(priv)[1:-1])

    for _ in tqdm(range(MIKU - (MI + KU))):
        _final_E1, _final_G = oracle()

        final_E2, _final_G2 = group_action(_final_E1, [-1] * len(ells), _final_G)
        final_E2.curve().set_order((p + 1)**2)

        ret1 = _final_G.curve_point().order()
        ret2 = (_final_G2).curve_point().order()
        priv = [-1 if (ret1 / ret2) % ell == 0 else 0 for ell in ells]

        alice_priv = [pi + ai for pi, ai in zip(priv, alice_priv)]
        io.sendlineafter(b">", str(priv)[1:-1])
        privs.append(priv)

    for _ in range(len(ells)):
        tmp = [privs[k][_] for k in range(MIKU - (MI + KU))][::-1]
        try:
            index = tmp.index(-1)
            print(tmp[index + 1:index + 2])
            # index = tmp[:16].index(-1)
            if sum(tmp[index + 1:index + 2]) == 0 and tmp[index + 1:index + 3] != []:
                alice_priv[_] += 1
        except ValueError:
            pass

    return [-1 * ai for ai in alice_priv]



fault = 0
success = 0

for _ in range(20):
    # io = process(["sage", "chall.sage"], hexdump=False)
    io = remote("nc alter-ego.chals.sekai.team 1337", hexdump=False, ssl=True)
    io.debug = False
    
    ret = BEAM_solver(io)
    io.debug = True
    print(sned := [-MIKU + _ for _ in ret])
    io.sendlineafter(b">", str(sned)[1:-1])
    if b"CANT FIND MY" in (message := io.recvline()):
        fault += 1
    else:
        success += 1
        print(fault)
        print(success)
        io.sh()
        exit()
    print(message)
    
    io.close()
