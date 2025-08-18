DELTA = 0x0aef98da
KEY_WORDS = (0x5f7438da, 0xf1fa60fb, 0x289c2239, 0x88042cb9)
CIPHER_WORDS = (0x1021d4ff, 0xa32b2ead, 0x4c38d5e, 0x15a65d4b)


def G(x: int, k: int) -> int:
    return ((((x << 4) & 0xFFFFFFFF) ^ (x >> 5)) + x ^ k) & 0xFFFFFFFF


def xtea_mc_decrypt(v0: int, v1: int, key: tuple[int, int, int, int], 
                    rounds: int = 32) -> tuple[int, int]:
    k0, k1, k2, k3 = key
    k = (k0, k1, k2, k3)

    s = (DELTA * rounds) & 0xFFFFFFFF
    for _ in range(rounds):
        v1 = (v1 - G(v0, k[(s >> 11) & 3])) & 0xFFFFFFFF
        v0 = (v0 - G(v1, k[s & 3])) & 0xFFFFFFFF
        s  = (s - DELTA) & 0xFFFFFFFF
    return v0, v1


def block_to_levers(v0: int, v1: int) -> list[int]:
    return [(v0 >> i) & 1 for i in range(32)] + [(v1 >> i) & 1 for i in range(32)]


ans = [
    *xtea_mc_decrypt(CIPHER_WORDS[0], CIPHER_WORDS[1], KEY_WORDS),
    *xtea_mc_decrypt(CIPHER_WORDS[2], CIPHER_WORDS[3], KEY_WORDS),
]
flag = b''.join([x.to_bytes(4, 'little') for x in ans])
print(f'{flag=}')

# solve.mcfunction
x, y, z = (18, -59, 7)
levers = block_to_levers(ans[0], ans[1]) + block_to_levers(ans[2], ans[3])
for i, lever in enumerate(levers):
    print(f'setblock {x-i} -59 7 minecraft:lever[powered={"true" if lever else "false"}]')
