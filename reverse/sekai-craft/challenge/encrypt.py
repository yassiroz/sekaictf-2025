DELTA = 0x0aef98da
MASK32 = 0xFFFFFFFF
ROUNDS = 32


def G(x: int, k: int) -> int:
    return ((((x << 4) & MASK32) ^ (x >> 5)) + x ^ k) & MASK32


def xtea_mc_encrypt(v0: int, v1: int, key: tuple[int, int, int, int],
                    rounds: int = ROUNDS) -> tuple[int, int]:
    k0, k1, k2, k3 = key
    k = (k0, k1, k2, k3)

    s = 0
    for _ in range(rounds):
        s = (s + DELTA) & MASK32
        v0 = (v0 + G(v1, k[s & 3])) & MASK32
        v1 = (v1 + G(v0, k[(s >> 11) & 3])) & MASK32
    return v0, v1


def xtea_mc_decrypt(v0: int, v1: int, key: tuple[int, int, int, int],
                    rounds: int = ROUNDS) -> tuple[int, int]:
    k0, k1, k2, k3 = key
    k = (k0, k1, k2, k3)

    s = (DELTA * rounds) & MASK32
    for _ in range(rounds):
        v1 = (v1 - G(v0, k[(s >> 11) & 3])) & MASK32
        v0 = (v0 - G(v1, k[s & 3])) & MASK32
        s  = (s - DELTA) & MASK32
    return v0, v1


def levers_to_block(lever_bits: list[int], offset: int) -> tuple[int, int]:
    v0 = sum(lever_bits[offset + i]      << i for i in range(32))
    v1 = sum(lever_bits[offset + 32 + i] << i for i in range(32))
    return v0 & MASK32, v1 & MASK32


def block_to_levers(v0: int, v1: int) -> list[int]:
    return [(v0 >> i) & 1 for i in range(32)] + [(v1 >> i) & 1 for i in range(32)]


def main() -> None:
    flag = b's3k41cr4tg00d:^)'
    assert len(flag) == 16
    key = (0x5f7438da, 0xf1fa60fb, 0x289c2239, 0x88042cb9)

    plain0 = (int.from_bytes(flag[:4], 'little'), int.from_bytes(flag[4:8], 'little'))
    plain1 = (int.from_bytes(flag[8:12], 'little'), int.from_bytes(flag[12:16], 'little'))

    cipher0 = xtea_mc_encrypt(*plain0, key)
    cipher1 = xtea_mc_encrypt(*plain1, key)

    print("cipher block #0 :", [hex(x) for x in cipher0])
    print("cipher block #1 :", [hex(x) for x in cipher1])

    assert xtea_mc_decrypt(*cipher0, key) == plain0
    assert xtea_mc_decrypt(*cipher1, key) == plain1


if __name__ == "__main__":
    main()
