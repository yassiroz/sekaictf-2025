import random
from functools import lru_cache


random.seed(12313371327381)
DELTA = 0x0aef98da
BITS = 32
ROUNDS = 32
LEVER_LINE = (18, -59, 7)
KEY_WORDS = (0x5f7438da, 0xf1fa60fb, 0x289c2239, 0x88042cb9)
CIPHER_WORDS = (0x1021d4ff, 0xa32b2ead, 0x4c38d5e, 0x15a65d4b)
USED_NAMES: set[str] = set()
MANGLE_NAMES = False


def _gen_name(n: int) -> str:
    name = None
    while name is None or name in USED_NAMES:
        name = ''.join(random.choices('iIl1', k=n))
    USED_NAMES.add(name)
    return name


@lru_cache(maxsize=None)
def mangle(source: str) -> str:
    if not MANGLE_NAMES or source.startswith('$') or source in USED_NAMES:
        return source
    return _gen_name(len(source))


def lever(idx: int) -> str: return mangle(f'lever{idx}')
def v(name: str, idx: int) -> str: return mangle(f'{name}_{idx}')
def k(i: int, j: int) -> str: return mangle(f'k{i}_{j}')
def s(idx: int) -> str: return mangle(f'sum_{idx}')
def d(idx: int) -> str: return mangle(f'delta_{idx}')
def c(block: int, idx: int) -> str: return mangle(f'cipher{block}_{idx}')
def t(prefix: str, idx: int)-> str: return mangle(f'{prefix}_{idx}')


OBJECTIVE = mangle('bit')
ZERO = f'${mangle("zero")}'
TWO = f'${mangle("two")}'
C = f'${mangle("cc")}'
OK = f'${mangle("ok")}'
mc = [
    f'scoreboard objectives add {OBJECTIVE} dummy',
    f'scoreboard players set {ZERO} {OBJECTIVE} 0',
    f'scoreboard players set {TWO} {OBJECTIVE} 2'
]
for b in range(BITS):
    mc.append(f'scoreboard players set {d(b)} {OBJECTIVE} {(DELTA >> b) & 1}')

x0, y0, z0 = LEVER_LINE
for n in range(160):
    x = x0 - n
    mc.append(
        f'execute store success score {lever(n)} {OBJECTIVE} '
        f'run execute if block {x} {y0} {z0} minecraft:lever[powered=true]'
    )


def XOR(dst: str, a: str, b: str) -> None:
    mc.append(f'scoreboard players operation {dst} {OBJECTIVE} = {a} {OBJECTIVE}')
    mc.append(f'scoreboard players operation {dst} {OBJECTIVE} += {b} {OBJECTIVE}')
    mc.append(f'scoreboard players operation {dst} {OBJECTIVE} %= {TWO} {OBJECTIVE}')


def COPY(dst: str, src: str) -> None:
    mc.append(f'scoreboard players operation {dst} {OBJECTIVE} = {src} {OBJECTIVE}')


def HALF(sumB: str, carB: str, a: str, b: str) -> None:
    t0, t1, t2 = '$' + mangle(f't0_{sumB}'), '$' + mangle(f't1_{sumB}'), '$' + mangle(f't2_{sumB}')
    XOR(t0, a, b)
    COPY(t1, a)
    mc.append(f'scoreboard players operation {t1} {OBJECTIVE} *= {b} {OBJECTIVE}')
    XOR(sumB, t0, carB)
    COPY(t2, carB)
    mc.append(f'scoreboard players operation {t2} {OBJECTIVE} *= {t0} {OBJECTIVE}')
    COPY(carB, t1)
    mc.append(f'scoreboard players operation {carB} {OBJECTIVE} += {t2} {OBJECTIVE}')
    mc.append(f'scoreboard players operation {carB} {OBJECTIVE} %= {TWO} {OBJECTIVE}')


def ADD32(dst: str, a: str, b: str) -> None:
    mc.append(f'scoreboard players set {C} {OBJECTIVE} 0')
    for i in range(BITS):
        HALF(t(dst, i), C, t(a, i), t(b, i))


def SHL4(out: str, inp: str) -> None:
    for b in range(BITS):
        src = b - 4
        COPY(t(out, b), t(inp, src) if src >= 0 else ZERO)


def SHR5(out: str, inp: str) -> None:
    for b in range(BITS):
        src = b + 5
        COPY(t(out, b), t(inp, src) if src < BITS else ZERO)


def SELECT_KEY(target_prefix: str, a_bit: str, b_bit: str) -> None:
    for kw in range(4):
        for bit in range(BITS):
            mc.append(
                f'execute if score {a_bit} {OBJECTIVE} matches {(kw >> 0) & 1}'
                f' if score {b_bit} {OBJECTIVE} matches {(kw >> 1) & 1} '
                f'run scoreboard players operation {t(target_prefix, bit)} {OBJECTIVE} = '
                f'{k(kw, bit)} {OBJECTIVE}'
            )


for kw, word in enumerate(KEY_WORDS):
    for bit in range(BITS):
        mc.append(f'scoreboard players set {k(kw, bit)} {OBJECTIVE} {(word >> bit) & 1}')

for blk, word in enumerate(CIPHER_WORDS):
    for bit in range(BITS):
        mc.append(f'scoreboard players set {c(blk, bit)} {OBJECTIVE} {(word >> bit) & 1}')

for chunk, start in enumerate((0, 64)):
    for b in range(BITS):
        mc.append(f'scoreboard players set {t("v0",  b)} {OBJECTIVE} 0')
        mc.append(f'scoreboard players set {t("v1",  b)} {OBJECTIVE} 0')
        mc.append(f'scoreboard players set {s(b)} {OBJECTIVE} 0')

    for i in range(BITS):
        COPY(t("v0", i), lever(start + i))
        COPY(t("v1", i), lever(start + BITS + i))

    for _ in range(ROUNDS):
        ADD32('sum', 'sum', 'delta')

        COPY('$i0', s(0))
        COPY('$i1', s(1))
        SELECT_KEY('kSel', '$i0', '$i1')

        SHL4('tmpA', 'v1')
        SHR5('tmpB', 'v1')
        for b in range(BITS):
            XOR(t('tmpT', b), t('tmpA', b), t('tmpB', b))
        ADD32('tmpT', 'tmpT', 'v1')
        for b in range(BITS):
            XOR(t('tmpT', b), t('tmpT', b), t('kSel', b))
        ADD32('v0', 'v0', 'tmpT')

        COPY('$j0', s(11))
        COPY('$j1', s(12))
        SELECT_KEY('kSel2', '$j0', '$j1')

        SHL4('tmpC', 'v0')
        SHR5('tmpD', 'v0')
        for b in range(BITS):
            XOR(t('tmpU', b), t('tmpC', b), t('tmpD', b))
        ADD32('tmpU', 'tmpU', 'v0')
        for b in range(BITS):
            XOR(t('tmpU', b), t('tmpU', b), t('kSel2', b))
        ADD32('v1', 'v1', 'tmpU')

    mc.append(f'scoreboard players set {OK} {OBJECTIVE} 1')
    for b in range(BITS):
        mc.append(
            f'execute unless score {t("v0", b)} {OBJECTIVE} = {c(chunk*2,   b)} {OBJECTIVE} '
            f'run scoreboard players set {OK} {OBJECTIVE} 0'
        )
        mc.append(
            f'execute unless score {t("v1", b)} {OBJECTIVE} = {c(chunk*2+1, b)} {OBJECTIVE} '
            f'run scoreboard players set {OK} {OBJECTIVE} 0'
        )
    mc.append(
        f'execute unless score {OK} {OBJECTIVE} matches 1 '
        f'run tellraw @a {{"text":"incorrect","color":"red"}}'
    )
    mc.append(
        f'execute unless score {OK} {OBJECTIVE} matches 1 run return 0'
    )

mc += [
    'tellraw @a {"text":"looks good!","color":"green"}',
    'return 0'
]
print('\n'.join(mc))
