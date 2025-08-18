from collections import defaultdict
from pathlib import Path

from pulp import (
    PULP_CBC_CMD,
    LpInteger,
    LpProblem,
    LpStatusOptimal,
    LpVariable,
    lpSum,
    value,
)
from sympy import Matrix

from config import AlchemyMaterialType, index, reactions, MSVCTupleKind

ROW2MAT = list(AlchemyMaterialType)
BASE = [
    AlchemyMaterialType.LEAD,
    AlchemyMaterialType.WATER,
    AlchemyMaterialType.SULFUR,
]
CALL_ID = next(i for i, (k, *_) in enumerate(reactions) if k is MSVCTupleKind.FunctionCallStmt)
THROW_ID = next(i for i, (k, *_) in enumerate(reactions) if k is MSVCTupleKind.ThrowStmt)

consumes = defaultdict(list)
produces = defaultdict(list)

for _r, (_, _ing_mask, _prod) in enumerate(reactions):
    for _m in AlchemyMaterialType:
        if _ing_mask & _m:
            consumes[_m].append(_r)
        if _prod == _m:
            produces[_m].append(_r)

A_raw = []
for _m in AlchemyMaterialType:
    _row = [0] * len(reactions)
    for _r in consumes[_m]:
        _row[_r] = -1
    for _r in produces[_m]:
        _row[_r] = 1
    A_raw.append(_row)
A = Matrix(A_raw)


def minimal_base(target: list[int]) -> dict[AlchemyMaterialType, int]:
    prob = LpProblem('reactions_count')

    r = LpVariable.dicts('r', range(len(reactions)), 0, None, LpInteger)
    s = {m: LpVariable(str(m), 0, None, LpInteger) for m in BASE}

    for i, row in enumerate(A.tolist()):
        mat = ROW2MAT[i]
        lhs = lpSum(row[j] * r[j] for j in range(len(reactions)))
        if mat in BASE:
            lhs += s[mat]
        prob += lhs == target[i]

    assert prob.solve(PULP_CBC_CMD(msg=False)) == LpStatusOptimal
    return {m: int(value(s[m])) for m in BASE}


def reaction_counts(target: list[int], start: list[int]) -> list[int]:
    b = Matrix([[t - s] for t, s in zip(target, start, strict=False)])
    prob = LpProblem('reactions')
    x = LpVariable.dicts('r', range(len(reactions)), 0, None, LpInteger)

    for i, row in enumerate(A.tolist()):
        prob += lpSum(row[j] * x[j] for j in range(len(reactions))) == b[i]

    for inv in A.nullspace():
        coeffs = list(map(int, inv))
        prob += lpSum(coeffs[i] * x[i] for i in range(len(reactions))) == 0

    prob += x[THROW_ID] == x[CALL_ID]

    assert prob.solve(PULP_CBC_CMD(msg=False)) == LpStatusOptimal
    return [int(value(x[j])) for j in range(len(reactions))]


def realize(counts: list[int], start: list[int]) -> list[int]:
    pending = counts[:]
    stock = start[:]
    seq = []

    ing_mask = [r[1] for r in reactions]
    prod = [r[2] for r in reactions]

    def ready(r: int) -> bool:
        bits = int(ing_mask[r])
        return all((not (bits & (1 << k))) or stock[k] > 0
                   for k in range(len(AlchemyMaterialType)))

    def execute(r: int) -> None:
        bits = int(ing_mask[r])
        for k in range(len(AlchemyMaterialType)):
            if bits & (1 << k):
                stock[k] -= 1
        stock[index(prod[r])] += 1
        pending[r] -= 1
        seq.append(r)

    need_throw = False

    while any(pending):
        if need_throw:
            if pending[THROW_ID] and ready(THROW_ID):
                execute(THROW_ID)
                need_throw = False
                continue
            raise RuntimeError('dead-lock: throw required, but not ready')

        for r, left in enumerate(pending):
            if not left or r == THROW_ID or not ready(r):
                continue
            execute(r)
            if r == CALL_ID:
                need_throw = True
            break
        else:
            raise RuntimeError('dead-lock: nothing ready')

    return seq


# def check_target_reachable(target: list[int]):
#     init = [1955,0,0,0,2995,0,3871]
#     invariants = A.nullspace()
#     diff = Matrix(target) - Matrix(init)
#     for v in invariants:
#         if int(v.dot(diff)) != 0:
#             raise ValueError("target violates conservation laws")


def main() -> None:
    target = [522, 727, 353, 727, 482, 706, 1337]
    assert len(target) == len(AlchemyMaterialType)
    # check_target_reachable(target)
    base = minimal_base(target)
    print('minimal base supply:', {k.name: v for k,v in base.items()})

    start = [0] * len(AlchemyMaterialType)
    for m, n in base.items():
        start[index(m)] = n

    counts = reaction_counts(target, start)
    print('counts:', counts)
    sequence = realize(counts, start)
    print(f'sequence length: {len(sequence)}')

    converter = [
        ((MSVCTupleKind.SimpleStmt,), 'int v%pos% = 0;'),
        (
            (
                MSVCTupleKind.FunctionCallStmt,
                MSVCTupleKind.ThrowStmt,
            ),
            'throw;',
        ),
        ((MSVCTupleKind.FunctionCallStmt,), 'reinterpret_cast<void(*)()>(0)();'),
        ((MSVCTupleKind.ReturnStmt,), 'return 0;'),
    ]

    codegen = ''

    pos = 0
    while pos < len(sequence):
        rest = [reactions[i][0] for i in sequence[pos:]]

        for kinds, code in converter:
            if not all((r == rest[i] for i, r in enumerate(kinds))):
                continue
            codegen += (' ' * 4) + code.replace('%pos%', str(pos)) + '\n'
            pos += len(kinds)
            break
        else:
            raise ValueError(f'Unknown reaction sequence at position {pos}: {rest[:5]} (truncated)')

    (Path(__file__).parent.parent / 'solution.cpp').write_text(f'int solution() {{\n{codegen}}}\n')
    print('generated solution.cpp')


if __name__ == '__main__':
    main()
