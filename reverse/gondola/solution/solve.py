from z3 import *


rotl_i64 = RotateLeft
rotr_i64 = RotateRight
band_i64 = lambda a, b: a & b
bor_i64 = lambda a, b: a | b
bxor_i64 = lambda a, b: a ^ b
shl_i64 = lambda a, b: a << b
shr_u64 = shr_i64 = lambda a, b: LShR(a, b)


def solve_1() -> int:
    s = Solver()
    loc_3 = BitVec('loc_3', 64)
    st_loc_3 = loc_3

    loc_2 = BitVecVal(8623051682217526346, 64)
    loc_4 = band_i64(loc_3, 62)
    reg_1 = bxor_i64(loc_2, bxor_i64(rotl_i64(loc_2, (band_i64(shl_i64(-2841402449925361436, loc_4), 36) + 49)), rotl_i64(loc_2, 39)))
    loc_2 = bor_i64(loc_4, 1)
    loc_5 = (reg_1 + bxor_i64((rotr_i64(shr_u64(4759118972362874166, loc_4), loc_2) - loc_3), -3306012594466711124))
    loc_2 = rotl_i64((loc_5 + shl_i64(loc_5, bor_i64(band_i64((band_i64(shr_u64(4356822460271002287, loc_4), loc_3) + 28), 62), 1))), bor_i64(band_i64(rotl_i64(-3599654368322586570, loc_2), 14), 1))
    loc_2 = bxor_i64(loc_2, shl_i64(loc_2, bor_i64(band_i64(((shr_u64((loc_3 * 742925643253982954), 56) + loc_3) * 47), 62), 1)))
    loc_3 = bxor_i64(loc_2, bxor_i64(rotl_i64(loc_2, 57), rotr_i64(loc_2, bor_i64((shl_i64(-4774275202249070850, loc_4) * loc_3), 1))))
    
    s.add(loc_3 == 2962060988158503004)
    s.check()
    m = s.model()
    return m.eval(st_loc_3).as_long()


def solve_2() -> int:
    s = Solver()
    loc_3 = BitVec('loc_3', 64)
    s.add(loc_3 & 0xFFFFFFFF == loc_3)
    st_loc_3 = loc_3

    loc_5 = (BitVecVal(2909675122655966860, 64) * bor_i64((loc_3 * 180512385711709), 7380094324862376181))
    loc_4 = band_i64(loc_3, 62)
    loc_2 = bor_i64(loc_4, 1)
    loc_5 = bxor_i64(loc_5, shr_u64(loc_5, bor_i64(band_i64(rotr_i64((band_i64(shr_u64(1383475029465073410, loc_4), loc_3) - loc_3), loc_2), 62), 1)))
    loc_3 = bxor_i64(loc_5, bxor_i64(rotl_i64(loc_5, bor_i64(shr_u64(shl_i64((1003390 - loc_3), loc_2), 15), 1)), rotl_i64(loc_5, bor_i64(shr_u64(((loc_3 * -8341237817759413455) + 5858299301512691920), loc_2), 1))))
    loc_3 = bor_i64(bor_i64(bor_i64(shl_i64(loc_3, 56), shl_i64(band_i64(loc_3, 65280), 40)), bor_i64(shl_i64(band_i64(loc_3, 16711680), 24), shl_i64(band_i64(loc_3, 4278190080), 8))), bor_i64(bor_i64(band_i64(shr_u64(loc_3, 8), 4278190080), band_i64(shr_u64(loc_3, 24), 16711680)), bor_i64(band_i64(shr_u64(loc_3, 40), 65280), shr_u64(loc_3, 56)))) + band_i64((shl_i64(-6512376135701343602, loc_4) + 9021780107656055508), 4886913136624203210)
    
    s.add(loc_3 == -2369189822284661616)
    s.check()
    m = s.model()
    return m.eval(st_loc_3).as_long()


def solve_3() -> int:
    s = Solver()
    loc_3 = BitVec('loc_3', 64)
    s.add(loc_3 & 0xFFFFFFFF == loc_3)
    st_loc_3 = loc_3

    loc_4 = BitVecVal(6593455689784348711, 64)
    loc_2 = band_i64(loc_3, 62)
    loc_4 = (bxor_i64(loc_4, bxor_i64(rotr_i64(loc_4, bxor_i64(shl_i64(1150443877981745306, loc_2), 11)), rotr_i64(loc_4, bor_i64(bxor_i64((loc_3 * 52), loc_3), 1)))) * bor_i64(bxor_i64((shl_i64(-1314727533138742334, loc_2) + loc_3), -1), 1))
    loc_4 = bxor_i64(loc_4, bxor_i64(rotl_i64(loc_4, 53), rotl_i64(loc_4, bor_i64(shr_u64(((band_i64(loc_3, 81990) * 48316) + 15360), 11), 1))))
    loc_4 = bxor_i64(loc_4, bxor_i64(rotl_i64(loc_4, bor_i64((0 - band_i64(loc_3, 14)), 27)), rotl_i64(loc_4, bor_i64(shr_u64((shl_i64(shr_u64(6474080420971629382, loc_2), 11) + 1321443404618737664), 56), 1))))
    loc_4 = (loc_4 - shl_i64(loc_4, bor_i64(band_i64((bor_i64(shr_u64((loc_3 + 2229619457770), 37), 13) - loc_3), 62), 1)))
    loc_3 = bxor_i64(loc_4, bxor_i64(rotr_i64(loc_4, bor_i64((band_i64((rotr_i64(499867118132017422, bor_i64(loc_3, 1)) - loc_3), loc_3) - loc_3), 1)), rotl_i64(loc_4, 63)))
    
    s.add(loc_3 == -6199318870751610502)
    s.check()
    m = s.model()
    return m.eval(st_loc_3).as_long()


def solve_4() -> str:
    return 'sm_1'
    s = Solver()
    loc_3 = BitVec('loc_3', 64)
    s.add(loc_3 & 0xFFFFFFFF == loc_3)
    st_loc_3 = loc_3

    loc_2 = band_i64(loc_3, 62)
    loc_5 = bor_i64(loc_2, 1)
    loc_6 = bxor_i64((rotl_i64(BitVecVal(9065908643065656256, 64), bor_i64(rotr_i64(rotl_i64(-3680473152504818101, loc_5), loc_5), 1)) + rotl_i64(bxor_i64(band_i64((3259888993861259150 - loc_3), loc_3), -1), 49)), rotl_i64(shr_u64(bor_i64(loc_3, 323389404160168651), loc_5), loc_5))
    loc_4 = shr_u64(4824063971456177356, loc_2)
    loc_4 = bxor_i64(loc_6, shr_u64(loc_6, bor_i64(band_i64(shr_u64(bor_i64(bor_i64(bor_i64(shl_i64(loc_4, 56), shl_i64(band_i64(loc_4, 65280), 40)), bor_i64(shl_i64(band_i64(loc_4, 16711680), 24), shl_i64(band_i64(loc_4, 4278190080), 8))), bor_i64(bor_i64(band_i64(shr_u64(loc_4, 8), 4278190080), band_i64(shr_u64(loc_4, 24), 16711680)), bor_i64(band_i64(shr_u64(loc_4, 40), 65280), shr_u64(loc_4, 56)))), 45), 62), 1)))
    loc_4 = bxor_i64(loc_4, bxor_i64(rotr_i64(loc_4, bor_i64(shr_u64(shl_i64(-7575533352951092208, loc_2), 56), 1)), rotl_i64(loc_4, bor_i64(shr_u64((loc_3 + 565), 5), 1))))
    loc_4 = bxor_i64(loc_4, shl_i64(loc_4, bor_i64(band_i64(loc_3, 46), 17)))
    loc_4 = (loc_4 + shl_i64(loc_4, bor_i64(band_i64((loc_3 * bxor_i64(shl_i64(-5156880989505199132, loc_2), -1)), 62), 1)))
    loc_3 = (loc_4 - shl_i64(loc_4, bor_i64(band_i64(shl_i64((shr_u64(5172634985249747992, loc_2) - loc_3), loc_5), 62), 1)))

    s.add(loc_3 == -7933734027473357990)
    res = []
    while s.check() == sat:
        m = s.model()
        vv = m.eval(st_loc_3).as_long()
        s.add(st_loc_3 != vv)
        try:
            vv = vv.to_bytes(4, 'little').decode()
            if not any(ord(c) >= 30 and ord(c) < 127 for c in vv):
                continue
            if vv[0] != 's' or vv[1] != 'm' or vv[2] != '_':
                continue
            res.append(vv)
        except UnicodeDecodeError:
            continue
        
    return res


def solve_5() -> int:
    s = Solver()
    loc_3 = BitVec('loc_3', 64)
    s.add(loc_3 & 0xFFFFFFFF == loc_3)
    st_loc_3 = loc_3

    loc_3 = BitVecVal(-1356631033178458273, 64)
    reg_1 = bor_i64(bor_i64(bor_i64(shl_i64(loc_3, 56), shl_i64(band_i64(loc_3, 65280), 40)), bor_i64(shl_i64(band_i64(loc_3, 16711680), 24), shl_i64(band_i64(loc_3, 4278190080), 8))), bor_i64(bor_i64(band_i64(shr_u64(loc_3, 8), 4278190080), band_i64(shr_u64(loc_3, 24), 16711680)), bor_i64(band_i64(shr_u64(loc_3, 40), 65280), shr_u64(loc_3, 56))))
    loc_3 = st_loc_3
    reg_1 = bxor_i64(rotl_i64(reg_1, bor_i64((bor_i64(shr_u64((loc_3 + 3740270535386903565), 56), 23) * loc_3), 1)), -4619238845427684646)
    loc_3 = bxor_i64((loc_3 + -4616715144965187269), -8569173798327520083)
    loc_3 = (reg_1 + bor_i64(bor_i64(bor_i64(shl_i64(loc_3, 56), shl_i64(band_i64(loc_3, 65280), 40)), bor_i64(shl_i64(band_i64(loc_3, 16711680), 24), shl_i64(band_i64(loc_3, 4278190080), 8))), bor_i64(bor_i64(band_i64(shr_u64(loc_3, 8), 4278190080), band_i64(shr_u64(loc_3, 24), 16711680)), bor_i64(band_i64(shr_u64(loc_3, 40), 65280), shr_u64(loc_3, 56)))))
    loc_3 = bxor_i64(loc_3, shl_i64(loc_3, 39))
    
    s.add(loc_3 == -764000949120238475)
    s.check()
    m = s.model()
    return m.eval(st_loc_3).as_long()


def solve_6() -> int:
    s = Solver()
    loc_3 = BitVec('loc_3', 64)
    s.add(loc_3 & 0xFFFFFFFF == loc_3)
    st_loc_3 = loc_3

    loc_4 = (BitVecVal(-2851629582878154216, 64) + bxor_i64(loc_3, 36051668767407190))
    loc_2 = band_i64(loc_3, 62)
    reg_1 = (loc_4 + shl_i64(loc_4, bor_i64(band_i64(((band_i64(loc_3, 8) * loc_3) + 26), 58), 1)))
    loc_4 = bor_i64(loc_2, 1)
    loc_5 = (reg_1 - bor_i64(rotl_i64(rotr_i64(-7384894205260299553, loc_4), loc_4), -2299178146027875472))
    loc_3 = bxor_i64(bxor_i64(loc_5, shl_i64(loc_5, bor_i64(band_i64((shl_i64(shr_i64(-4331792876883399301, loc_2), loc_4) + loc_3), 62), 1))), 5185608289172264064)
    
    s.add(loc_3 == -8197181009963186243)
    s.check()
    m = s.model()
    return m.eval(st_loc_3).as_long()


def solve_7() -> int:
    s = Solver()
    loc_3 = BitVec('loc_3', 64)
    s.add(loc_3 & 0xFFFFFFFF == loc_3)
    st_loc_3 = loc_3

    loc_2 = band_i64(loc_3, 62)
    loc_4 = bor_i64(loc_2, 1)
    loc_4 = ((BitVecVal(6819041451075660244, 64) * -511) + band_i64(rotr_i64(shr_u64(bor_i64(loc_3, -5056680446052056208), loc_4), loc_4), -7361207612496853418))
    loc_4 = bxor_i64(bxor_i64(loc_4, bxor_i64(rotl_i64(loc_4, bor_i64((bxor_i64((loc_3 + 22), 30) - loc_3), 1)), rotr_i64(loc_4, bxor_i64(band_i64(band_i64((loc_3 + 40), loc_3), 62), 13)))), -1)
    loc_3 = (((loc_4 - shl_i64(loc_4, bor_i64(band_i64(bor_i64(shr_u64(2315141858787142786, loc_2), loc_3), 62), 1))) + ((-6610288770926234540 - loc_3) * 3123491549520060319)) * 8796093022209)

    s.add(loc_3 == -5461962825392448732)
    s.check()
    m = s.model()
    return m.eval(st_loc_3).as_long()


def solve_8() -> int:
    s = Solver()
    loc_3 = BitVec('loc_3', 64)
    s.add(loc_3 & 0xFFFFFFFF == loc_3)
    st_loc_3 = loc_3

    loc_16 = band_i64(loc_3, 62)
    loc_17 = bor_i64(loc_16, 1)
    loc_17 = (BitVecVal(-2754993476178209139, 64) + band_i64(rotr_i64(shr_u64(bor_i64(loc_3, -5056680446052056208), loc_17), loc_17), -7361207612496853418))
    loc_17 = bxor_i64(bxor_i64(rotr_i64(loc_17, bxor_i64(band_i64(loc_16, (loc_3 + 40)), 13)), rotl_i64(loc_17, bor_i64((bxor_i64((loc_3 + 22), 30) - loc_3), 1))), loc_17)
    loc_3 = (((((-6610288770926234540 - loc_3) * 3123491549520060319) + bxor_i64(loc_17, -1)) + shl_i64((loc_17 + 1), bor_i64(band_i64(bor_i64(shr_u64(2315141858787142786, loc_16), loc_3), 62), 1))) * 8796093022209)

    s.add(loc_3 == 0xd569cc8badd8c4eb)
    s.check()
    m = s.model()
    return m.eval(st_loc_3).as_long()


flag = ''
for i, x in enumerate([
    solve_1,
    solve_2,
    solve_3,
    solve_4,
    solve_5,
    solve_6,
    solve_7,
    solve_8,
]):
    print('solving for', i + 1)
    r = x()
    if isinstance(r, int):
        flag += r.to_bytes(4, 'little').replace(b'\x00', b'?').decode()
    elif isinstance(r, list):
        flag += str(r).replace(' ', '')
    elif isinstance(r, str):
        flag += r
    else:
        raise ValueError

flag += 'A' * (32 - len(flag))
print(flag)
