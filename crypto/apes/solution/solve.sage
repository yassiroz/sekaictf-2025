from pwn import *
from tqdm import trange

F = GF(256)
PF = ProjectiveSpace(1,F)
plainperm = bytes((F.from_integer(i)^254).to_integer() for i in range(256))

io = process(['python', 'apes.py'])

# this solve script does the simplest thing of expecting a single cycle of length 64.
# this only happens roughly once every 5549 keys. so we retry until we get a good one.
# there exist better solutions, e.g. 1 in 60, but the solve script is longer so mehh...
for _ in trange(20_000):
    io.sendline(plainperm.hex().encode())
    cipherperm = bytes.fromhex(io.readline_contains(b'perm').split()[-1].decode())
    
    ab = [(F.from_integer(i), F.from_integer(j)) for i, j in enumerate(cipherperm)]
    M = matrix([a,1,a*b,b] for a,b in ab)
    
    while True:
        v = matrix(sample(M.rows(), 3)).right_kernel_matrix()[0]
        cnt = list(M * v).count(0)
        if cnt > 100:
            break

    if cnt == 193:
        print("Found a suitable key!")
        break
    io.sendline()
else:
    raise('Either something went wrong, or just unlucky, try again.')

M = matrix(2,2,v)
M = sqrt(det(M)) / M

def ind(n):
    return n[0].to_integer()+1 if n[1] else 257

perm = Permutation([ind(M * PF(F.from_integer(i))) for i in cipherperm] + [ind(M * PF(1,0))]).inverse()
arr = next([x-1 for x in t] for t in perm.cycle_tuples() if len(t)>1)
arr = (arr * 2)[arr.index(256)+1:arr.index(256)+len(arr)]
print(f'{arr = }')

soln = arr[:]
for i in range(len(soln)):
    for j in range(i+1, len(soln)):
        soln[j] = plainperm[soln[i]^^soln[j]]
soln.append(cipherperm[arr[-1]])
print(f'{soln = }')

io.sendline(bytes(soln).hex().encode())
print(io.readall())