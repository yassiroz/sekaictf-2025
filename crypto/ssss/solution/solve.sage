import os
os.environ['TERM'] = 'linux'

from pwn import *
# context.log_level="debug"

p = 2 ** 256 - 189
R.<x0> = GF(p)[]

t = 29

# conn = process(["python3", "../dist/chall.py"])
conn = remote('ssss.chals.sekai.team', 1337, ssl=True)

def query():
	conn.sendline(str(t).encode())
	g = 2
	while pow(g, (p-1)//t, p) == 1:
		g += 1

	g = pow(g, (p-1)//t, p)
	assert pow(g, t, p) == 1

	shares = []
	for i in range(t):
		x = pow(g, i, p)
		conn.sendline(str(x).encode())
		y = int(conn.recvline())
		shares.append((x, y))

	return list(R.lagrange_polynomial(shares))

A = query()
conn.sendline(b"1")
conn.recvline()  # :<

B = query()

for secret in A:
	if secret in B:
		conn.sendline(str(secret).encode())
		print(conn.recvline().decode().strip())