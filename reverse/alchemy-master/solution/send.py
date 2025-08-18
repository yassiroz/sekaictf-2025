from pwn import *
from pathlib import Path


sol = (Path(__file__).parent / 'solution_final.cpp').read_text()

io = remote('alchemy-master.chals.sekai.team', 1337, ssl=True)
io.send((sol + '\n').encode())
io.sendline(b'__END__')

io.recvuntil(b'flag: ')
print('flag:', io.recvuntil(b'}').decode())
io.close()
