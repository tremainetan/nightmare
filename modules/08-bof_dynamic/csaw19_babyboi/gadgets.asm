Gadgets information
============================================================
0x00000000004005fe : adc byte ptr [rax], ah ; jmp rax
0x00000000004005fd : adc byte ptr [rax], spl ; jmp rax
0x00000000004005c9 : add ah, dh ; nop dword ptr [rax + rax] ; repz ret
0x0000000000400587 : add al, byte ptr [rax] ; add byte ptr [rax], al ; jmp 0x400550
0x00000000004005cf : add bl, dh ; ret
0x000000000040079d : add byte ptr [rax], al ; add bl, dh ; ret
0x000000000040079b : add byte ptr [rax], al ; add byte ptr [rax], al ; add bl, dh ; ret
0x0000000000400567 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x400550
0x0000000000400729 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x000000000040067c : add byte ptr [rax], al ; add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400610
0x000000000040079c : add byte ptr [rax], al ; add byte ptr [rax], al ; repz ret
0x000000000040067d : add byte ptr [rax], al ; add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x400610
0x000000000040027d : add byte ptr [rax], al ; add byte ptr [rdi + 0x4e], al ; push rbp ; add cl, ah ; call qword ptr [rbp - 0x24]
0x000000000040072a : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000400569 : add byte ptr [rax], al ; jmp 0x400550
0x000000000040072b : add byte ptr [rax], al ; leave ; ret
0x0000000000400606 : add byte ptr [rax], al ; pop rbp ; ret
0x000000000040027e : add byte ptr [rax], al ; push rbp ; add cl, ah ; call qword ptr [rbp - 0x24]
0x000000000040067e : add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400610
0x00000000004005ce : add byte ptr [rax], al ; repz ret
0x0000000000400605 : add byte ptr [rax], r8b ; pop rbp ; ret
0x00000000004005cd : add byte ptr [rax], r8b ; repz ret
0x000000000040067f : add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x400610
0x0000000000400667 : add byte ptr [rcx], al ; pop rbp ; ret
0x000000000040027f : add byte ptr [rdi + 0x4e], al ; push rbp ; add cl, ah ; call qword ptr [rbp - 0x24]
0x0000000000400283 : add cl, ah ; call qword ptr [rbp - 0x24]
0x000000000040072c : add cl, cl ; ret
0x0000000000400577 : add dword ptr [rax], eax ; add byte ptr [rax], al ; jmp 0x400550
0x0000000000400668 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret
0x000000000040027c : add eax, dword ptr [rax] ; add byte ptr [rax], al ; push rbp ; add cl, ah ; call qword ptr [rbp - 0x24]
0x000000000040054b : add esp, 8 ; ret
0x000000000040054a : add rsp, 8 ; ret
0x00000000004005c8 : and byte ptr [rax], al ; hlt ; nop dword ptr [rax + rax] ; repz ret
0x0000000000400564 : and byte ptr [rax], al ; push 0 ; jmp 0x400550
0x0000000000400574 : and byte ptr [rax], al ; push 1 ; jmp 0x400550
0x0000000000400584 : and byte ptr [rax], al ; push 2 ; jmp 0x400550
0x0000000000400541 : and byte ptr [rax], al ; test rax, rax ; je 0x40054a ; call rax
0x0000000000400285 : call qword ptr [rbp - 0x24]
0x0000000000400548 : call rax
0x000000000040077c : fmul qword ptr [rax - 0x7d] ; ret
0x00000000004005ca : hlt ; nop dword ptr [rax + rax] ; repz ret
0x0000000000400683 : in eax, 0x5d ; jmp 0x400610
0x0000000000400546 : je 0x40054a ; call rax
0x00000000004005f9 : je 0x400608 ; pop rbp ; mov edi, 0x601040 ; jmp rax
0x000000000040063b : je 0x400648 ; pop rbp ; mov edi, 0x601040 ; jmp rax
0x000000000040056b : jmp 0x400550
0x0000000000400685 : jmp 0x400610
0x00000000004008d3 : jmp qword ptr [rbp]
0x0000000000400601 : jmp rax
0x000000000040072d : leave ; ret
0x0000000000400662 : mov byte ptr [rip + 0x2009ff], 1 ; pop rbp ; ret
0x000000000040053f : mov ch, 0xa ; and byte ptr [rax], al ; test rax, rax ; je 0x40054a ; call rax
0x0000000000400562 : mov dl, 0xa ; and byte ptr [rax], al ; push 0 ; jmp 0x400550
0x0000000000400728 : mov eax, 0 ; leave ; ret
0x0000000000400682 : mov ebp, esp ; pop rbp ; jmp 0x400610
0x00000000004005fc : mov edi, 0x601040 ; jmp rax
0x0000000000400681 : mov rbp, rsp ; pop rbp ; jmp 0x400610
0x0000000000400582 : movabs byte ptr [0x26800200a], al ; jmp 0x400550
0x0000000000400603 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x00000000004005cb : nop dword ptr [rax + rax] ; repz ret
0x0000000000400645 : nop dword ptr [rax] ; pop rbp ; ret
0x0000000000400665 : or dword ptr [rax], esp ; add byte ptr [rcx], al ; pop rbp ; ret
0x000000000040063c : or ebx, dword ptr [rbp - 0x41] ; adc byte ptr [rax], spl ; jmp rax
0x000000000040078c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040078e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400790 : pop r14 ; pop r15 ; ret
0x0000000000400792 : pop r15 ; ret
0x0000000000400684 : pop rbp ; jmp 0x400610
0x00000000004005fb : pop rbp ; mov edi, 0x601040 ; jmp rax
0x000000000040078b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040078f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400608 : pop rbp ; ret
0x0000000000400793 : pop rdi ; ret
0x0000000000400791 : pop rsi ; pop r15 ; ret
0x000000000040078d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400566 : push 0 ; jmp 0x400550
0x0000000000400576 : push 1 ; jmp 0x400550
0x0000000000400586 : push 2 ; jmp 0x400550
0x0000000000400282 : push rbp ; add cl, ah ; call qword ptr [rbp - 0x24]
0x0000000000400680 : push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400610
0x00000000004005d0 : repz ret
0x000000000040054e : ret
0x00000000004005f8 : sal byte ptr [rbp + rcx + 0x5d], 0xbf ; adc byte ptr [rax], spl ; jmp rax
0x000000000040063a : sal byte ptr [rbx + rcx + 0x5d], 0xbf ; adc byte ptr [rax], spl ; jmp rax
0x0000000000400545 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x00000000004007a5 : sub esp, 8 ; add rsp, 8 ; ret
0x00000000004007a4 : sub rsp, 8 ; add rsp, 8 ; ret
0x000000000040079a : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; repz ret
0x0000000000400544 : test eax, eax ; je 0x40054a ; call rax
0x0000000000400543 : test rax, rax ; je 0x40054a ; call rax

Unique gadgets found: 90
