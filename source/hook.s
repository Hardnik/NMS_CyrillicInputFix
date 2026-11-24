.intel_syntax noprefix
.text
.globl probe
probe:
    sub rax,r10
    pushfq
    push rdx
    push r8
    push r9
dispatch:
    cmp rax,r15
    je ascii
    cmp rax,2
    jne skip
    cmp byte ptr [r10],0xd0
    je tail
    cmp byte ptr [r10],0xd1
    jne skip
tail:
    movzx edx,byte ptr [r10+1]
    and edx,0xc0
    cmp edx,0x80
    jne skip
    # Ограничение буфера редактора: 512 байт, включая NUL.
    mov ecx,[rdi+0xafc]
    cmp ecx,2
    jb skip
    cmp ecx,509
    jbe bounded
    mov ecx,509
bounded:
    sub ecx,2
    xor edx,edx
scan:
    cmp byte ptr [rsi+rdx+8],0
    je insert
    inc edx
    cmp edx,ecx
    jbe scan
    jmp skip
insert:
    # Сохраняем указатели и выделяем shadow space.
    sub rsp,0x40
    mov [rsp+0x20],r10
    mov [rsp+0x28],r11
    mov [rsp+0x30],r9
    mov rcx,rsi
    mov rdx,r10
    mov r8d,2
    call qword ptr [rip+insert_text]
    mov r10,[rsp+0x20]
    mov r11,[rsp+0x28]
    mov r9,[rsp+0x30]
    add rsp,0x40
skip:
restore_skip:
    pop r9
    pop r8
    pop rdx
    popfq
    jmp qword ptr [rip+resume_no]
ascii:
restore_ascii:
    pop r9
    pop r8
    pop rdx
    popfq
    cmp rax,r15
    movsx edx,byte ptr [r10]
    mov rcx,rsi
    jmp qword ptr [rip+resume_yes]
