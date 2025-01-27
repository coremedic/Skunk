.x64
.model flat, fastcall
option casemap:none
option win64:1

; Export procedures
public ProxyCaller

_TEXT$B segment

ProxyCaller:
    jmp rdx ; Probably can find a more legit gadget for this lmfao

_TEXT$B ends

end
