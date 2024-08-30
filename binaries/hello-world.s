section .data
    string1 db "Hello World!", 0xa, 0

; Adapted from https://stackoverflow.com/a/27594733

section .text
bits 64
global _start
_start:
    ; write string to stdout
    mov     rdx, 14             ; length
    lea     rsi, [rel string1]  ; string1 to source index
    mov     rax, 1              ; set write to command
    mov     rdi,rax             ; set destination index to rax (stdout)
    syscall                     ; call kernel

    ; exit 
    xor     rdi,rdi             ; zero rdi (rdi hold return value)
    mov     rax, 0x3c           ; set syscall number to 60 (0x3c hex)
    syscall                     ; call kernel
    ret

%ifidn __OUTPUT_FORMAT__,elf
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf32
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf64
section .note.GNU-stack noalloc noexec nowrite progbits
%endif