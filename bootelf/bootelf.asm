BITS 16

org     0x08048000

ehdr:                                                 ; Elf32_Ehdr
              ; Fun fact, on x86 the ELF header is a jump into the
              ; 4th byte of p_filesz. We can use this to chain into
              ; another jump into our actual bootloader
              db      0x7F, "ELF", 1, 1, 1, 0         ;   e_ident
      times 8 db      0
              dw      2                               ;   e_type
              dw      3                               ;   e_machine
              dd      1                               ;   e_version
              dd      _start                          ;   e_entry
              dd      phdr - $$                       ;   e_phoff
              dd      0                               ;   e_shoff
              dd      0                               ;   e_flags
              dw      ehdrsize                        ;   e_ehsize
              dw      phdrsize                        ;   e_phentsize
              dw      1                               ;   e_phnum
              dw      0                               ;   e_shentsize
              dw      0                               ;   e_shnum
              dw      0                               ;   e_shstrndx

ehdrsize      equ     $ - ehdr

phdr:                                                 ; Elf32_Phdr
              dd      1                               ;   p_type
              dd      0                               ;   p_offset
              dd      $$                              ;   p_vaddr
              dd      $$                              ;   p_paddr
              ; We're gonna fix up the file sizes here so that 0x47 is
              ; a jmp instruction to the start of the bootloader
              ; This is totally fine as long as p_memsz >= p_filesz
              ; Note: the jump is to (boot-$) and needs to be fixed up as follows:
              ;   -3  since the jmp instruction begins 3 bytes forward
              ;   -2  for the length of the jmp instruction and operand
              db      (boot - $ - 5), 0x00, 0x00, 0xeb          ;   p_filesz
              ; p_memsz needs to be adjusted since `boot` is 4 bytes closer to here
              ; than to p_filesz
              db      (boot - $ - 5 + 4), 0x00, 0x00, 0xeb          ;   p_memsz
              dd      5                               ;   p_flags
              dd      0x1000                          ;   p_align

phdrsize      equ     $ - phdr

bits 16 ; tell NASM this is 16 bit code
bootbase equ 0x7c00

boot:
  mov si, (bootbase + msg - $$)   ; Move  'msg' into si to prepare for the BIOS interrupt call
                                  ; Note: we need do some address fixing here since mov needs
                                  ; an absolute address
  mov ah, 0x0e ; BIOS interrupt call to write character

.loop:
  lodsb    ; load a byte from *si into al and increment si
  or al,al ; is al == 0?
  jz halt  ; if al == 0, jump to halt
  int 0x10 ; runs the bios interrupt 0x10 - Video services. Reads action form ah and arg from al
  jmp .loop

halt:
  cli ; clear interrupt flag
  hlt ; halt execution

msg: db 'This bootloader is also an ELF executable!', 0

times 510 - ($ - $$) db 0; pad remaining bytes with zeroes
dw 0xaa55 ; bootloader magic

bits 32

_start:
              mov     eax, 4      ; syscall write
              mov     ebx, 1      ; stdout
              mov     ecx, emsg   ; message pointer
              mov     edx, mlen   ; message length
              int     0x80

              mov     ebx, 42      ; return code
              mov     eax, 1      ; exit
              int     0x80

emsg:         db      'This ELF executable is also a bootloader!', 0xa
mlen:         equ     $ - emsg

filesize      equ     $ - $$
