; This file is both a valid x86 bootloader and a valid x86 windows executable

; Build with `nasm -f bin -o bootpe.exe bootpe.asm`
; Boot with  `qemu-system-x86_64 -fda bootelf.out -curses` or your preferred alternative

; Thanks to two wonderful neighbors who have taken the time to write about their adventures in the
; land of x86:

; Thanks to Alexander Sotirov at [http://www.phreedom.org/research/tinype/] for his excellent
; walkthrough of creating a tiny PE file. I've borrowed one of the steps here to create a small but
; valid windows executable as a starting point

; Thanks also to Alex Parker at [http://3zanders.co.uk/2017/10/13/writing-a-bootloader] for teaching
; me about bootloaders, which started this whole insanity in the first place. I've borrowed some of
; his code as well

bits 16
imagebase equ 0x400000

;
; MZ header
;
; The only two fields that matter are e_magic and e_lfanew

mzhdr:
    dw "MZ"                       ; e_magic - equals dec %ebp, pop %ebx, which we can ignore
    jmp boot                      ; e_cblp UNUSED - jump into the bootloader
    dw 0                          ; e_cp UNUSED
    dw 0                          ; e_crlc UNUSED
    dw 0                          ; e_cparhdr UNUSED
    dw 0                          ; e_minalloc UNUSED
    dw 0                          ; e_maxalloc UNUSED
    dw 0                          ; e_ss UNUSED
    dw 0                          ; e_sp UNUSED
    dw 0                          ; e_csum UNUSED
    dw 0                          ; e_ip UNUSED
    dw 0                          ; e_cs UNUSED
    dw 0                          ; e_lsarlc UNUSED
    dw 0                          ; e_ovno UNUSED
    times 4 dw 0                  ; e_res UNUSED
    dw 0                          ; e_oemid UNUSED
    dw 0                          ; e_oeminfo UNUSED
    times 10 dw 0                 ; e_res2 UNUSED
    dd pesig                      ; e_lfanew

bootbase equ 0x7c00

boot:
  mov si, (bootbase + msg - $$)   ; Move  'msg' into si to prepare for the BIOS interrupt call
                                  ; Note: we need do some address fixing here since mov needs
                                  ; an absolute address:w
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

msg: db "This bootloader is also a windows executable!", 0

times 510 - ($ - $$) db 0; pad remaining bytes with zeroes
dw 0xaa55 ; bootloader magic

; Now we resume the windows executable

bits 32

;
; PE signature
;

pesig:
    dd "PE"

;
; PE header
;

pehdr:
    dw 0x014C                     ; Machine (Intel 386)
    dw 1                          ; NumberOfSections
    dd 0                          ; TimeDateStamp UNUSED
    dd 0                          ; PointerToSymbolTable UNUSED
    dd 0                          ; NumberOfSymbols UNUSED
    dw opthdrsize                 ; SizeOfOptionalHeader
    dw 0x103                      ; Characteristics (no relocations, executable, 32 bit)

;
; PE optional header
;

%define round(n, r) (((n+(r-1))/r)*r)

filealign equ 1
secalign equ 1

opthdr:

    dw 0x10B                      ; Magic (PE32)
    db 8                          ; MajorLinkerVersion UNUSED
    db 0                          ; MinorLinkerVersion UNUSED
    dd round(codesize, filealign) ; SizeOfCode UNUSED
    dd 0                          ; SizeOfInitializedData UNUSED
    dd 0                          ; SizeOfUninitializedData UNUSED
    dd start                      ; AddressOfEntryPoint
    dd code                       ; BaseOfCode UNUSED
    dd round(filesize, secalign)  ; BaseOfData UNUSED
    dd imagebase                  ; ImageBase
    dd 1                          ; SectionAlignment
    dd filealign                  ; FileAlignment
    dw 4                          ; MajorOperatingSystemVersion UNUSED
    dw 0                          ; MinorOperatingSystemVersion UNUSED
    dw 0                          ; MajorImageVersion UNUSED
    dw 0                          ; MinorImageVersion UNUSED
    dw 4                          ; MajorSubsystemVersion
    dw 0                          ; MinorSubsystemVersion UNUSED
    dd 0                          ; Win32VersionValue UNUSED
    dd round(filesize, secalign)  ; SizeOfImage
    dd round(hdrsize, filealign)  ; SizeOfHeaders
    dd 0                          ; CheckSum UNUSED
    dw 2                          ; Subsystem (Win32 GUI)
    dw 0x400                      ; DllCharacteristics UNUSED
    dd 0x100000                   ; SizeOfStackReserve UNUSED
    dd 0x1000                     ; SizeOfStackCommit
    dd 0x100000                   ; SizeOfHeapReserve
    dd 0x1000                     ; SizeOfHeapCommit UNUSED
    dd 0                          ; LoaderFlags UNUSED
    dd 16                         ; NumberOfRvaAndSizes (always 16 afaik)

;
; Data directories
;

    dd 0, 0                       ; export table UNUSED

    dd idata                      ; Import Table
    dd idatasize

    times 14 dd 0, 0              ; other tables

opthdrsize equ $ - opthdr

;
; PE import section
;

    db ".idata", 0, 0             ; Name
    dd idsecsize                  ; VirtualSize
    dd round(hdrsize, secalign)   ; VirtualAddress
    dd round(idsecsize, filealign); SizeOfRawData
    dd idsection                  ; PointerToRawData
    dd 0                          ; PointerToRelocations UNUSED
    dd 0                          ; PointerToLinenumbers UNUSED
    dw 0                          ; NumberOfRelocations UNUSED
    dw 0                          ; NumberOfLinenumbers UNUSED
    dd 0xc0000000                 ; Characteristics (read, write)

;
; PE code section
;

    db ".text", 0, 0, 0           ; Name
    dd codesize                   ; VirtualSize
    dd round(hdrsize, secalign)   ; VirtualAddress
    dd round(codesize, filealign) ; SizeOfRawData
    dd code                       ; PointerToRawData
    dd 0                          ; PointerToRelocations UNUSED
    dd 0                          ; PointerToLinenumbers UNUSED
    dw 0                          ; NumberOfRelocations UNUSED
    dw 0                          ; NumberOfLinenumbers UNUSED
    dd 0x60000020                 ; Characteristics (read, execute, code)

hdrsize equ $ - $$

;
; PE import section data
;

align filealign, db 0

idsection:

idata:

; Import table (array of IMAGE_IMPORT_DESCRIPTOR structures)
    dd ilt                                    ; ILT
    dd 0                                      ; TimeDateStamp UNUSED
    dd 0                                      ; ForwarderChain UNUSED
    dd dllname                                ; Name
    dd iat                                    ; IAT

    ; empty IMAGE_IMPORT_DESCRIPTOR structure

    dd 0                                      ; ILT UNUSED
    dd 0                                      ; TimeDateStamp UNUSED
    dd 0                                      ; ForwarderChain UNUSED
    dd 0                                      ; Name UNUSED
    dd 0                                      ; IAT UNUSED

idatasize equ $ - idata

; Import address table (array of IMAGE_THUNK_DATA structures)

iat:
msgbox:
    dd msgboxname
    dd 0

; Import lookup table (array of IMAGE_THUNK_DATA structures)

ilt:
    dd msgboxname
    dd 0

; Hint/Name Table

msgboxname:
    dw 0
    db "MessageBoxA", 0, 0

dllname:
    db "user32.dll", 0

idsecsize equ $ - idata

;
; PE code section data
;

align filealign, db 0

code:

; Entry point

start:

    ; db 0xcc                       ; Debug breakpoints

    ; Call MessageBoxA
    push 0                          ; Type = OK
    push imagebase + .cap           ; Caption
    push imagebase + .msg           ; Text
    push 0                          ; Owner = NULL
    call [imagebase + msgbox]       ; Call user32.dll!MsgBoxA

    ; Exit
    push byte 0
    pop eax
    ret

.msg:
    db "This program is also an x86 bootloader!", 0
.cap:
    db "Poc||GTFO", 0

codesize equ $ - code

filesize equ $ - $$
