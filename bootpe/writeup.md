Having found myself working with bootloaders and assembly lately, and learning realizing how simple
bootloaders are, I decided to try and make a bootloader/executable polyglot

## ELFs are hard to play

~~My first thought was to create an ELF file that was also a valid bootloader. Unfortunately, the ELF
header is appeared to be a rather daunting task, so I decided to try a different format. I found
Microsoft PE to be easier to work with (though I would like to come back to ELF someday and see if
I can make it work)~~

I managed to get an ELF working as well. The ELF magic (0x7f, "ELF") results in an x86 jump to the
4th byte of p_filesz. By fixing up p_filesz and p_memsz, we can turn that into a second jmp
instruction that goes to our bootloader. This is fine, since p_filesz just needs to be large enough
to hold the binary, but can be larger, and p_memsz needs to be >= p_filesz

## Building a Halfling

Windows executables start with a legacy DOS header consisting of the bytes `4d5a` followed by 58
unused, and finally e_lfanew, the pointer to the PE header (the actual header the executable cares
about).

This is great for several reasons: First, the magic header translates into some fairly benign x86
opcodes (`dec ebp` and `pop edx`), which we can safely ignore. Second, the subsequent 58 bytes are
ignored by modern versions of Windows and can be safely set to any value. We can use this to write
a very tiny bootloader, or more usefully to jump further down the file. Finally, the PE header is
identified by a pointer, and it does not have to follow the DOS header. This means that the DOS
header only occupies 4 out of the 510 usable bytes for our bootloader. With some clever alignment
of the PE header, you could even make use of the pointer, allowing you to use 508 of the 510 
bytes.

In this case, I decided to simply jump past the DOS header into my bootloader. I largely used
Alex Parker's bootloader sample (http://3zanders.co.uk/2017/10/13/writing-a-bootloader/) since it
does a great job of getting the point across

```
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
```



Next I need a valid PE header. I started with the one Alexander Sotirov wrote for his foray into
tiny PE files (http://www.phreedom.org/research/tinype/). However, since I cared more about having
a valid header than about size, I simply used the first version of a PE header written in assembly,
SANS any overlapping.

Thankfully, this worked and the binary ran on both windows and qemu. However, I wanted to do
something better than setting a return code in windows. Since Windows doesn't follow the Linux
convention of using syscalls, I would actually need to import a DLL 

To do this, I needed to fix up a few things. First, I needed to add the data directories to the PE
optional header. Up until now, these were all set to NULL, since the mimial executable did not need
to import any DLLs. I once again borrowed from Alexander's code. However, at this point he had
already finished overlapping the PE and optional headers, so I had to reference the MSDN guide as
well. The end result was this:

```
    dd 16                         ; NumberOfRvaAndSizes (always 16 afaik)

;
; Data directories
;

    dd 0, 0                       ; export table UNUSED

    dd idata                      ; Import Table
    dd idatasize

    times 14 dd 0, 0              ; other tables

opthdrsize equ $ - opthdr
```

Windows expects 16 entires in the Data Directories table. We only care about the second one here
(imports) so we can null out the rest

Next I needed a place to put the import data. I could have just shoved it into the code section,
but it seemed better to do this properly, so I added a .idata section

```
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
```

This is mostly identical to the code section, but with different name, length, offsets, and
permissions. Honestly, I'm not sure if the permission match exactly, but this works and it
seems reasonable (the program needs to read the import data, and the loader needs to write
the actual offsets when the dll is loaded.

After that, I just had to create the section:

```
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
```

The Import table specifies where the Import Lookup Table (ILT) and Impport Address Table (IAT) are
located, as well as the name of the corresponding DLL

The IAT and ILT are identical, and specify all the symbols being imported. If the first bit of the
entry is 1, it is followed by 15 0 bits, and then a 16-bit ordinal. If the first bit is 0, it is
followed by a 31-bit pointer into a Hint/Name table

The Hint/Name table entries consit of a Hint which specifies where to look (for a faster result if
it matches) and a null-terminated string of the function name, as well as an optional padding byte
to ensure alignment on an even address. The padding byte is also null.

As a fun aside, if the function name is not found in the specified DLL, it will also attempt to
search the executable itself, which makes for some rather confusing error messages.

With the setup above, the loader should be able to load  `user32.dll` and locate the `MessageBoxA`
funciton. Once it does, it replace the entry in the IAT with the actual virtual address of the
function. This is the address we will use for an indirect call (hence the label). The rest of the
assembly is pretty simple:

```
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
```

Note that since call and push use absolute addresses, we need to offset them by the image base.

```
imagebase equ 0x400000
```

There's probably a better way of doing that, but I couldn't figure it out.

## Conclusion

And there it is, a windows executable that's also a bootloader. I hope somebody can think of
something useful to do with this, or a way to take it a step further.
