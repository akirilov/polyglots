# Polyglots

A repository of polyglots I've made

## bootpe

A polyglot that is a valid windows executable and a valid x86 bootloader

#### Compile:


```
nasm -f bin -o bootpe.exe bootpe.asm
```

#### Run:


```
qemu-system-x86_64 -fda bootpe.exe -curses
```

Or just open from Windows

#### Writeup

* [BootPE Writeup](./bootpe/writeup.md)
