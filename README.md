# Polyglots

A repository of polyglots I've made

## bootpe

A polyglot that is a valid windows executable and a valid x86 bootloader

#### Compile:

```
nasm -f bin -o bootpe.exe bootpe.asm
nasm -f bin -o bootelf bootelf.asm
```

#### Run:

```
qemu-system-x86_64 -fda bootpe.exe -curses
qemu-system-x86_64 -fda bootelf -curses
```

Or just run each executable as you normally would

#### Writeup

* [BootPE Writeup](./bootpe/writeup.md)
