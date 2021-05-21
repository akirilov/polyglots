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
qemu-system-x86_64 bootpe.exe
```

(If you don't have a video device, e.g. if you're remoting into a server, append the `-curses` flag)

Or just run it as you normally would on Windows

## bootelf

A polyglot that is a valid ELF executable and a valid x86 bootloader

#### Compile:

```
nasm -f bin -o bootelf bootelf.asm
```

#### Run:

```
qemu-system-x86_64 bootelf
```

(If you don't have a video device, e.g. if you're remoting into a server, append the `-curses` flag)

Or just run it as you normally would on Linux

#### Writeup

* [BootPE Writeup](./bootpe/writeup.md)
