---
title: '3kCTF 2021: crypto warmup (Crypto)'
layout: post
date: '2021-05-17'
tags:
- CTF
- writeup
- 3kCTF 2021
- Crypto
comments: true
---

> I found this weird code. Can you tell me what it does?
>
> [source code](/files/challenge-9117504dc1ed3a5ffe385f8a736c42e384d707e4.py)


In this challenge, we've been instructed to investigate what the weird (source) code provided to us does. We'll start off by having a look at the provided code.

```python
import random
import math

n = 24

def make_stuff():
    A = []; b = [1, 10]
    for i in range(n):
        A.append(random.randint(*b))
        b[False] = sum(A) + 1
        b[True] = int(b[False] << 1)
    c = random.randint(sum(A), sum(A) << 1)
    while True:
        d = random.randint(sum(A), sum(A) << 1)
        if math.gcd(c, d) == 1:
            break

    return [(d*w) % c for w in A]


def weird_function_1(s):
    return sum([list(map(int,bin(ord(c))[2:].zfill(8))) for c in s], [])

def do_magic(OooO, B):
    return sum(m * b for m, b in zip(weird_function_1(OooO), B))

B = make_stuff()

with open("flag") as fd:
    flag = fd.read().strip()

print(B)
for i in range(0, len(flag), 3):
    print(do_magic(flag[i:i+3], B))



##[4267101277, 4946769145, 6306104881, 7476346548, 7399638140, 1732169972, 1236242271, 5109093704, 2163850849, 6552199249, 3724603395, 3738679916, 5211460878, 642273320, 3810791811, 761851628, 1552737836, 4091151711, 1601520107, 3117875577, 2485422314, 1983900485, 6150993150, 2045278518]
##34451302951
##58407890177
##49697577713
##45443775595
##38537028435
##47069056666
##49165602815
##43338588490
##32970122390
```

Okay, great. Looks like we've got some really convoluted code, and its corresponding output (as a comment in the footer). Honestly, those look like methods that i'd rather not try to reverse engineer if possible. Let's see if we can avoid that.

Since the script requires us to provide it with a `flag` file as an input, we'll just create a dummy flag file. Let's run it a couple of times with a couple of different (strategically crafted) inputs to experiment a little.

```
vagrant in pwnbox in /CTF/3kctf-2021/crypto-warmup
❯ echo 'A' > flag

vagrant in pwnbox in /CTF/3kctf-2021/crypto-warmup
❯ python challenge-9117504dc1ed3a5ffe385f8a736c42e384d707e4.py
[4316173603, 263032606, 3491191816, 490181243, 2594442091, 4889967607, 1876762711, 2761318113, 1911248680, 4275746134, 5462674934, 1692723012, 663157380, 1622784835, 3725119112, 413770260, 4171334239, 230254536, 469323800, 5354734443, 3690100820, 2612607148, 1882137547, 4060404198]
3024350719

vagrant in pwnbox in /CTF/3kctf-2021/crypto-warmup
❯ echo 'AAAAAAAAAAAAA' > flag

vagrant in pwnbox in /CTF/3kctf-201/crypto-warmup
❯ python challenge-9117504dc1ed3a5ffe385f8a736c42e384d707e4.py
[12457030802, 18534521622, 11399858735, 3661097524, 4905801752, 17284823133, 2744961516, 3818664119, 5220934942, 16912503315, 6338532888, 1478174232, 8027743066, 12251517306, 8427126852, 5781047713, 12590268095, 10949857589, 14008435307, 9251216834, 9156619481, 9323263175, 5368576116, 13238876554]
69235470912
69235470912
69235470912
69235470912
22353185741

vagrant in pwnbox in /CTF/3kctf-2021/crypto-warmup
❯ echo 'AAAA' > flag

vagrant in pwnbox in /CTF/3kctf-2021/crypto-warmup
❯ python challenge-9117504dc1ed3a5ffe385f8a736c42e384d707e4.py
[3677393784, 13247890319, 16171259953, 8723745419, 5661285336, 11798413924, 12379192564, 8042971801, 3579869011, 7054945237, 9305379677, 17803531518, 3484009520, 4987453311, 4290441915, 18154297343, 13050406667, 12406866282, 10404883077, 9624753770, 6249042126, 9490910358, 883137378, 16474901793]
75381872775
21290862120

vagrant in pwnbox in /CTF/3kctf-2021/crypto-warmup
❯ echo 'AAA' > flag

vagrant in pwnbox in /CTF/3kctf-2021/crypto-warmup
❯ python challenge-9117504dc1ed3a5ffe385f8a736c42e384d707e4.py
[624381889, 1057064400, 2880926312, 1111783797, 1407486327, 1374509498, 454062102, 1439374225, 762804765, 1375217426, 752632396, 2751106728, 1753762286, 2205439227, 53392029, 1309875825, 1386835135, 1803116467, 1186008788, 1862312604, 2606316934, 1961093141, 2738209362, 2591776479]
9576424822

vagrant in pwnbox in /CTF/3kctf-2021/crypto-warmup
❯ echo 'AAA###ABCABCAAAAAA######' > flag

vagrant in pwnbox in /CTF/3kctf-2021/crypto-warmup
❯ python challenge-9117504dc1ed3a5ffe385f8a736c42e384d707e4.py
[14509993070, 10381864378, 9380603529, 16084077673, 7501167127, 15800027237, 7281020780, 12462458811, 13461309825, 3216602601, 9893568560, 13088289070, 79504825, 11628772419, 15980443041, 7977281801, 6645771183, 7511180388, 15350273489, 7465108870, 13472380914, 7002025518, 6221528624, 10152752687]
51702140666
94699931322
65926830530
65926830530
51702140666
51702140666
94699931322
94699931322
```

If you're observant enough, you'd realise we can potentially craft out a (likely) solution from the above experiments. Still confused? Let's list the observations we made.

1. The length of our flag affects how many numbers are produced.
    - `A` produces `3024350719` whereas `AAAA` produces `75381872775` and `21290862120`.
2. A number is produced for every block of 3 characters.
    - `AAA` produces `9576424822` whereas `AAAA` produces `75381872775` and `21290862120`.
3. Each block of 3 characters seem to produce the same (unique) number (within the same run)
    - `AAAAAAAAAAAAA` produces 4 instances of `69235470912` (we've got 4 `AAA`s) and 1 instance of `22353185741` (the trailing `A`). We've also tried to test this more extensively by feeding in `AAA###ABCABCAAAAAA######` in our last experiment, and it checks out.
4. The numbers produced differ across runs.
    - This likely has to do with the list of numbers that are printed prior to the numbers. (This is more of a hunch)

Since each unique set of three characters (trigram) seem to produce a unique number, we can just generate all the possible mappings of trigrams to numbers and do a reverse lookup. Observation 4 can be mitigated because the list of numbers that was used to encode the actual flag was already given to us in the comments within the code. This can be trivially achieved by making some slight modifications to the code provided to us.

```python
from pwn import *

import itertools
import string


def make_stuff():
    return [
        4267101277,
        4946769145,
        6306104881,
        7476346548,
        7399638140,
        1732169972,
        1236242271,
        5109093704,
        2163850849,
        6552199249,
        3724603395,
        3738679916,
        5211460878,
        642273320,
        3810791811,
        761851628,
        1552737836,
        4091151711,
        1601520107,
        3117875577,
        2485422314,
        1983900485,
        6150993150,
        2045278518,
    ]


def weird_function_1(s):
    return sum([list(map(int, bin(ord(c))[2:].zfill(8))) for c in s], [])


def do_magic(OooO, B):
    return sum(m * b for m, b in zip(weird_function_1(OooO), B))


B = make_stuff()

hashes = [
    34451302951,
    58407890177,
    49697577713,
    45443775595,
    38537028435,
    47069056666,
    49165602815,
    43338588490,
    32970122390,
]

with log.progress("Generating trigram-hash mapping") as p:
    trigrams = {
        do_magic(trigram, B): trigram
        for trigram in [
            "".join(x)
            for x in itertools.product(string.printable + "\x00", repeat=3)
        ]
    }

flag = "".join([trigrams[_hash] for _hash in hashes])[:-2]

log.success(f"Found Flag: {flag}")
```

Running the above script yields us the flag in approximately 10 seconds as seen below.

```
vagrant in pwnbox in /CTF/3kctf-2021/crypto-warmup
❯ time python xpl.py
[+] Generating trigram-hash mapping: Done
[+] Found Flag: CTF{w4rmup-kn4ps4ck-ftw!}

real    0m10.161s
user    0m10.004s
sys     0m0.119s
```

Flag: `CTF{w4rmup-kn4ps4ck-ftw!}`
