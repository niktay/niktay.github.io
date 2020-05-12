---
title: "Sharky CTF 2020: ｚ３ｒｏｂｏｔｗａｖｅｓ (Reverse)"
layout: post
date: 2020-05-12
tags:
- CTF
- writeup
- Sharky CTF 2020
- RE
- Reversing
comments: true
---

> I made a robot that can only communicate with "z3". He locked himself and now he is asking me for a password !
>
> ｚ３ｗａｖｅｓ
>
> Creator : Nofix
>
> [z3_robot](/files/z3_robot)

Let's see what we're provided with.

```
vagrant@ctf:/vagrant/challenges/sharky/z3robotwaves$ file z3_robot
z3_robot: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=bce2975b632a64a4c4af2009a81f41f43619dad1, not stripped
```

Oh nice a 64-bit ELF file, and it's not even stripped. How nice of them. Let's run it and see what it does.

```
vagrant@ctf:/vagrant/challenges/sharky/z3robotwaves$ ./z3_robot
      \_/
     (* *)
    __)#(__
   ( )...( )(_)
   || |_| ||//
>==() | | ()/
    _(___)_
   [-]   [-]   Z3 robot says :z3 Z3Z3z3 Zz3 zz33 3Z Passz3rd? Zz3 zZ3 3Z Z3Z3z
-> 123
      \_/
     (* *)
    __)#(__
   ( )...( )(_)
   || |_| ||//
>==() | | ()/
    _(___)_
   [-]   [-]   Z3 robot says :
3Z Z3 z3 zz3 3zz33
```

Okay, looks like a typical RE challenge. It seems to be asking for an input (a `Passz3rd` in this case) and checking if it's valid. Let's have a look at it in [Ghidra](https://ghidra-sre.org/).

```c
undefined8 check_flag(byte *param_1)

{
  undefined8 uVar1;
  byte bVar2;
  
  if (((((((((((param_1[0x14] ^ 0x2b) == param_1[7]) &&
             ((int)(char)param_1[0x15] - (int)(char)param_1[3] == -0x14)) &&
            ((char)param_1[2] >> 6 == '\0')) &&
           ((param_1[0xd] == 0x74 && (((int)(char)param_1[0xb] & 0x3fffffffU) == 0x5f)))) &&
          ((bVar2 = (byte)((char)param_1[0x11] >> 7) >> 5,
           (int)(char)param_1[7] >> ((param_1[0x11] + bVar2 & 7) - bVar2 & 0x1f) == 5 &&
           (((param_1[6] ^ 0x53) == param_1[0xe] && (param_1[8] == 0x7a)))))) &&
         ((bVar2 = (byte)((char)param_1[9] >> 7) >> 5,
          (int)(char)param_1[5] << ((param_1[9] + bVar2 & 7) - bVar2 & 0x1f) == 0x188 &&
          (((((int)(char)param_1[0x10] - (int)(char)param_1[7] == 0x14 &&
             (bVar2 = (byte)((char)param_1[0x17] >> 7) >> 5,
             (int)(char)param_1[7] << ((param_1[0x17] + bVar2 & 7) - bVar2 & 0x1f) == 0xbe)) &&
            ((int)(char)param_1[2] - (int)(char)param_1[7] == -0x2b)) &&
           (((param_1[0x15] == 0x5f && ((param_1[2] ^ 0x47) == param_1[3])) &&
            ((*param_1 == 99 && ((param_1[0xd] == 0x74 && ((param_1[0x14] & 0x45) == 0x44)))))))))))
         ) && ((param_1[8] & 0x15) == 0x10)) &&
       (((param_1[0xc] == 0x5f && ((char)param_1[4] >> 4 == '\a')) && (param_1[0xd] == 0x74)))) &&
      (((((bVar2 = (byte)((char)*param_1 >> 7) >> 5,
          (int)(char)*param_1 >> ((*param_1 + bVar2 & 7) - bVar2 & 0x1f) == 0xc &&
          (param_1[10] == 0x5f)) &&
         ((((int)(char)param_1[8] & 0xacU) == 0x28 &&
          ((param_1[0x10] == 0x73 && ((param_1[0x16] & 0x1d) == 0x18)))))) &&
        ((param_1[9] == 0x33 &&
         ((((param_1[5] == 0x31 && (((int)(char)param_1[0x13] & 0x3fffffffU) == 0x72)) &&
           ((char)param_1[0x14] >> 6 == '\x01')) &&
          (((char)param_1[7] >> 1 == '/' && (param_1[1] == 0x6c)))))))) &&
       (((((((char)param_1[3] >> 4 == '\a' &&
            (((param_1[0x13] & 0x49) == 0x40 && (param_1[4] == 0x73)))) &&
           ((param_1[0xb] & param_1[2]) == 0x14)) &&
          (((((*param_1 == 99 && ((int)(char)param_1[5] + (int)(char)param_1[4] == 0xa4)) &&
             (((int)(char)param_1[0xf] & 0x3ffffffU) == 0x5f)) &&
            ((((param_1[10] ^ 0x2b) == param_1[0x11] && ((param_1[0xc] ^ 0x2c) == param_1[4])) &&
             (((int)(char)param_1[0x13] - (int)(char)param_1[0x15] == 0x13 &&
              ((param_1[0xc] == 0x5f && (param_1[0xc] == 0x5f)))))))) &&
           ((char)param_1[0xf] >> 1 == '/')))) &&
         (((param_1[0x13] == 0x72 && ((int)(char)param_1[0x12] + (int)(char)param_1[0x11] == 0xa8))
          && (param_1[0x16] == 0x3a)))) &&
        (((param_1[0x15] & param_1[0x17]) == 9 &&
         (bVar2 = (byte)((char)param_1[0x13] >> 7) >> 5,
         (int)(char)param_1[6] << ((param_1[0x13] + bVar2 & 7) - bVar2 & 0x1f) == 0x18c)))))))) &&
     (((((((int)(char)param_1[7] + (int)(char)param_1[3] == 0xd2 &&
          ((((int)(char)param_1[0x16] & 0xedU) == 0x28 && (((int)(char)param_1[0xc] & 0xacU) == 0xc)
           ))) && ((param_1[0x12] ^ 0x6b) == param_1[0xf])) &&
        ((((((((param_1[0x10] & 0x7a) == 0x72 && ((*param_1 & 0x39) == 0x21)) &&
             ((param_1[6] ^ 0x3c) == param_1[0x15])) &&
            ((param_1[0x14] == 0x74 && (param_1[0x13] == 0x72)))) && (param_1[0xc] == 0x5f)) &&
          (((param_1[2] == 0x34 && (param_1[0x17] == 0x29)) &&
           ((param_1[10] == 0x5f &&
            ((((param_1[9] & param_1[0x16]) == 0x32 &&
              ((int)(char)param_1[2] + (int)(char)param_1[3] == 0xa7)) &&
             ((int)(char)param_1[0x11] - (int)(char)param_1[0xe] == 0x44)))))))) &&
         (((param_1[0x15] == 0x5f && ((param_1[0x13] ^ 0x2d) == param_1[10])) &&
          ((((int)(char)param_1[0xc] & 0x3fffffffU) == 0x5f &&
           (((((param_1[6] & 0x40) != 0 && ((param_1[0x16] & param_1[0xc]) == 0x1a)) &&
             ((bVar2 = (byte)((char)param_1[0x13] >> 7) >> 5,
              (int)(char)param_1[7] << ((param_1[0x13] + bVar2 & 7) - bVar2 & 0x1f) == 0x17c &&
              ((((param_1[0x14] ^ 0x4e) == param_1[0x16] && (param_1[6] == 99)) &&
               (param_1[0xc] == param_1[7])))))) &&
            (((int)(char)param_1[0x13] - (int)(char)param_1[0xd] == -2 &&
             ((char)param_1[0xe] >> 4 == '\x03')))))))))))) &&
       (((param_1[0xc] & 0x38) == 0x18 &&
        (((bVar2 = (byte)((char)param_1[10] >> 7) >> 5,
          (int)(char)param_1[8] << ((param_1[10] + bVar2 & 7) - bVar2 & 0x1f) == 0x3d00 &&
          (param_1[0x14] == 0x74)) &&
         ((bVar2 = (byte)((char)param_1[0x16] >> 7) >> 5,
          (int)(char)param_1[6] >> ((param_1[0x16] + bVar2 & 7) - bVar2 & 0x1f) == 0x18 &&
          (((((int)(char)param_1[0x16] - (int)(char)param_1[5] == 9 &&
             (bVar2 = (byte)((char)param_1[0x16] >> 7) >> 5,
             (int)(char)param_1[7] << ((param_1[0x16] + bVar2 & 7) - bVar2 & 0x1f) == 0x17c)) &&
            (param_1[0x16] == 0x3a)) &&
           ((param_1[0x10] == 0x73 && ((param_1[0x17] ^ 0x1d) == param_1[0x12])))))))))))) &&
      ((((int)(char)param_1[0xe] + (int)(char)param_1[0x17] == 0x59 &&
        (((param_1[2] & param_1[5]) == 0x30 && (((int)(char)param_1[0xf] & 0x9fU) == 0x1f)))) &&
       ((param_1[4] == 0x73 &&
        (((param_1[0x17] ^ 0x4a) == *param_1 && ((param_1[6] ^ 0x3c) == param_1[0xb])))))))))) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}
```

Looking through the binary, we notice that our input is passed into a function called `check_flag` as seen above. Wow what kind of fresh hell is this? That's a lot of conditions to fulfil. However, as the title of the challenge suggests, we can make use of [Z3](https://github.com/Z3Prover/z3) which is a [SMT solver](https://en.wikipedia.org/wiki/Satisfiability_modulo_theories). To put it simply, Z3 can help us find a solution set which satisfies a specific set of constraints.

After tidying up the constraints above (Note: I mapped param_1[0] to a, param_1[1] to b, and so on), we should be able to produce the following script:

```python
from z3 import *

solver = Solver()

a = BitVec('a', 32)
b = BitVec('b', 32)
c = BitVec('c', 32)
d = BitVec('d', 32)
e = BitVec('e', 32)
f = BitVec('f', 32)
g = BitVec('g', 32)
h = BitVec('h', 32)
i = BitVec('i', 32)
j = BitVec('j', 32)
k = BitVec('k', 32)
l = BitVec('l', 32)
m = BitVec('m', 32)
n = BitVec('n', 32)
o = BitVec('o', 32)
p = BitVec('p', 32)
q = BitVec('q', 32)
r = BitVec('r', 32)
s = BitVec('s', 32)
t = BitVec('t', 32)
u = BitVec('u', 32)
v = BitVec('v', 32)
w = BitVec('w', 32)
x = BitVec('x', 32)

solver.add((u ^ 0x2B) == h)
solver.add(v - d == -20)
solver.add((c >> 6) == 0)
solver.add(n == 116)
solver.add(4 * l == 380)
solver.add(h >> r % 8 == 5)
solver.add((g ^ 0x53) == o)
solver.add(i == 122)
solver.add(f << j % 8 == 392)
solver.add(q - h == 20)
solver.add(h << x % 8 == 190)
solver.add(c - h == -43)
solver.add(v == 95)
solver.add((c ^ 0x47) == d)
solver.add(a == 99)
solver.add(n == 116)
solver.add((u & 0x45) == 68)
solver.add((i & 0x15) == 16)
solver.add(m == 95)
solver.add(e >> 4 == 7)
solver.add(n == 116)
solver.add(a >> a % 8 == 12)
solver.add(k == 95)
solver.add((i & 0xAC) == 40)
solver.add(q == 115)
solver.add((w & 0x1D) == 24)
solver.add(j == 51)
solver.add(f == 49)
solver.add(4 * t == 456)
solver.add(u >> 6 == 1)
solver.add(h >> 1 == 47)
solver.add(b == 108)
solver.add(d >> 4 == 7)
solver.add((t & 0x49) == 64)
solver.add(e == 115)
solver.add((c & l) == 20)
solver.add(a == 99)
solver.add(e + f == 164)
solver.add(p << 6 == 6080)
solver.add((k ^ 0x2B) == r)
solver.add((m ^ 0x2C) == e)
solver.add(t - v == 19)
solver.add(m == 95)
solver.add(p >> 1 == 47)
solver.add(t == 114)
solver.add(r + s == 168)
solver.add(w == 58)
solver.add((x & v) == 9)
solver.add(g << t % 8 == 396)
solver.add(d + h == 210)
solver.add((w & 0xED) == 40)
solver.add((m & 0xAC) == 12)
solver.add((s ^ 0x6B) == p)
solver.add((q & 0x7A) == 114)
solver.add((a & 0x39) == 33)
solver.add((g ^ 0x3C) == v)
solver.add(u == 116)
solver.add(t == 114)
solver.add(m == 95)
solver.add(c == 52)
solver.add(x == 41)
solver.add(k == 95)
solver.add((w & j) == 50)
solver.add(d + c == 167)
solver.add(r - o == 68)
solver.add(v == 95)
solver.add((t ^ 0x2D) == k)
solver.add(4 * m == 380)
solver.add((g & 0x40) != 0)
solver.add((m & w) == 26)
solver.add(h << t % 8 == 380)
solver.add((u ^ 0x4E) == w)
solver.add(g == 99)
solver.add(m == h)
solver.add(t - n == -2)
solver.add(o >> 4 == 3)
solver.add((m & 0x38) == 24)
solver.add(i << k % 8 == 15616)
solver.add(u == 116)
solver.add(g >> w % 8 == 24)
solver.add(w - f == 9)
solver.add(h << w % 8 == 380)
solver.add(w == 58)
solver.add(q == 115)
solver.add((x ^ 0x1D) == s)
solver.add(x + o == 89)
solver.add((f & c) == 48)
solver.add((p & 0x9F) == 31)
solver.add(e == 115)
solver.add((x ^ 0x4A) == a)
solver.add((g ^ 0x3C) == l)

solver.check()
solver.model()

flag = [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x]

print ''.join([chr(solver.model()[i].as_long()) for i in flag])
```

Let's see the script in action!

<script id="asciicast-329422" src="https://asciinema.org/a/329422.js" async></script>

Flag: `shkCTF{cl4ss1c_z3___t0_st4rt_:)}`
