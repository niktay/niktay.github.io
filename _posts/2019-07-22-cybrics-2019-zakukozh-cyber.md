---
title: 'CyBRICS Quals 2019: Zakukozh (Cyber)'
layout: post
date: '2019-07-22'
tags:
- CTF
- writeup
- Cybrics Qualifiers 2019
- Crypto
comments: true
---

> This image containing flag is encrypted with affine cipher. Scrape it 
> 
> [zakukozh.bin](/files/zakukozh.bin)


In this challenge, we are given a file with an extension of `.bin`. We start off by trying to identify it.

```
vagrant@ubuntu-cosmic:/vagrant/zakukozh$ file zakukozh.bin

zakukozh.bin: data
```

The `file` command tells us that it seems to be just binary data. Lets get an idea of what we're working with by doing a hexdump.

```
vagrant@ubuntu-cosmic:/vagrant/zakukozh$ hexdump -C zakukozh.bin | head

00000000  60 09 eb 82 1c ef df ef  59 59 59 1c a0 91 55 27  |`.......YYY...U'|
00000010  59 59 77 bc 59 59 59 2e  d1 77 59 59 59 a9 44 38  |YYw.YYY..wYYY.D8|
00000020  31 59 59 59 68 16 27 82  37 59 8b 6b fd 00 59 59  |1YYYh.'.7Y.k..YY|
00000030  59 95 62 28 dc 28 59 59  b8 ba fe 1d 08 a4 59 59  |Y.b(.(YY......YY|
00000040  59 e0 e9 91 90 16 59 59  2b c6 59 59 2b c6 68 02  |Y.....YY+.YY+.h.|
00000050  da 31 35 59 59 fe 7e a0  55 28 45 61 db 3c 3d 10  |.15YY.~.U(Ea.<=.|
00000060  08 a6 a1 a3 a4 89 ab 3e  68 b0 1b 82 a6 35 fd cd  |.......>h....5..|
00000070  1c e0 d9 de 59 67 7f e3  45 70 b0 e2 e6 22 55 17  |....Yg..Ep..."U.|
00000080  32 d9 de 3e 87 1d d2 c2  59 51 e7 e6 59 49 a2 82  |2..>....YQ..YI..|
00000090  68 39 eb ab 77 19 7d fd  a4 d9 a1 b0 ef 59 f8 07  |h9..w.}......Y..|
```

Based on the challenge description, this file is the output of an image that has been encrypted with an [affine cipher](https://en.wikipedia.org/wiki/Affine_cipher). An affine cipher is a [monoalphabetic cipher](https://en.wikipedia.org/wiki/Substitution_cipher) (implies each input has a one-to-one mapping its output) which has an encryption function of

$$E(x) = (ax + b)\pmod m$$

where the modulus $$m$$ is the size of the alphabet, and $$a$$ and $$b$$ are the keys. Since we're dealing with binary data, the size of our "alphabet" would be $$256$$ since each byte can have a value of $$0$$ to $$255$$ which means that $$m = 256$$. Additionally, $$a$$ and $$m$$ are chosen such that they are [coprime](https://en.wikipedia.org/wiki/Coprime_integers), meaning that they have a [gcd](https://en.wikipedia.org/wiki/Greatest_common_divisor) of $$1$$.


Given that this is a monoalphabetic cipher, the decryption function $$D(x)$$ is simply the inverse of $$E(x)$$. In simple terms, if $$E(4) = 20$$, then $$E(20) = 4$$. Therefore, we just need to derive the original mapping, i.e. figure out the values of $$a$$ and $$b$$. Based on what what we  mentioned earlier, $$a$$ and $$m$$ must be coprime. As for $$b$$, since we are doing a modulus by $$m$$, it implies that $$b$$ should be less than $$256$$. Therefore, we can conclude that 

$$a \in \{x \in \mathbb{Z}^+ \mid x \perp 256\}$$

$$b \in \{x \in \mathbb{Z}^+ \mid x \lt 256\}$$

Considering that this is a CTF, we'd like to solve this as fast as possible. Since finding the coprimes might be too much of a hassle, we can just assume that

$$a \in \{x \in \mathbb{Z}^+ \mid x \lt 256\}$$

This is reasonable since a search space of $$256^2$$ is still pretty small. The following script bruteforces the values of $$a$$ and $$b$$. 

```python
def reffine(a, b, c):
    return chr((a * (ord(c) - b)) % 256)

with open('zakukozh.bin') as f:
	encrypted = f.read()

for i in range(256):
    for j in range(256):
        decrypted = ''.join([reffine(i, j, c) for c in encrypted])

        with open('output/dec_{}_{}.out'.format(i, j), 'wb') as f:
            f.write(decrypted)
```

Since the challenge description mentioned that it's supposed to be an image, we can just filter our results based on that. 

```
vagrant@ubuntu-cosmic:/vagrant/zakukozh/output$ file * | grep image

dec_136_107.out: BS image, Version 8352, Quantization 8200, (Decompresses to 61480 words)
dec_136_11.out:  BS image, Version 8352, Quantization 8200, (Decompresses to 61480 words)
dec_136_139.out: BS image, Version 8352, Quantization 8200, (Decompresses to 61480 words)
dec_136_171.out: BS image, Version 8352, Quantization 8200, (Decompresses to 61480 words)
dec_136_203.out: BS image, Version 8352, Quantization 8200, (Decompresses to 61480 words)
dec_136_235.out: BS image, Version 8352, Quantization 8200, (Decompresses to 61480 words)
dec_136_43.out:  BS image, Version 8352, Quantization 8200, (Decompresses to 61480 words)
dec_136_75.out:  BS image, Version 8352, Quantization 8200, (Decompresses to 61480 words)
dec_151_122.out: floppy image data (IBM SaveDskF)
dec_15_176.out:  Netpbm PAM image file
dec_162_184.out: PBF image (deflate compression)
dec_162_56.out:  PBF image (deflate compression)
dec_177_15.out:  SGI image data, 64992-D, 53472 x 10794, 11005 channels, "[\202F**?\277AfIV\262\014\035\316\261)g\362T\005Z\334\177\211QL\203gF\216^\375\201\252\037*\330p\224V\021Q\343\247#f\2103\252\037\177\370\256\323\303*\242X\247*\032\243\203\211\012\034\334\350\352\016\216\005\252\362Q\340*\031x\226*\010\306\002*\346\3019*\242\267\247*\032"
dec_177_177.out: JPEG image data
dec_194_199.out: JPEG 2000 image
dec_194_71.out:  JPEG 2000 image
dec_221_148.out: SVr3 curses screen image, little-endian
dec_234_123.out: RLE image data, 2152 x 60652, lower left corner: 26208, lower right corner: 2090, alpha channel, comment, 42 color channels, 28 color map channels
dec_234_251.out: RLE image data, 2152 x 60652, lower left corner: 26208, lower right corner: 2090, alpha channel, comment, 42 color channels, 28 color map channels
dec_239_89.out:  PNG image data, 621 x 219, 8-bit/color RGB, non-interlaced
dec_254_181.out: floppy image data (IBM SaveDskF, old)
dec_254_53.out:  floppy image data (IBM SaveDskF, old)
dec_35_213.out:  SVr3 curses screen image, big-endian
```

Looking through the results, we discover that `dec_239_89.out` is a `PNG` that contains the flag.

![](/images/zakukoh/dec_239_89.png)

Flag: `cybrics{W311_C0M3_2_CY13R1C5}`

<script type="text/javascript" async
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-MML-AM_CHTML">
</script>
