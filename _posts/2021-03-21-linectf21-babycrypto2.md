---
title: 'LINECTF 2021: babycrypto2 (Crypto)'
layout: post
date: '2021-03-21'
tags:
- CTF
- writeup
- LINECTF 2021
- Crypto
comments: true
---

> `nc 35.200.39.68 16002`
>
> [babycrypto2.py](/files/babycrypto2.py)


In this challenge we are provided with the ip and port of a network service and a python script which seemingly contains the code of the network service. Lets have a look at the code shall we?

```python
flag = open("flag", "rb").read().strip()

AES_KEY = get_random_bytes(AES.block_size)
TOKEN = b64encode(get_random_bytes(AES.block_size*10-1))
COMMAND = [b'test',b'show']
PREFIX = b'Command: '
```

The code reads in the flag from a file, defines 2 commands: `test` and `show`, generates a token, generates a key, and defines a prefix.

```python
class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data, AES.block_size)))

    def encrypt_iv(self, data, iv):
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data, AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)


def run_server(client):
    client.send(b'test Command: ' + AESCipher(AES_KEY).encrypt(PREFIX+COMMAND[0]+TOKEN) + b'\n')
    while(True):
        client.send(b'Enter your command: ')
        tt = client.recv(1024).strip()
        tt2 = AESCipher(AES_KEY).decrypt(tt)
        client.send(tt2 + b'\n')
        if tt2 == PREFIX+COMMAND[1]+TOKEN:
            client.send(b'The flag is: ' + flag)
            client.close()
            break
```

In summary, the logic of `run_server()` is as follows:

1. Print an encrypted test command `AESCipher(aes_key).encrypt(prefix + b'test' + token)`
2. Continuously accepts (encrypted) commands from us, decrypts it, sends us the decrypted command, and **sends us the flag** if the decrypted command is `prefix + b'show' + token`

Additionally we note that more specifically (with reference to the `AESCipher` class) the commands are being encrypted with `AES-128-CBC`. We know that the block size is 16 bytes (128 bits) because `AES.block_size` yields 16.

```python
def encrypt(self, data):
    iv = get_random_bytes(AES.block_size)
    self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
    return b64encode(iv + self.cipher.encrypt(pad(data, AES.block_size)))

def decrypt(self, data):
    raw = b64decode(data)
    self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
    return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)
```

The crux of this challenge lies in the `encrypt()` and `decrypt()` methods. Instead of just giving us the encrypted data, `encrypt()` also prepends the iv. Additionally, `decrypt()` makes use of the prepended iv to do the decryption. **This is a fatal flaw in the implementation because we now have control of what the first block decrypts to**.

![](/images/babycrypto2/AES-CBC-decrypt.png)

With reference to the first block in the diagram above, notice how the IV directly influences (is XOR-ed with) the the output of $$D(C_1,~K)$$ to produce plaintext $$P_1$$. More formally,

$$D(C_1,~K)~\oplus~\text{IV}~=~P_1$$

Now lets consider what the first block of plaintext for the test command `AESCipher(aes_key).encrypt(prefix + b'test' + token)` (sent to us) would look like.

```
First Block Visualized
======================
____________________________________________________________________________________________________
|                      PREFIX                         |        Command        |        Token       |
____________________________________________________________________________________________________
| 'C' | 'o' | 'm' | 'm' | 'a' | 'n' | 'd' | ':' | ' ' | 't' | 'e' | 's' | 't' | t[0] | t[1] | t[2] |
----------------------------------------------------------------------------------------------------
   1     2     3     4     5     6     7     8     9     10    11    12    13    14     15     16
```

Considering that:

1. The original IV (which we shall define as $$\text{IV}_\text{original}$$ ) is sent to us.
2. We can modify the IV before we send it in to be decrypted

We can easily change 'test' to 'show' by sending in a "poisoned" IV. How does this work?

Suppose,

$$ D(C,~K)~\oplus~\text{IV}_\text{original}~=~\text{test}$$

Then we XOR both sides by $$(\text{test}~\oplus~\text{show})$$,

$$
D(C,~K)~\oplus~\text{IV}_\text{original}~\oplus~(\text{test}~\oplus~\text{show})~=~\text{test}~\oplus~(\text{test}~\oplus~\text{show}) \\
D(C,~K)~\oplus~\text{IV}_\text{original}~\oplus~(\text{test}~\oplus~\text{show})~=~\text{show}\\
$$

Voilà! The 'test' command is now 'show'. So now let's suppose,

$$\text{IV}_{\text{poison}}~=~\text{IV}_{\text{original}}~\oplus~\text{test}~\oplus~\text{show}$$

We can now do,

$$D(C,~K)~\oplus~\text{IV}_\text{poison}~=~\text{show}$$

Awesome, looks like what we need! But in reality, _not quite_. In practice, we cannot just XOR 'test' and 'show' with the original IV directly due to alignment.

```
D(C_1, K) visualized
====================
____________________________________________________________________________________________________
|                      PREFIX                         |        Command        |        Token       |
____________________________________________________________________________________________________
   1     2     3     4     5     6     7     8     9     10    11    12    13    14     15     16
```

Notice how the command we are trying to mutate is at offset 10 to 13. Therefore, we need to pad it to the correct position. How do we achieve this without corrupting PREFIX and TOKEN? We can use the _identity element_ for XOR (0 i.e. Null Byte) which gives us,

$$A~\oplus~0~=~A$$

Therefore we can construct $$\text{IV}_{\text{poison}}$$ as follows:

```python
iv_poison = xor(iv_original, b'\x00' * 9 + xor(b'test', b'show') + b'\x00' * 3)
```

So lets recap our game plan:

1. Read in the test command and extract out IV (first block) to obtain $$\text{IV}_{\text{original}}$$
2. Construct $$\text{IV}_{\text{poison}}$$  as defined above
3. Prepend $$\text{IV}_{\text{poison}}$$ to the encrypted test command (less the first block, which is the IV that we are replacing) which we received in step 1 so that `decrypt()` will use our poisoned IV.
4. Get flag. Profit!

We now craft the following script to implement the steps above.

```python
from pwn import *
from base64 import b64decode, b64encode

HOST = '35.200.39.68'
PORT = 16002

TESTCMD_PROMPT = 'test Command: '
CIPHERTEXT_PROMPT = 'Ciphertext:'
COMMAND_PROMPT = 'Enter your command: '
FLAG_MARKER = 'The flag is: '

COMMAND = [b'test', b'show']

poison_command = b'\x00' * 9 + xor(COMMAND[0], COMMAND[1]) + b'\x00' * 3


def chunks(l, n):
    return [l[i:i + n] for i in range(0, len(l), n)]

io = remote(HOST, PORT)

io.recvuntil(TESTCMD_PROMPT)

testcmd_encrypted = b64decode(io.recvline())

testcmd_blocks = chunks(testcmd_encrypted, 16)

iv_poison = xor(poison_command, testcmd_blocks[0])

poison_payload = b''.join([iv_poison, ] + testcmd_blocks[1:])

io.sendlineafter(COMMAND_PROMPT, b64encode(poison_payload))

io.recvuntil(FLAG_MARKER)

log.success(io.recvuntil('}').decode())

io.close()
```

Flag: `LINECTF{echidna_kawaii_and_crypto_is_difficult}`

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-MML-AM_CHTML">
</script>
