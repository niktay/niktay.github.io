---
title: 'LINECTF 2021: babycrypto1 (Crypto)'
layout: post
date: '2021-03-21'
tags:
- CTF
- writeup
- LINECTF 2021
- Crypto
comments: true
---

> `nc 35.200.115.41 16001`
>
> [babycrypto1.py](/files/babycrypto1.py)


In this challenge we are provided with the ip and port of a network service and a python script which seemingly contains the code of the network service. Let's have a look at the code shall we?

```python
flag = open("flag", "rb").read().strip()
COMMAND = [b'test',b'show']
```

The code reads in the flag from a file, and defines 2 commands: `test` and `show`.

```python
if __name__ == '__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 16001))
    server.listen(1)

    while True:
        client, address = server.accept()

        aes_key = get_random_bytes(AES.block_size)
        token = b64encode(get_random_bytes(AES.block_size*10))[:AES.block_size*10]

        process = multiprocessing.Process(target=run_server, args=(client, aes_key, token))
        process.daemon = True
        process.start()
```

As seen above, a _key_ and _token_ is randomly generated (per session) upon a client connecting to the server. The client is then serviced by the `run_server()` function.

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


def run_server(client, aes_key, token):
    client.send(b'test Command: ' + AESCipher(aes_key).encrypt(token+COMMAND[0]) + b'\n')
    client.send(b'**Cipher oracle**\n')
    client.send(b'IV...: ')
    iv = b64decode(client.recv(1024).decode().strip())
    client.send(b'Message...: ')
    msg = b64decode(client.recv(1024).decode().strip())
    client.send(b'Ciphertext:' + AESCipher(aes_key).encrypt_iv(msg,iv) + b'\n\n')
    while(True):
        client.send(b'Enter your command: ')
        tt = client.recv(1024).strip()
        tt2 = AESCipher(aes_key).decrypt(tt)
        client.send(tt2 + b'\n')
        if tt2 == token+COMMAND[1]:
            client.send(b'The flag is: ' + flag)
            client.close()
            break
```

In summary, the logic of `run_server()` is as follows:

1. Print an encrypted test command `AESCipher(aes_key).encrypt(token + b'test')`
2. Provide us with a "Cipher oracle"
    - lets us supply an IV and message
    - performs encryption `AESCipher(aes_key).encrypt_iv(msg, iv)` and returns the ciphertext
3. Continuously accepts (encrypted) commands from us, decrypts it, sends us the decrypted command, and **sends us the flag** if the decrypted command is `token + b'show'`

Additionally we note that more specifically (with reference to the `AESCipher` class) the commands are being encrypted with `AES-128-CBC`. We know that the block size is 16 bytes (128 bits) because `AES.block_size` yields 16.

At this point, the question we should be asking ourselves is:

> How the heck do we generate an encrypted command (ciphertext) that decrypts to `token + b'show'` if we dont have access to the IV and key?

It's possible, but requires some ingenuity on our part. The first step to enlightment is contingent on our understanding of how AES works in CBC mode.


![](/images/babycrypto1/AES-CBC-decrypt.png)

Let's first try to understand how decryption works in CBC mode. We can generalize the above diagram as follows:

Where $$n$$ is the block number, $$C$$ is the Ciphertext, $$P$$ is the Plaintext, and $$D(x)$$ is the decryption function, and $$K$$ is the key,

$$
P_n = \begin{cases} D(C_{n},~K)~\oplus~\text{IV} & n = 1 \\
		            D(C_{n},~K)~\oplus~C_{n-1} & n > 1 \\
      \end{cases}
$$

Let's approach this problem by zooming in on the part we are most interested in, the command.

```python
token = b64encode(get_random_bytes(AES.block_size*10))[:AES.block_size*10]
```

As seen from the snippet of code above, the size of our token is going to be aligned to the block size. Therefore, we can assume that the **last block contains only the command (plus padding)** since encryption is performed on `token + command`. So let's focus solely on what actually matters.

![](/images/babycrypto1/AES-CBC-decrypt-simplified.png)

With reference to the simplified diagram above, we can now reframe our problem as follows:

> What should the ciphertext in the last block be such that it decrypts to 'show'?

Or more formally,

$$ D(?,~K) \oplus~C_{n-1}~=~\text{show}$$

How are we going to figure out what the ciphertext should be? If you still haven't figured it out by now, I would encourage you to mentally (or physically?) flip the above diagram upside down and compare it to the diagram below.

![](/images/babycrypto1/AES-CBC-encrypt.png)

Do you see the resemblance? No? Well let me help you out a little.

![](/images/babycrypto1/AES-CBC-encrypt-simplified.png)

That's right, all we have to do is to encrypt 'show' and set the IV to $$C_{n-1}$$ to figure out what the ciphertext should be! Conveniently, the challenge provides us with a "Cipher Oracle" which lets us encrypt an arbitrary message using an IV which we can also supply.

So let's recap our game plan:

1. Read in the test command and extract out the second last block i.e. $$C_{n-1}$$
2. Use the "Cipher Oracle" to encrypt 'show' with $$C_{n-1}$$ from step 1 as the IV. Read in the ciphertext.
3. Append the ciphertext from step 2 to the test command from step 1 (less the last block since we are replacing it).
4. Get flag. Profit!

We now craft the following script to implemnt the step above.

```python
from pwn import *
from base64 import b64decode, b64encode

HOST = '35.200.115.41'
PORT = 16001

TESTCMD_PROMPT = 'test Command: '
IV_PROMPT = 'IV...: '
MSG_PROMPT = 'Message...: '
CIPHERTEXT_PROMPT = 'Ciphertext:'
COMMAND_PROMPT = 'Enter your command: '
FLAG_MARKER = 'The flag is: '

COMMAND = [b'test', b'show']

def chunks(l, n):
    return [l[i:i + n] for i in range(0, len(l), n)]

io = remote(HOST, PORT)

io.recvuntil(TESTCMD_PROMPT)

testcmd_encrypted = b64decode(io.recvline())
testcmd_blocks = chunks(testcmd_encrypted, 16)

iv = testcmd_blocks[-2]
pt = COMMAND[1]

io.sendlineafter(IV_PROMPT, b64encode(iv))
io.sendlineafter(MSG_PROMPT, b64encode(pt))
io.recvuntil(CIPHERTEXT_PROMPT)

poison_block = b64decode(io.recvline().rstrip())

poison_ciphertext = b''.join(testcmd_blocks[:-2] + [poison_block, ])

io.sendlineafter(COMMAND_PROMPT, b64encode(poison_ciphertext))

io.recvuntil(FLAG_MARKER)

log.success(io.recvuntil('}').decode())

io.close()
```

Flag: `LINECTF{warming_up_crypto_YEAH}`

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-MML-AM_CHTML">
</script>
