# Questionnaire - HTB Cyber Apocalypse 2023

Just a simple questionnaire which needs to be answered by connecting to the remote instance.

Connect using  `nc <IP> <PORT>`

Answers to all questions can be found by reading the descriptions of each section carefully on the remote instance.

Answers to all the questions:


##### Question 1:

```
Is this a '32-bit' or '64-bit' ELF? (e.g. 1337-bit)
```

###### Answer:

```
64-bit
```

##### Question 2:

```
What's the linking of the binary? (e.g. static, dynamic)
```

###### Answer:

```
dynamic
```

##### Question 3

```
Is the binary 'stripped' or 'not stripped'?
```
###### Answer:
```
not stripped
```

##### Question 4

```
Which protections are enabled (Canary, NX, PIE, Fortify)?
```

###### Answer:

```
NX
```

##### Question 5

```
What is the name of the custom function that gets called inside `main()`? (e.g. vulnerable_function())
```

###### Answer:

```
vuln()
```

##### Question 6

```
What is the size of the 'buffer' (in hex or decimal)?
```

###### Answer:

```
0x20
```

##### Question 7

```
Which custom function is never called? (e.g. vuln())
```

###### Answer:

```
gg()
```

##### Question 8

```
What is the name of the standard function that could trigger a Buffer Overflow? (e.g. fprintf())
```

###### Answer:

```
fgets()
```

##### Question 9

```
Insert 30, then 39, then 40 'A's in the program and see the output.

After how many bytes a Segmentation Fault occurs (in hex or decimal)?
```

###### Answer:

```
0x28
```

This can be calculated from the 0x20 buffer, rbp overwritten fully at 0x28 so 0x28 causes segfault cause of newline from fgets

##### Question 10

```
What is the address of 'gg()' in hex? (e.g. 0x401337)
```

###### Answer:

```
0x401176
```

##### Flag
`HTB{th30ry_bef0r3_4cti0n}`


### Automatic script
```py
from pwn import *

context.log_level = "ERROR"
IP = "Insert IP here"
PORT = 0x0 #<INSERT PORT HERE>
io = remote(IP, PORT)

def send_answer(ans):
    io.recvuntil(b'>> ')
    io.sendline(ans)

answers = [
    b'64-bit',
    b'dynamic',
    b'not stripped',
    b'NX',
    b'vuln()',
    b'0x20',
    b'gg()',
    b'fgets()',
    b'0x28',
    b'0x401176'
]

for answer in answers:
    send_answer(answer)
io.recvuntil(b'your first challenge! Here is the flag!\n\n')
flag = io.recvline()
print(f"FLAG: {flag.decode('UTF-8')}")
io.close()
```
