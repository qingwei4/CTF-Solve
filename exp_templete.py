from pwn import *

#context.arch = 'i386'
context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

binary = ''
libc_path = ''
Host = ''
Port = 

#p = remote(Host, Port)
p = process(binary)
elf = ELF(binary)
libc = ELF(libc_path)
malloc_hook = libc.symbols('__malloc_hook')
free_hook = libc.symbols('__free_hook')

p.interactive()