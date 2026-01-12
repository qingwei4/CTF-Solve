AES AEAD
===
401 points / 5 solves

### Writeup

This binary modify GHASH implementation in AES GCM.

The standard one should be
```
Y_i = (Y_{i-1} ^ X_i) * H
```

and in the binary it is
```
Y_i = (Y_{i-1} * H) ^ X_i
```

My teammate Neobeo says that we can use it to forge the tag and message length in AES GCM.
Then I use it to trigger oob read, leaking libc address, heap address and H0 in AES GCM.

The oob read also gives us an encryption oracle in AES ECB.
With H0 we can forge arbitrary ciphertext for AES CGM, controlling the content of decrypted plaintext/

The remaining part is just heap overflow and do the fsop.

Notice that the first 0x180 bytes will be encrypted by AES ECB after AES GCM decryption. And we cannot control the encrypted value. We have to start our overwrite at the location before _IO_2_1_stderr_.

Also scanf() will load some pointer at _nl_global_locale and dereference them. If we allocate at _IO_2_1_stderr_ - 0x180, the dereference will failed and crash.
We can allocate at _nl_global_locale - 0x180 and forge the structure. We also need to overwirite the _IO_list_all which is between _nl_global_locale and _IO_2_1_stderr_. Then overwrite _IO_2_1_stderr_ to get shell.

