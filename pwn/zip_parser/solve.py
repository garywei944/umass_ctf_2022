from pwn import *

elf = context.binary = ELF('./chal')
libc = elf.libc

local = True

if local:
    io = elf.process()
else:
    host = 'localhost'
    port = 8080
    io = remote(host, port)

if args.GDB:
    gdb.attach(io, """
        b *main+69
        c
    """)

io.send(b'16')

io.interactive()
