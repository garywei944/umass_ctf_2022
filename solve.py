from pwn import *

elf = context.binary = ELF('./chall')
libc = elf.libc

local = False

if local:
    io = elf.process()
else:
    host = 'localhost'
    port = 8080
    io = remote(host, port)

if args.GDB:
    gdb.attach(io, """
        b *main
        c
    """)

io.interactive()
