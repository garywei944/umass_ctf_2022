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
        # b *main+174
        b *parse_data+522
        c
    """)

# io.send(b'00000128')

# s = b'aaaabaaacaaadaaaeaaa' \
#     b'faaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaab'
#
# payload = b''
# payload += p32(0x06054b50)
# payload += s[:20]
# payload += s[20:]

# can control header

io.sendline(payload)

io.interactive()
