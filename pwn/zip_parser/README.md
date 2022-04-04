# zip_parser

ret2dlresolve on x86_64 with large gap between text and writable sections

by garywei944 on 4/4/2022

`zip_parser` is a pwn challenge on UMass CTF 2022. The binary mimics a real
world scenario of a zip parser that contains a buffer overflow vulnerability
due to lack of boundary check. What makes the challenge extremely hard and
non-trivial is that the binary doesn't have any output function loaded on the
GOT table, which makes it impossible to leak any memory before exploitation.

Also, yet the pwntools automation functions for doing ret2dlresolve works well
for this challenge, it doesn't work for 64-bit binaries with large gap between
text and writable sections. I used an approach of manually forging link_map
that deals with such issue.

In this writeup, I will go through the thought process from developing this
challenge and including a detailed explanation to my approach of ret2dlresolve.

## Static Analysis

To investigate the challenge binary, we can begin with some checksec and
reverse engineering.

### checksec

![](images/checksec.png)

### Reversing

Loading up the binary in Ghidra gives us a pretty messy decompiled code at
first. But reversing engineering won't be the majority of this writeup, so I'd
quickly go through the decompiled code and talk about what could we do to
exploit it.

#### `main()`

![](images/dis_main.png)

`main()` function is the entry point to the binary. It read the size of zip
file first, and then read the zip file.

![](images/diagram1.png)

Then it parses *End of Central Directory*, *Central Directory*, *Local Header*
in order.

#### `parse_head()`

![](images/dis_parse_head.png)

Recall the layout of zip file and ***End of central directory record (
EOCD)***

![](images/eocd.png)

`parse_head()` search for the keyword `0x06054b50` that recognize EOCD and load
useful information from it. The parsed data is then stored in a header struct
that I defined in Ghidra to make the code more readable.

line 18 checks `comp_size <= 0x80`, but it won't be used anyway in the rest of
the program.

#### `parse_centdir()`

![](images/dis_parse_centdir.png)

`parse_centdir()` parse n sections of ***Central directory file header***.

![](images/cdfh.png)

#### `parse_data()`

![](images/dis_parse_data.png)

`parse_data()` read data from the Local file header, `memcpy` the data
following to a buffer on stack and then `strcpy` it to a newly allocated buffer
on heap.

![](images/lfh.png)

Here comes our buffer flow vulnerability. The `comp_size` is read in line 15
and 18 without any boundary check, and it could be a different number from the
one load above by `parser_centdir()`. So we are eventually able to read a large
number of bytes from the zip file we make onto the stack, causing buffer
overflow and executing our ROP exploitation.

## Exploitation

### Problem of ret2libc

The most intuitive method to spawn a shell by a ROP exploitation is ret2libc.
But take a loot at GOT table via `readelf -r chal`

```text
Relocation section '.rela.dyn' at offset 0x618 contains 5 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000403ff0  000400000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000403ff8  000700000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000404080  000c00000005 R_X86_64_COPY     0000000000404080 stdout@GLIBC_2.2.5 + 0
000000404090  000d00000005 R_X86_64_COPY     0000000000404090 stdin@GLIBC_2.2.5 + 0
0000004040a0  000e00000005 R_X86_64_COPY     00000000004040a0 stderr@GLIBC_2.2.5 + 0

Relocation section '.rela.plt' at offset 0x690 contains 9 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 strcpy@GLIBC_2.2.5 + 0
000000404020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 setbuf@GLIBC_2.2.5 + 0
000000404028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000404030  000500000007 R_X86_64_JUMP_SLO 0000000000000000 memcmp@GLIBC_2.2.5 + 0
000000404038  000600000007 R_X86_64_JUMP_SLO 0000000000000000 fgets@GLIBC_2.2.5 + 0
000000404040  000800000007 R_X86_64_JUMP_SLO 0000000000000000 memcpy@GLIBC_2.14 + 0
000000404048  000900000007 R_X86_64_JUMP_SLO 0000000000000000 malloc@GLIBC_2.2.5 + 0
000000404050  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 atoi@GLIBC_2.2.5 + 0
000000404058  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
```

No print function is loaded to this binary. So we can't leak the location of
libc or further return to a `system` libc call.

### ret2dlresolve

After hours of googling, ret2dlresolve is the attack method that works if we
can execute a ROP chain but can't leak any address from memory. It is very
complicate and hard to understand, and I don't want to explain how it works in
detail in this writeup.

I have found these online resources that are crucial for me to solve this
challenge. *(Bear with me the most useful one is in Chinese)*

#### Very useful Resources

- [ret2dlresolve超详细教程(x86&x64)](https://blog.csdn.net/qq_51868336/article/details/114644569)
  \- the resource that I follow to develop this exploitation
- [redpwnCTF 2021 - devnull-as-a-service (pwn)](https://activities.tjhsst.edu/csc/writeups/redpwnctf-2021-devnull)
  \- clear and understandable explanation to ret2dlresolve
- [0ctf babystack with return-to dl-resolve](https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62)
  \- another understandable explanation to ret2dlresolve, but on x86
- [ret2dlresolve利用方法](https://blog.csdn.net/qq_38204481/article/details/90074190)
  \- explanation of ret2dlresolve with diagrams, but in Chinese and on x86

#### ret2dlresolve on x86

Most resources I found online are conducted on 32-bit systems. Some of them are
well-structured and relatively easy to understand.

In short, cited
from [redpwnCTF 2021 - devnull-as-a-service (pwn)](https://activities.tjhsst.edu/csc/writeups/redpwnctf-2021-devnull)

> If a function needs to be resolved (i.e. the binary does not use Full RELRO and the function is being called for the first time), then the PLT will push an offset and jump into the resolver to fill in the relocation and then jump into the real function. There are several ELF structures that facilitate this process:
>
> 1. the resolver uses the offset pushed by the PLT stub to look up the function’s ElfW(Rel)/ElfW(Rela) from the ELF JMPREL section
> 2. the resolver uses the r_info from the ElfW(Rel)/ElfW(Rela) to look up the function’s ElfW(Sym) from the ELF SYMTAB section
> 3. the resolver uses the st_name from the ElfW(Sym) to look up the function’s name from the ELF STRTAB section
> 4. the resolver uses the r_info from the ElfW(Rel)/ElfW(Rela) to look up the function’s vernum from the ELF VERSYM section


## Execution

## Reference

- [ZIP (file format) - Wikipedia](https://en.wikipedia.org/wiki/ZIP_(file_format))
  \- for zip file structure