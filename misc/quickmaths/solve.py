from pwn import *

local = False

if local:
    elf = context.binary = ELF('./chall')
    libc = elf.libc
    io = elf.process()
else:
    host = '34.148.103.218'
    port = 1228
    io = remote(host, port)

if args.GDB:
    gdb.attach(io, """
        b *main
        c
    """)

io.recvlines(5)

for _ in range(1000):
    problem = io.recvline().strip()
    a, op, b = problem.split()
    a, b = int(a), int(b)
    print(problem.decode())
    # print(a, b)
    if op == b'+':
        r = a + b
    elif op == b'-':
        r = a - b
    elif op == b'*':
        r = a * b
    elif op == b'//':
        r = a // b
    else:
        raise ValueError(problem)

    print(r)
    io.sendline(str(r).encode())
    print(io.recvline().decode())  # Correct
    print('-' * 50)

print(io.recv())
# io.interactive()
