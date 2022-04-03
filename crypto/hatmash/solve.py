from pwn import *
import numpy as np

local = False

if local:
    io = process(['python3', 'hatmash_np.py'])
else:
    host = '34.139.216.197'
    port = 10001
    io = remote(host, port)

if args.GDB:
    gdb.attach(io, """
        b *main
        c
    """)

io.recvuntil(b'KEY: ')
KEY = unhex(io.recvline().strip())
io.recvuntil(b'TARGET: ')
TARGET = unhex(io.recvline().strip())

log.info(f'KEY: {KEY}')
log.info(f'TARGET: {TARGET}')


def bytes_to_mat(x):
    # assert len(x) == 32
    _bits = list('{:0256b}'.format(int.from_bytes(x, 'big')))
    _bits = [int(b) for b in _bits]
    return np.array(_bits).reshape(16, 16)


A, B, C = [bytes_to_mat(KEY[i::3]) for i in range(3)]

T = bytes_to_mat(TARGET)

# Brute-force!

MAX_N = 300
MAX_GUESSES = 1 << 15
rng = np.random.default_rng()

t = 0

for n in range(1, MAX_N):
    _C = np.eye(16)
    for _ in range(n + 1):
        _C = _C @ C
    _C %= 2

    for _ in range(min(MAX_GUESSES, 90 * n)):
        rands = rng.integers(32, 126, n)
        t += 1

        r = np.eye(16)
        for rand in rands:
            for c in f'{rand:08b}':
                if c == '0':
                    r = r @ A
                else:
                    r = r @ B
            r %= 2

        if not ((r + _C + T) % 2).any():
            print('-' * 50)
            print('Success!')
            print(rands)
            print(f'Find a sulotion in {t} guesses!')
            print('-' * 50)

            payload = b''.join([pack(int(_r), 8, 'big') for _r in rands])
            print(payload)
            io.sendline(payload)
            print(io.recv())
            exit(0)
        else:
            # print('Failed.')
            # print(rands)
            print(f'{n}\t{t}')
