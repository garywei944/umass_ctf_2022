from pwn import *
import numpy as np

local = True

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
    return np.array(_bits, dtype=int).reshape(16, 16)


A, B, C = [bytes_to_mat(KEY[i::3]) for i in range(3)]

T = bytes_to_mat(TARGET)


def compute(_s):
    pass


# Very likely invertible
if np.linalg.cond(C) < 1 / sys.float_info.epsilon:
    print(np.linalg.inv(C) @ C)

# # Brute-force!
# L, U = ord(' '), ord('~')
#
# MAX_N = 1 << 3
#
# # Initialize memorize
# C_map = {
#     1: C @ C
# }
# for i in range(2, MAX_N + 1):
#     C_map[i] = C_map[i - 1] @ C
# T_map = {}
# for i in range(1, MAX_N + 1):
#     T_map[i] = (C_map[i] + T) % 2
# del C_map
#
# n = 20
# key_map = {
#     i: {} for i in range(1, n + 1)
# }
# for i in range(1, n + 1):
#     for c in range(0, 1 << i):
#         r = np.eye(16, dtype=int)
#         s = f'{c:0{i}b}'
#         for b in s:
#             if b == '0':
#                 r = r @ A
#             else:
#                 r = r @ B
#         r %= 2
#         if np.all(r == np.eye(16, dtype=int)):
#             print(r)
#             print(f'Found identity matrix with {s}!')
#         key_map[i][s] = r
#     print(i)
# print('finish keymap')
#
# # # No 2 char result in same matrix almost every time
# # E = np.zeros((256, 256), dtype=int)
# # for i in range(256):
# #     for j in range(i + 1, 256):
# #         E[i, j] = np.all(key_map[i] == key_map[j])
# # print(E)
# # print(np.any(E))
# target_bits = '{:0256b}'.format(int.from_bytes(TARGET, 'big'))
# # cands = []
# for i in range(1, n + 1):
#     cands = list(set(target_bits[j:j + i] for j in range(256 - i)))
#     _l = len(cands)
#     E = np.zeros((_l, _l), dtype=int)
#     for _i in range(_l):
#         for _j in range(_i + 1, _l):
#             E[_i, _j] = np.all(key_map[i][cands[_i]] == key_map[i][cands[_j]])
#     # print(E)
#     print(np.any(E))
# # print(len(cands))
