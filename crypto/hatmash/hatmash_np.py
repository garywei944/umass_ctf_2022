#!/usr/bin/env python3
#
# Polymero
#

# Imports
import os
import numpy as np

# Local imports
with open('flag.txt', 'rb') as f:
    FLAG = f.read()


def bytes_to_mat(x):
    assert len(x) == 32
    bits = list('{:0256b}'.format(int.from_bytes(x, 'big')))
    bits = [int(b) for b in bits]
    return np.array(bits).reshape(16, 16)


def mat_to_bytes(x):
    a = int(''.join([str(i) for i in x.flatten()]), 2).to_bytes(
        (len(x) * len(x[0]) + 7) // 8, 'big')
    return a


def mod_mult(a, b, m):
    return (a @ b) % m


def mod_add(a, b, m):
    return (a + b) % m


KEY = os.urandom(32 * 3)
print('KEY:', KEY.hex())

A, B, C = [bytes_to_mat(KEY[i::3]) for i in range(3)]
A, B, C = map(np.array, [A, B, C])


def mash(x):
    bits = list('{:0{n}b}'.format(int.from_bytes(x, 'big'), n=8 * len(x)))
    if bits.pop(0) == '0':
        ret = A
    else:
        ret = B
    for bit in bits:
        if bit == '0':
            ret = mod_mult(ret, A, 2)
        else:
            ret = mod_mult(ret, B, 2)
    lenC = C
    for _ in range(len(x)):
        lenC = mod_mult(lenC, C, 2)
    return mat_to_bytes(mod_add(ret, lenC, 2))


target_hash = mash(b"gib m3 flag plox?").hex()
print('TARGET:', target_hash)

# range(32, 126)
ALP = range(ord(' '), ord('~'))

try:

    user_msg = input().encode()
    assert all(i in ALP for i in list(user_msg))

    if b"gib m3 flag plox?" in user_msg:
        print('Uuh yeah nice try...')

    elif mash(user_msg).hex() == target_hash:
        print('Wow, well I suppose you deserve it {}'.format(FLAG.decode()))

    else:
        print('Not quite, try again...')

except:
    print('Try to be serious okay...')

