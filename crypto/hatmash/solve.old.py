from pwn import *
import numpy as np
import pprint


def bytes_to_mat(x):
    # assert len(x) == 32
    _bits = list('{:0256b}'.format(int.from_bytes(x, 'big')))
    _bits = [int(b) for b in _bits]
    return np.array(_bits, dtype=int).reshape(16, 16)


def chr_to_mat(c, A, B):
    r = np.eye(16, dtype=int)
    s = f'{c:08b}'
    for b in s:
        if b == '0':
            r = r @ A
        else:
            r = r @ B
    return r % 2


def mash(x, A, B, C, T):
    """
    The mash function finally turns out to check

    {A, B}^(8n) + C^(n+1) == T

    And all matrix operations are defined for logical matrices
    https://en.wikipedia.org/wiki/Logical_matrix
    """
    bits = list('{:0{n}b}'.format(int.from_bytes(x, 'big'), n=8 * len(x)))
    if bits.pop(0) == '0':
        ret = A
    else:
        ret = B
    for bit in bits:
        if bit == '0':
            ret = (ret @ A) % 2
        else:
            ret = (ret @ B) % 2
    lenC = C
    for _ in range(len(x)):
        lenC = (lenC @ C) % 2

    # A + B is equivalent to A XOR B for A, B logical matrices
    return not (ret ^ lenC ^ T).any()


def multi_order(mat, max_iter=int(1e4)):
    """
    Compute the multiplicative order of matrix mat s.t.

    mat^i == mat

    Then i-1 is the multi. order
    """
    r = mat
    for i in range(max_iter):
        r = (r @ mat) % 2

        if (r == mat).all():
            return i + 1
    return -1


ALP = range(ord(' '), ord('~'))
TARGET_PASS = b"gib m3 flag plox?"


def main():
    """
    The idea is to
    1. find a character in b"ib m3 flag plox", let's use 'f' for example,
       compute the multi. order of the matrix that corresponding to it,
       denoted `m`.
    2. compute the multi. order of C, denoted `n`.

    Since the mash check the following equation

    {A, B}^(8n) + C^(n+1) == T

    Inserting (m-1) times 'f' right before 'f' won't change {A, B}^(8n) since
    matrix multiplication is associative. But it breaks C^(n+1)

    So we need to insert the least common multiple of m-1 and n-1 times 'f'
    instead.

    Another issue is sometimes the multi. order are all too large, and it would
    take the server several minutes to do the naive implementation of matrix
    multiplication. In this case we just run multiple times and hope we could
    end up with a small enough multi. order.
    """
    log.info('*' * 120)
    log.info('Start a new try!')
    log.info('-' * 50)

    # Change here to run locally
    local = False

    if local:
        io = process(['python3', 'hatmash.py'])
    else:
        # host = '34.139.216.197'
        host = 'localhost'
        port = 10001
        io = remote(host, port)

    io.recvuntil(b'KEY: ')
    KEY = unhex(io.recvline().strip())
    io.recvuntil(b'TARGET: ')
    TARGET = unhex(io.recvline().strip())

    log.info(f'KEY: {KEY}')
    log.info(f'TARGET: {TARGET}')

    A, B, C = [bytes_to_mat(KEY[i::3]) for i in range(3)]

    T = bytes_to_mat(TARGET)

    mo_map = {}
    mo_C = multi_order(C)
    log.info('-' * 50)

    if mo_C == -1:
        log.info(f'multi. order of C: {mo_C}')
        log.warn('Multiplicative order of C too large, good luck next time!')
        log.info('-' * 50)
        io.close()
        return

    for c in set(TARGET_PASS[:-1]):
        r = multi_order(chr_to_mat(c, A, B))
        if r != -1:
            mo_map[chr(c)] = r

    log.info('multi. oder table')
    log.info(pprint.pformat(mo_map))

    if len(mo_map) == 0:
        log.warn('Multiplicative order of all possible input char are too '
                 'large, good luck next time!')
        io.close()
        return

    # Use the char with the smallest multi. order
    target_chr = min(mo_map, key=mo_map.get)
    target_mo = mo_map[target_chr]
    target_idx = TARGET_PASS.rindex(target_chr.encode())

    log.info(
        f'Using {target_chr} at index {target_idx} as target char with multi. '
        f'order of {target_mo}'
    )
    log.info('-' * 50)

    log.info(f'multi. order of {target_chr}: {target_mo}')
    log.info(f'multi. order of C: {mo_C}')

    # Compute the least common multiple
    lcm_mo = np.lcm(target_mo, mo_C)
    log.info(f'LCM of mo_chr and mo_C: {lcm_mo}')

    # Try a new one if the payload is going to be huge
    if lcm_mo > (1 << 16):  # approx. 64000
        log.warn('Payload too large! Do another one.')
        log.info('-' * 50)

        io.close()
        return

    payload = TARGET_PASS[:target_idx]
    payload += lcm_mo * target_chr.encode()
    payload += TARGET_PASS[target_idx:]

    log.info(f'Pass self check: {mash(payload, A, B, C, T)}')

    log.info('-' * 50)
    log.info(f'Sending {len(payload)} bytes payloads')

    io.sendline(payload)
    print(io.recv())  # CAPTURE THE FLAG!!!
    exit(0)


if __name__ == '__main__':
    while True:
        main()
