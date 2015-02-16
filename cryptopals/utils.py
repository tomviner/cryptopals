from base64 import b16encode
from itertools import chain, izip, repeat

from .set1_chal1 import decode_hex

PAD_CHAR = '\x04'


def hex_xor(h1, h2):
    n1 = len(h1)
    n2 = len(h2)
    assert n1 == n2
    # no support for differing length inputs at the moment
    i1 = int(h1, base=16)
    i2 = int(h2, base=16)
    # ^ is XOR operator
    result_int = i1 ^ i2
    # use format to avoid 0x prefix
    # pad with leading zeros, to match length of input
    return '{:0{}x}'.format(result_int, n1)


def xor(bs1, bs2):
    n1 = len(bs1)
    n2 = len(bs2)
    # no support for differing length inputs at the moment
    assert n1 == n2
    hex_res = hex_xor(b16encode(bs1), b16encode(bs2))
    return decode_hex(hex_res)


def pad(plaintext, block_size, pad_char=PAD_CHAR):
    n = block_size - (len(plaintext) % block_size)
    return '{}{}'.format(plaintext, n*pad_char)


def grouper(n, iterable, padvalue=PAD_CHAR):
    "grouper(3, 'abcdefg', 'x') --> ('a','b','c'), ('d','e','f'), ('g','x','x')"
    groups = izip(*[chain(iterable, repeat(padvalue, n-1))]*n)
    return (''.join(group) for group in groups)
