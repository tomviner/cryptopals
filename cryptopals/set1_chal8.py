"""
Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic;
the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
"""

from collections import Counter
from itertools import izip_longest


# From http://stackoverflow.com/a/312644/15890
def grouper(n, iterable, padvalue=None):
    "grouper(3, 'abcdefg', 'x') --> ('a','b','c'), ('d','e','f'), ('g','x','x')"
    return izip_longest(*[iter(iterable)]*n, fillvalue=padvalue)


def get_uniq_block_counts(cipher_lines):
    return {
        line: len(set(map(''.join, grouper(16, line))))
        for line in cipher_lines
    }

def detect_ecb(line_to_uniq_chunks):
    ecb_line = min(line_to_uniq_chunks, key=line_to_uniq_chunks.get)
    return ecb_line, line_to_uniq_chunks[ecb_line]


def test_detect_ecb():
    block_len = 16
    cipher_lines = open('cryptopals/set1_chal8.txt', 'rb').read().splitlines()
    line_to_uniq_chunk_count = get_uniq_block_counts(cipher_lines)
    num_uniq_blocks = line_to_uniq_chunk_count.values()
    # if each line can fit 20 blocks of 16 bytes, we expect one line
    # to have fewer than 20 unique blocks, and the rest no uniques,
    # hence the full 20 unique blocks out of 20
    blocks_long = len(cipher_lines[0]) / block_len
    # this tells us one line has just 14/20 unique blocks, in other words
    # it has repeat blocks of 16 bytes
    uniq_blocks_in_detected_line = 14
    assert dict(Counter(num_uniq_blocks)) == {
        uniq_blocks_in_detected_line: 1,
        blocks_long: len(cipher_lines)-1
    }
    ecb_line, uniq_chunks = detect_ecb(line_to_uniq_chunk_count)
    assert uniq_chunks == uniq_blocks_in_detected_line
    assert ecb_line == (
        'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd05'
        '2f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1'
        'd46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566'
        '489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c'
        '4040deb0ab51b29933f2c123c58386b06fba186a')
