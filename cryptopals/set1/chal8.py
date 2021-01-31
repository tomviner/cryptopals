"""
Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic;
the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
"""

import re
from collections import Counter
from itertools import zip_longest


# From http://stackoverflow.com/a/312644/15890
def grouper(n, iterable, padvalue=None):
    "grouper(3, 'abcdefg', 'x') --> ('a','b','c'), ('d','e','f'), ('g','x','x')"
    return zip_longest(*[iter(iterable)] * n, fillvalue=padvalue)


def get_uniq_block_counts(cipher_lines):
    return {line: len(set(map(bytes, grouper(16, line)))) for line in cipher_lines}


def detect_ecb(line_to_uniq_chunks):
    ecb_line = min(line_to_uniq_chunks, key=line_to_uniq_chunks.get)
    return ecb_line, line_to_uniq_chunks[ecb_line]


def test_detect_ecb():
    block_len = 16
    cipher_lines = open('cryptopals/set1/chal8.txt', 'rb').read().splitlines()
    line_to_uniq_chunk_count = get_uniq_block_counts(cipher_lines)
    num_uniq_blocks = line_to_uniq_chunk_count.values()
    # if each line can fit 20 blocks of 16 bytes, we expect one line
    # to have fewer than 20 unique blocks, and the rest no uniques,
    # hence the full 20 unique blocks out of 20
    blocks_long = len(cipher_lines[0]) / block_len
    # this tells us one line has just 14/20 unique blocks, in other words
    # it has repeat blocks of 16 bytes
    num_uniq_blocks_in_detected_line = 14
    assert dict(Counter(num_uniq_blocks)) == {
        num_uniq_blocks_in_detected_line: 1,
        blocks_long: len(cipher_lines) - 1,
    }
    ecb_line, num_uniq_chunks = detect_ecb(line_to_uniq_chunk_count)
    assert num_uniq_chunks == num_uniq_blocks_in_detected_line

    assert ecb_line == (
        b'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd05'
        b'2f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1'
        b'd46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566'
        b'489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c'
        b'4040deb0ab51b29933f2c123c58386b06fba186a'
    )

    repeat_regex = r"""
        (.{16})(.{16})(.{16})(.{16})
        (.{16})(.{16})\3\4
        (.{16})(.{16})\3\4
        (.{16})(.{16})\3\4
        (.{16})(.{16})(.{16})(.{16})
    """

    assert re.match(repeat_regex, ecb_line.decode(), re.VERBOSE)

    example_pattern = (
        b'<-- Block: a --><-- Block: b --><-- Block: c --><-- Block: d -->'
        b'<-- Block: e --><-- Block: f --><-- Block: c --><-- Block: d -->'
        b'<-- Block: g --><-- Block: h --><-- Block: c --><-- Block: d -->'
        b'<-- Block: i --><-- Block: j --><-- Block: c --><-- Block: d -->'
        b'<-- Block: k --><-- Block: l --><-- Block: m --><-- Block: n -->'
    )

    assert re.match(repeat_regex, example_pattern.decode(), re.VERBOSE)
