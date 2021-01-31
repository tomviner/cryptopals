"""
Implement repeating-key XOR
Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key;
the first byte of plaintext will be XOR'd against I, the next C, the next E, then I
again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function.
Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it.
I promise, we aren't wasting your time with this.
"""

from base64 import b16encode
from itertools import cycle
from textwrap import dedent

from ..utils import xor_hex


def repeating_key_xor(plaintext, key):
    key_gen = cycle(key)

    return ''.join(
        xor_hex(b16encode(bytes([char])), b16encode(bytes([key_char])))
        for char, key_char in zip(plaintext, key_gen)
    ).encode()


def test_repeating_key_xor_example():
    plaintext = (
        dedent(
            """
            Burning 'em, if you ain't quick and nimble
            I go crazy when I hear a cymbal
            """
        )
        .strip()
        .encode()
    )
    key = b'ICE'
    result = repeating_key_xor(plaintext, key)
    expected = (
        b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
        b"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )
    assert result == expected


def test_repeating_key_xor_identity():
    # x ^ x is always 0
    int(repeating_key_xor(b'barbar', b'bar'), 16) == 0


def test_repeating_key_xor_simple():
    # test plaintext='pt' and key='k'
    int_result = int(repeating_key_xor(b'pt', b'k'), 16)
    expected = (ord('p') ^ ord('k')) * 16 ** 2 + ord('t') ^ ord('k')
    assert int_result == expected
