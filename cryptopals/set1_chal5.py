"""
Implement repeating-key XOR
Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key;
the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function.
Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it.
I promise, we aren't wasting your time with this.
"""

from base64 import b16encode
from itertools import cycle, izip
from textwrap import dedent

from .set1_chal2 import hex_xor


def repeating_key_xor(plaintext, key):
    key_gen = cycle(key)

    return ''.join(
        hex_xor(b16encode(char), b16encode(key_char))
        for char, key_char in izip(plaintext, key_gen)
    )


def test_repeating_key_xor_example():
    plaintext = dedent("""
        Burning 'em, if you ain't quick and nimble
        I go crazy when I hear a cymbal
    """).strip()
    key = 'ICE'
    result = repeating_key_xor(plaintext, key)
    expected = (
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    assert result == expected

def test_repeating_key_xor_identity():
    # x ^ x is always 0
    int(repeating_key_xor('barbar', 'bar'), 16) == 0

def test_repeating_key_xor_simple():
    # test plaintext='pt' and key='k'
    int_result = int(repeating_key_xor('pt', 'k'), 16)
    expected = (ord('p') ^ ord('k')) * 16**2 + ord('t') ^ ord('k')
    assert int_result == expected
