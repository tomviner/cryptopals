"""
An ECB/CBC detection oracle
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random
 bytes.

Write a function that encrypts data under an unknown key --- that is,
a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen
 randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and
 under CBC the other half (just use random IVs each time for CBC). Use
 rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You
should end up with a piece of code that, pointed at a block box
that might be encrypting ECB or CBC, tells you which one is happening.
"""

import random

import pytest

from .aes import encrypt_cbc, encrypt_ecb, grouper, pad


def random_bytes(n):
    return ''.join(
        unichr(random.choice(xrange(2**8)))
        for _ in xrange(n)).encode('utf-8')[:n]

def encryption_oracle(plaintext, use_ecb=None):
    password = random_bytes(16)
    n1 = random.randint(5, 10)
    n2 = random.randint(5, 10)
    buffered = '{}{}{}'.format(
        random_bytes(n1), plaintext, random_bytes(n2))
    final_plaintext = pad(buffered, 16)
    use_ecb = random.randint(2) if use_ecb is None else use_ecb
    if use_ecb:
        return encrypt_ecb(final_plaintext, password)
    else:
        iv = random_bytes(16)
        return encrypt_cbc(final_plaintext, password, iv)


def test_random_bytes():
    assert len(random_bytes(16)) == 16

@pytest.mark.parametrize('use_ecb', 5 * (True, False))
def test_encryption_oracle(use_ecb):
    plaintext = random_bytes(16) * 3
    ciphertext = encryption_oracle(plaintext, use_ecb)
    blocks = list(grouper(16, ciphertext))
    num_uniq_blocks = len(set(blocks))
    detect_ecb = num_uniq_blocks < len(blocks)
    assert use_ecb == detect_ecb
