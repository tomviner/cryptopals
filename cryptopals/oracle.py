import random

from .aes import encrypt_cbc, encrypt_ecb
from .utils import grouper, pad, random_bytes


def encryption_oracle(plaintext):
    password = random_bytes(16)
    n1 = random.randint(5, 10)
    n2 = random.randint(5, 10)
    buffered = '{}{}{}'.format(
        random_bytes(n1), plaintext, random_bytes(n2))
    final_plaintext = pad(buffered, 16)
    use_ecb = bool(random.randint(0, 1))
    if use_ecb:
        return encrypt_ecb(final_plaintext, password)
    else:
        iv = random_bytes(16)
        return encrypt_cbc(final_plaintext, password, iv)


def detect_cipher(encryption_func):
    plaintext = random_bytes(16) * 3
    ciphertext = encryption_func(plaintext)
    blocks = list(grouper(16, ciphertext))
    num_uniq_blocks = len(set(blocks))
    return num_uniq_blocks < len(blocks)
