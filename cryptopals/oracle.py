import random

from .aes import encrypt_cbc, encrypt_ecb
from .utils import pad


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
