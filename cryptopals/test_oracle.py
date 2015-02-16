import pytest

from .oracle import encryption_oracle, random_bytes
from .utils import grouper


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
