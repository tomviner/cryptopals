# -*- coding: utf-8 -*-
import pytest

from .aes import (
    _decrypt_cbc,
    _encrypt_cbc,
    decrypt_cbc,
    decrypt_ecb,
    encrypt_cbc,
    encrypt_ecb,
)
from .utils import pad


def test_aes_ecb():
    # both multiples of 16 bytes
    plaintext = 'message with data, £ & secrets.'.encode()
    password = b'1234567890123456'
    ciphertext = encrypt_ecb(plaintext, password)
    decrypted = decrypt_ecb(ciphertext, password)
    assert decrypted == plaintext


@pytest.mark.parametrize('n', range(7))
def test_padding(n):
    block_size = 3
    plaintext = b"message"[:n]
    plaintext_padded = pad(plaintext, block_size)
    m = len(plaintext_padded)
    assert m % block_size == 0


@pytest.mark.parametrize('n', range(20))
def test_aes_cbc__my_cbc_en(n):
    orig_plaintext = 'this is my message, cost=£££'.encode()
    plaintext = orig_plaintext[: len(orig_plaintext) - n]
    password = b'1234567890123456'
    plaintext_padded = pad(plaintext, 16)
    assert len(plaintext_padded) % 16 == 0
    ciphertext = encrypt_cbc(plaintext_padded, password)
    decrypted = _decrypt_cbc(ciphertext, password)
    assert decrypted == plaintext


@pytest.mark.parametrize('n', range(20))
def test_aes_cbc__my_cbc_de(n):
    orig_plaintext = 'this is my message, cost=£££'.encode()
    plaintext = orig_plaintext[: len(orig_plaintext) - n]
    password = b'1234567890123456'
    plaintext_padded = pad(plaintext, 16)
    assert len(plaintext_padded) % 16 == 0
    ciphertext = _encrypt_cbc(plaintext_padded, password)
    decrypted = decrypt_cbc(ciphertext, password)
    assert decrypted == plaintext


@pytest.mark.parametrize('n', range(20))
def test_aes_cbc(n):
    orig_plaintext = 'this is my message, cost=£££'.encode()
    plaintext = orig_plaintext[: len(orig_plaintext) - n]
    password = b'1234567890123456'
    plaintext_padded = pad(plaintext, 16)
    assert len(plaintext_padded) % 16 == 0
    ciphertext = encrypt_cbc(plaintext_padded, password)
    decrypted = decrypt_cbc(ciphertext, password)
    assert decrypted == plaintext
