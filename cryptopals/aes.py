# Python Cryptography Toolkit (pycrypto)

from Crypto.Cipher import AES

from .set1_chal1 import decode_hex
from .utils import grouper, hex_xor, xor

PAD_CHAR = '\x04'
IV = '\x00' * AES.block_size



def encrypt_ecb(plaintext, password):
    crypter = AES.new(password, AES.MODE_ECB)
    return crypter.encrypt(plaintext)

def decrypt_ecb(ciphertext, password):
    crypter = AES.new(password, AES.MODE_ECB)
    return crypter.decrypt(ciphertext)


def _encrypt_cbc(plaintext, password):
    # import ipdb; ipdb.set_trace()
    crypter = AES.new(password, AES.MODE_CBC, IV)
    return crypter.encrypt(plaintext)

def _decrypt_cbc(ciphertext, password):
    crypter = AES.new(password, AES.MODE_CBC, IV)
    return crypter.decrypt(ciphertext).rstrip(PAD_CHAR)


def encrypt_cbc(
    plaintext, password, iv=IV, block_size=AES.block_size
):
    # padded_plaintext = pad(plaintext, block_size)
    res = []
    crypt_block = iv
    for plain_block in grouper(block_size, plaintext):
        block = xor(plain_block, crypt_block)
        crypt_block = encrypt_ecb(block, password)
        res.append(crypt_block)
    return ''.join(res)


def decrypt_cbc(
    ciphertext, password, iv=IV, block_size=AES.block_size
):
    res = []
    prev_block = iv
    for cipher_block in grouper(block_size, ciphertext):
        block = decrypt_ecb(cipher_block, password)
        plain_block = xor(block, prev_block)
        res.append(plain_block)
        prev_block = cipher_block
    return ''.join(res).rstrip(PAD_CHAR)
