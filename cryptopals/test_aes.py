from .aes import encrypt_ecb, decrypt_ecb


def test_aes_ecb():
    # both multiples of 16 bytes
    plaintext = 'this is my message with secrets!'
    password = '1234567890123456'
    ciphertext = encrypt_ecb(password, plaintext)
    decrypted = decrypt_ecb(password, ciphertext)
    assert decrypted == plaintext
