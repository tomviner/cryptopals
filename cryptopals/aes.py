from Crypto.Cipher import AES


def decrypt_ecb(password, ciphertext):
    """ Python Cryptography Toolkit (pycrypto) """
    crypter = AES.new(password, AES.MODE_ECB)
    return crypter.decrypt(ciphertext)

def encrypt_ecb(password, ciphertext):
    """ Python Cryptography Toolkit (pycrypto) """
    crypter = AES.new(password, AES.MODE_ECB)
    return crypter.encrypt(ciphertext)
