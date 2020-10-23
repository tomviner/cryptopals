from .aes import encrypt_cbc, encrypt_ecb
from .oracle import detect_cipher, encryption_oracle
from .utils import random_bytes


def test_random_bytes():
    assert len(random_bytes(16)) == 16


def test_oracle(mocker, reproducible_randomness):
    m_encrypt_ecb = mocker.patch(
        'cryptopals.oracle.encrypt_ecb', side_effect=encrypt_ecb
    )
    m_encrypt_cbc = mocker.patch(
        'cryptopals.oracle.encrypt_cbc', side_effect=encrypt_cbc
    )
    ecb_covered, cbc_covered = False, False
    # ensure we cover both types of encryption
    while not ecb_covered or not cbc_covered:
        ecb_used = detect_cipher(encryption_oracle)
        assert ecb_used == m_encrypt_ecb.called
        assert ecb_used != m_encrypt_cbc.called
        ecb_covered = ecb_covered or m_encrypt_ecb.called
        cbc_covered = cbc_covered or m_encrypt_cbc.called
        m_encrypt_ecb.reset_mock()
        m_encrypt_cbc.reset_mock()
