"""
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
"""
from __future__ import unicode_literals

from base64 import b16encode

from cryptopals.set1_chal2 import decode_hex, hex_xor
from cryptopals.set1_chal3 import (select_most_englishest, simple_score,
                        single_letter_xor_plaintexts)


def decrypt_single_character_xor_from_file(filename='cryptopals/set1_chal4_data.txt'):
    encrypted_lines_hex = open(filename).read().splitlines()
    plaintext_map = {
        plaintext: (hex_string, letter)
        for hex_string in encrypted_lines_hex
        for plaintext, letter in single_letter_xor_plaintexts(hex_string).items()
    }
    plaintext = select_most_englishest(plaintext_map.keys(), score_func=simple_score)
    return plaintext_map[plaintext], plaintext


def test_decrypt_single_character_xor_from_file():
    (hex_string, letter), plaintext = decrypt_single_character_xor_from_file()
    expected_answer = b"Now that the party is jumping\n"
    expected_single_char = b'5'
    assert plaintext == expected_answer
    assert letter == expected_single_char
    assert hex_string == b'7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f'

    expected_answer_hex = b16encode(expected_answer).lower()
    n = len(decode_hex(expected_answer_hex))
    # check answer, using the fact that if encryp^char=plain then plain^char=encryp
    encryped_hex = hex_xor(expected_answer_hex, b16encode(n * expected_single_char))
    assert encryped_hex == hex_string
