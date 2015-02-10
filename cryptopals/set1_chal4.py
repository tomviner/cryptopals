"""
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
"""

from base64 import b16encode

from .set1_chal2 import decode_hex, hex_xor
from .set1_chal3 import (select_most_englishest, simple_score,
                         single_letter_xor_plaintexts)


def decrypt_single_character_xor(encrypted_hex):
    """ return (hex_string, letter, message plaintext) tuple
    """
    encrypted_lines_hex = encrypted_hex.splitlines()
    plaintext_map = {
        plaintext: (hex_string, letter)
        for hex_string in encrypted_lines_hex
        for plaintext, letter in single_letter_xor_plaintexts(hex_string).items()
    }
    plaintext = select_most_englishest(plaintext_map.keys(), score_func=simple_score)
    hex_string, letter = plaintext_map[plaintext]
    return hex_string, letter, plaintext


def test_decrypt_single_character_xor_from_file():
    filename = 'cryptopals/set1_chal4_data.txt'
    encrypted_hex = open(filename).read()
    hex_string, letter, plaintext = decrypt_single_character_xor(encrypted_hex)
    expected_answer = "Now that the party is jumping\n"
    expected_single_char = '5'
    assert plaintext == expected_answer
    assert letter == expected_single_char
    assert hex_string == '7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f'

    expected_answer_hex = b16encode(expected_answer).lower()
    n = len(decode_hex(expected_answer_hex))
    # check answer, using the fact that if encryp^char=plain then plain^char=encryp
    encryped_hex = hex_xor(expected_answer_hex, b16encode(n * expected_single_char))
    assert encryped_hex == hex_string
