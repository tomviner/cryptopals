"""
Convert hex to base64
The string:

49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

Cryptopals Rule
Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
"""
from __future__ import unicode_literals

from base64 import b16decode, b64encode


def decode_hex(input_hex):
    return b16decode(input_hex.upper(), casefold=True)

def hex_to_base64(input_hex):
    string = decode_hex(input_hex)
    return b64encode(string)


def test_hex_to_base64_easy():
    input_hex = b'78797A'
    assert decode_hex(input_hex) == b'xyz'
    expected_b64 = b'eHl6'
    assert hex_to_base64(input_hex) == expected_b64

def test_hex_to_base64_example():
    input_hex = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    assert decode_hex(input_hex) == b"I'm killing your brain like a poisonous mushroom"
    expected_b64 = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert hex_to_base64(input_hex) == expected_b64
