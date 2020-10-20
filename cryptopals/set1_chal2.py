"""
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:


746865206b696420646f6e277420706c6179
"""

from .set1_chal1 import decode_hex
from .utils import hex_xor


def test_hex_xor_example():
    # everything is hex here
    # input1 doesn't appear to be an encoded readable string
    input1 = '1c0111001f010100061a024b53535009181c'
    input2 = '686974207468652062756c6c277320657965'
    assert decode_hex(input2) == b"hit the bull's eye"
    result = hex_xor(input1, input2)
    expected = '746865206b696420646f6e277420706c6179'
    assert decode_hex(result) == b"the kid don't play"
    assert result == expected
