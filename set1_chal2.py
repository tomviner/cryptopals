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

from set1_chal1 import decode_hex


def hex_xor(h1, h2):
    i1 = int(h1, base=16)
    i2 = int(h2, base=16)
    # use format to avoid 0x prefix
    # ^ is xor operator
    return '{:x}'.format(i1 ^ i2)


def test_hex_xor_from_binary():
    """
    binary XOR example:
    bin(0b1010 ^ 0b0011) == '0b1001'
    (10 ^ 3) == 9
    (0xa ^ 0x3) == 0x9
    """
    assert hex_xor('a', '3') == '9'

def test_hex_xor_easy():
    # everything here is hex
    # last digits from example below
    result = hex_xor('c', '5')
    expected = '9'
    assert result == expected

def test_hex_xor_example():
    # everything is hex here
    # input1 doesn't appear to be an encoded readable string
    input1 = '1c0111001f010100061a024b53535009181c'
    input2 = '686974207468652062756c6c277320657965'
    assert decode_hex(input2) == "hit the bull's eye"
    result = hex_xor(input1, input2)
    expected = '746865206b696420646f6e277420706c6179'
    assert decode_hex(result) == "the kid don't play"
    assert result == expected
