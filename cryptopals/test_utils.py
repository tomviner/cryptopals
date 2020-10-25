from .set1.chal1 import decode_hex
from .utils import hex_xor


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


def test_short_output_padding():
    """
    If the initial bits are the same, the XOR result is shorter
    >>> bin(0b01110011 ^ 0b01111100)
    '0b1111'

    >>> '{:X}'.format(0b1111)
    'F'

    This can break hex decoding:
    >>> from base64 import b16decode
    >>> b16decode('F')
    Traceback (most recent call last):
    ...
    TypeError: Odd-length string
    """
    result = hex_xor(hex(0b01110011), hex(0b01111100))
    # no type error
    decode_hex(result)
