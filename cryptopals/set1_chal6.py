"""
Break repeating-key XOR
It is officially on, now.
This challenge isn't conceptually hard, but it involves actual error-prone coding.
The other challenges in this set are there to bring you up to speed.
This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two strings.
The Hamming distance is just the number of differing bits. The distance between:

this is a test
and
wokka wokka!!!

is 37. Make sure your code agrees before you proceed.
For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed
perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and
average the distances.
Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
Now transpose the blocks: make a block that is the first byte of every block, and a block that
is the second byte of every block, and so on.
Solve each block as if it was single-character XOR. You already have code to do this.
For each block, the single-byte XOR key that produces the best looking histogram is the
repeating-key XOR key byte for that block. Put them together and you have the key.
This code is going to turn out to be surprisingly useful later on. Breaking repeating-key
XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But
more people "know how" to break it than can actually break it, and a similar technique breaks
something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the other ones. We promise,
there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance
really is 37.
"""
from __future__ import division

from base64 import *


def str_to_bin(s):
    result_int = int(b16encode(s), 16)
    # use format to avoid 0x prefix
    # pad with leading zeros,
    return '{:0{}b}'.format(result_int, 8*len(s))

def hamming_distance(str1, str2):
    # no support for differing length inputs at the moment
    assert len(str1) == len(str2)
    return len([
        None for bit1, bit2 in zip(str_to_bin(str1), str_to_bin(str2))
        if bit1 != bit2])

def keysize_to_hamming_distance(keysize, text):
    block_distances = [
        # compare blocks 0:2 v 2:4, 2:4 v 4:6
        hamming_distance(
            text[keysize*n:keysize*n+keysize], text[keysize*n+keysize:keysize*n+keysize*2]
        ) / keysize
        for n in range(20)
    ]
    return sum(block_distances) / len(block_distances)

def best_keysize_via_hamming_distance(bytes_encrypted):
    return min(
        range(2, 41),
        key=lambda keysize: keysize_to_hamming_distance(keysize, bytes_encrypted)
    )

def test_keysize_to_hamming_distance():
    b64_encrypted = open('cryptopals/set1_chal6.txt', 'rb').read()
    bytes_encrypted = b64decode(b64_encrypted)
    best_keysize = best_keysize_via_hamming_distance(bytes_encrypted)
    assert best_keysize == 29

def test_str_to_bin_simple():
    # ord('A') == 65 == 0b1000001
    assert str_to_bin('A') == '01000001'
    assert str_to_bin('?') == '00111111'

def test_hamming_example():
    assert hamming_distance('this is a test', 'wokka wokka!!!') == 37

def test_hamming_identity():
    assert hamming_distance('identity $%^', 'identity $%^') == 0

def test_hamming_zero_truncation():
    # 00111111', 01000001
    assert hamming_distance('?', 'A') == 6
