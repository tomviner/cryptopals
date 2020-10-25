"""
Break repeating-key XOR
It is officially on, now.
This challenge isn't conceptually hard, but it involves actual error-prone coding.
The other challenges in this set are there to bring you up to speed.
This one is there to qualify you. If you can do this one, you're probably just fine up
to Set 6.

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
For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of
bytes,
and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
The KEYSIZE with the smallest normalized edit distance is probably the key. You could
proceed
perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and
average the distances.
Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE
length.
Now transpose the blocks: make a block that is the first byte of every block, and a
block that
is the second byte of every block, and so on.
Solve each block as if it was single-character XOR. You already have code to do this.
For each block, the single-byte XOR key that produces the best looking histogram is the
repeating-key XOR key byte for that block. Put them together and you have the key.
This code is going to turn out to be surprisingly useful later on. Breaking
repeating-key
XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing.
But
more people "know how" to break it than can actually break it, and a similar technique
breaks
something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the other ones. We
promise,
there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit
distance
really is 37.
"""
from __future__ import division

import re
from base64 import b16encode, b64decode
from textwrap import dedent

from .chal1 import decode_hex
from .chal4 import decrypt_single_character_xor
from .chal5 import repeating_key_xor


def str_to_bin(s):
    result_int = int(b16encode(s), 16)
    # use format to avoid 0x prefix
    # pad with leading zeros,
    return '{:0{}b}'.format(result_int, 8 * len(s))


def hamming_distance(str1, str2):
    # no support for differing length inputs at the moment
    assert len(str1) == len(str2)
    return len(
        [None for bit1, bit2 in zip(str_to_bin(str1), str_to_bin(str2)) if bit1 != bit2]
    )


def keysize_to_hamming_distance(keysize, text):
    block_distances = [
        # compare blocks 0:2 v 2:4, 2:4 v 4:6
        hamming_distance(
            text[keysize * n : keysize * n + keysize],
            text[keysize * n + keysize : keysize * n + keysize * 2],
        )
        / keysize
        for n in range(10)
    ]
    return sum(block_distances) / len(block_distances)


def best_keysize_via_hamming_distance(bytes_encrypted):
    return min(
        range(2, 41),
        key=lambda keysize: keysize_to_hamming_distance(keysize, bytes_encrypted),
    )


def skips_by_keysize(s, keysize):
    return [s[start::keysize] for start in range(keysize)]


def decrypt_repeating_key_xor(bytes_encrypted):
    best_keysize = best_keysize_via_hamming_distance(bytes_encrypted)
    skips_blocks = skips_by_keysize(bytes_encrypted, best_keysize)

    letters = list(
        zip(*[decrypt_single_character_xor(b16encode(block)) for block in skips_blocks])
    )[1]
    key = b''.join(letters)
    return key, decode_hex(repeating_key_xor(bytes_encrypted, key))


def test_skips_by_keysize_simple():
    s = '0123456789'
    zipped = ['0369', '147', '258']
    assert skips_by_keysize(s, 3) == zipped


def test_str_to_bin_simple():
    # ord('A') == 65 == 0b1000001
    assert str_to_bin(b'A') == '01000001'
    assert str_to_bin(b'?') == '00111111'


def test_hamming_example():
    assert hamming_distance(b'this is a test', b'wokka wokka!!!') == 37


def test_hamming_identity():
    assert hamming_distance(b'identity $%^', b'identity $%^') == 0


def test_hamming_zero_truncation():
    # 00111111', 01000001
    assert hamming_distance(b'?', b'A') == 6


def test_keysize_to_hamming_distance_example():
    """
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 2 3.25
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 3 3.26666666667
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 4 3.365
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 5 3.224
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 6 3.35
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 7 3.25428571429
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 8 3.2925
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 9 3.20444444444
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 10 3.28
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 11 3.16727272727
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 12 3.21666666667
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 13 3.15846153846
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 14 3.25142857143
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 15 3.136
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 16 3.19625
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 17 3.23647058824
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 18 3.19555555556
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 19 3.31368421053
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 20 3.153
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 21 3.19714285714
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 22 3.19545454545
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 23 3.28347826087
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 24 3.2975
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 25 3.164
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 26 3.26307692308
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 27 3.29925925926
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 28 3.27285714286
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 29 2.71655172414
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 30 3.24266666667
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 31 3.21483870968
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 32 3.2
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 33 3.16181818182
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 34 3.26117647059
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 35 3.26971428571
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 36 3.20111111111
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 37 3.22648648649
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 38 3.14736842105
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 39 3.24717948718
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 40 3.1455
    """
    b64_encrypted = open('cryptopals/set1/chal6.txt', 'rb').read()
    bytes_encrypted = b64decode(b64_encrypted)
    best_keysize = best_keysize_via_hamming_distance(bytes_encrypted)
    assert best_keysize == 29


def test_skips_by_keysize():
    b64_encrypted = open('cryptopals/set1/chal6.txt', 'rb').read()
    bytes_encrypted = b64decode(b64_encrypted)
    best_keysize = best_keysize_via_hamming_distance(bytes_encrypted)
    skips_blocks = skips_by_keysize(bytes_encrypted, best_keysize)
    assert len(skips_blocks) == 29

    key, plaintext = decrypt_repeating_key_xor(bytes_encrypted)
    assert key == b'Terminator X: Bring the noise'
    expected = dedent(
        """
        I'm back and I'm ringin' the bell
        A rockin' on the mike while the fly girls yell
        In ecstasy in the back of me
        Well that's my DJ Deshay cuttin' all them Z's
        Hittin' hard and the girlies goin' crazy
        Vanilla's on the mike, man I'm not lazy.

        I'm lettin' my drug kick in
        It controls my mouth and I begin
        To just let it flow, let my concepts go
        My posse's to the side yellin', Go Vanilla Go!

        Smooth 'cause that's the way I will be
        And if you don't give a damn, then
        Why you starin' at me
        So get off 'cause I control the stage
        There's no dissin' allowed
        I'm in my own phase
        The girlies sa y they love me and that is ok
        And I can dance better than any kid n' play

        Stage 2 -- Yea the one ya' wanna listen to
        It's off my head so let the beat play through
        So I can funk it up and make it sound good
        1-2-3 Yo -- Knock on some wood
        For good luck, I like my rhymes atrocious
        Supercalafragilisticexpialidocious
        I'm an effect and that you can bet
        I can take a fly girl and make her wet.

        I'm like Samson -- Samson to Delilah
        There's no denyin', You can try to hang
        But you'll keep tryin' to get my style
        Over and over, practice makes perfect
        But not if you're a loafer.

        You'll get nowhere, no place, no time, no girls
        Soon -- Oh my God, homebody, you probably eat
        Spaghetti with a spoon! Come on and say it!

        VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino
        Intoxicating so you stagger like a wino
        So punks stop trying and girl stop cryin'
        Vanilla Ice is sellin' and you people are buyin'
        'Cause why the freaks are jockin' like Crazy Glue
        Movin' and groovin' trying to sing along
        All through the ghetto groovin' this here song
        Now you're amazed by the VIP posse.

        Steppin' so hard like a German Nazi
        Startled by the bases hittin' ground
        There's no trippin' on mine, I'm just gettin' down
        Sparkamatic, I'm hangin' tight like a fanatic
        You trapped me once and I thought that
        You might have it
        So step down and lend me your ear
        '89 in my time! You, '90 is my year.

        You're weakenin' fast, YO! and I can tell it
        Your body's gettin' hot, so, so I can smell it
        So don't be mad and don't be sad
        'Cause the lyrics belong to ICE, You can call me Dad
        You're pitchin' a fit, so step back and endure
        Let the witch doctor, Ice, do the dance to cure
        So come up close and don't be square
        You wanna battle me -- Anytime, anywhere

        You thought that I was weak, Boy, you're dead wrong
        So come on, everybody and sing this song

        Say -- Play that funky music Say, go white boy, go white boy go
        play that funky music Go white boy, go white boy, go
        Lay down and boogie and play that funky music till you die.

        Play that funky music Come on, Come on, let me hear
        Play that funky music white boy you say it, say it
        Play that funky music A little louder now
        Play that funky music, white boy Come on, Come on, Come on
        Play that funky music
    """
    )
    # my editor kills spaces at end of line, so put them back
    expected = re.sub(r'(\n+)', r' \1', expected).lstrip().encode()
    assert plaintext == expected
