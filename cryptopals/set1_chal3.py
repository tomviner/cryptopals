"""
Single-byte XOR cipher
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character.
Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext.
Character frequency is a good metric.
Evaluate each output and choose the one with the best score.

Achievement Unlocked
You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
"""


import csv
import random
import string
from base64 import b16encode


from .set1_chal1 import decode_hex
from .set1_chal2 import hex_xor
from .testing_utils import param_by_functions, reproducible_randomness


# prevent 'imported but unused'
reproducible_randomness


def single_letter_xor_plaintexts(input_hex, character_domain=string.printable):
    """return {message plaintext: letter} dict"""
    n = len(decode_hex(input_hex))
    return {
        decode_hex(hex_xor(input_hex, b16encode((n * letter).encode()))): letter
        for letter in character_domain
    }


def find_xor_plaintext(input_hex):
    plaintext_letter_map = single_letter_xor_plaintexts(input_hex)
    best = select_most_englishest(list(plaintext_letter_map.keys()))
    return plaintext_letter_map[best], best


def get_letter_proportion_map():
    """return {letter: expected occurence proportion} dict

    Data from http://norvig.com/mayzner.html
    """
    with open('cryptopals/ngrams1_any_position.csv') as f:
        rdr = csv.reader(f)
        next(rdr)  # col heading row
        occurence_map = {letter: int(count) for letter, count in rdr}
    total_occurences = sum(occurence_map.values())
    return {
        letter: occurences / total_occurences
        for letter, occurences in occurence_map.items()
    }


def simple_score(text):
    """Count number of unique non-letter* characters

    * honorary_letters allow for common punctuation

    This approach is all you need against random bytes.
    """
    honorary_letters = b" '.,"
    letters = set(string.ascii_letters.encode()) | set(honorary_letters)
    return len(set(text) - letters)


def ord_average(text):
    """Average of the ascii ordinal of each char"""
    ords = [ord(ch) for ch in text.decode()]
    return sum(ords) / len(ords)


def ord_average_score(text):
    """Take the average of the ascii ordinal of each char
    and return the square of the difference to the average
    of the upper/lowercase letters
    """
    letters_av = ord_average(string.ascii_letters.encode())
    text_av = ord_average(text)
    return (letters_av - text_av) ** 2


def letter_freq_score(text, english_proportion_map=get_letter_proportion_map()):
    """Score based on character frequency

    For each letter in `text` + the alphabet, assess how its number
    of occurences differs from that of English language.

    This approach may be needed when plaintexts are jumbled letter
    phrases (as opposed to random bytes).
    """
    n = len(text)
    text = text.decode().upper().replace(' ', '')
    character_domain = set(string.ascii_uppercase) | set(text)
    NON_LETTER_SCORE = 1
    # sum of squares of differences between expected letter counts and actual
    letter_score_map = {
        letter: (
            text.count(letter)
            - n * english_proportion_map.get(letter, NON_LETTER_SCORE)
        )
        ** 2
        for letter in character_domain
    }
    return sum(letter_score_map.values())


def select_most_englishest(texts, score_func=letter_freq_score):
    """Simply pick the text with the lowest score."""
    return min(texts, key=score_func)


scoring_functions = (simple_score, letter_freq_score, ord_average_score)


def param_by_score_functions(xfails=()):
    return param_by_functions('score_func', scoring_functions, xfails)


@param_by_functions('score_func', [simple_score])
def test_score_letter_v_letter_equal(score_func):
    assert score_func(b'aeio') == score_func(b'zqxj')


@param_by_functions('score_func', [letter_freq_score, ord_average_score])
def test_score_letter_v_letter(score_func):
    assert score_func(b'aeio') < score_func(b'zqxj')


@param_by_score_functions()
def test_score_letter_v_punctuation(score_func):
    assert score_func(b'zqxj') < score_func(b'!@#$')


@param_by_score_functions()
def test_score_punctuation_v_control(score_func):
    assert score_func(b'!@#$') < score_func(b'\x00\x01\x02\x03') + 1e-6


@param_by_score_functions(xfails=[letter_freq_score])
def test_score_length_invariant(score_func):
    assert score_func(b'e') == score_func(b'eee')


def test_score_worded_text(reproducible_randomness):
    def make_word():
        return ''.join(
            random.choice(string.ascii_lowercase)
            for _ in range(int(random.gauss(5, 1)))
        )

    def random_phrase():
        return ' '.join(make_word() for _ in range(random.randint(5, 15))).encode()

    real_text = b'Hello this is honestly some real text'
    plaintexts = (
        real_text,
        random_phrase(),
        random_phrase(),
        random_phrase(),
        b'Mmmmmm mmmmmm mm mmmmm mmm mmmmm mmmmm mmmmmmm mmmm',
        b'Zzzzzz zzzzzz zz zzzzz zzz zzzzz zzzzz zzzzzzz zzzz',
    )
    assert select_most_englishest(plaintexts) == real_text


def test_score_random_bytes(reproducible_randomness):
    def random_bytes():
        return ''.join(chr(random.randint(0, 255)) for _ in range(37))

    real_text = 'Hello this is honestly some real text'
    plaintexts = (
        real_text,
        random_bytes(),  # i.e. 'l\xa4\\VN\xa3\xba\xd7\xa9\xd2\xce\xf7sU...'
        random_bytes(),
        random_bytes(),
        random_bytes(),
    )
    selected = select_most_englishest(plaintexts, score_func=simple_score)
    assert selected == real_text


def test_find_plaintext_example():
    input_hex = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    letter, plaintext = find_xor_plaintext(input_hex)
    assert letter == 'X'
    assert plaintext == b"Cooking MC's like a pound of bacon"
    n = len(decode_hex(input_hex))
    assert decode_hex(hex_xor(input_hex, b16encode(n * b'X'))) == plaintext
