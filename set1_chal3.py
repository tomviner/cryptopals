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
from __future__ import division

import csv
import random
import re
import string
from base64 import b16encode
from operator import itemgetter

import pytest

from set1_chal1 import decode_hex
from set1_chal2 import hex_xor


def single_letter_xor_plaintexts(input_hex):
    n = len(decode_hex(input_hex))
    hex_encoded_letter_map = {
        letter: b16encode(n * letter)
        for letter in string.letters + string.digits
    }
    return {
        decode_hex(hex_xor(input_hex, letter_hex)): letter
        for letter, letter_hex in hex_encoded_letter_map.items()
    }

def find_xor_plaintext(input_hex):
    plaintext_letter_map = single_letter_xor_plaintexts(input_hex)
    best = select_most_englishest(plaintext_letter_map.keys())
    return plaintext_letter_map[best], best


def get_letter_proportion_map():
    """ From http://norvig.com/mayzner.html
    """
    with open('ngrams1_any_position.csv') as f:
        rdr = csv.reader(f)
        rdr.next()  # col heading row
        occurence_map = {
            letter: int(count) for letter, count in rdr
        }
    total_occurences = sum(occurence_map.values())
    proportion_map = {
        letter: occurences / total_occurences
        for letter, occurences in occurence_map.items()
    }
    return proportion_map

def simple_score(text):
    """ Count number of unique non-letter* characters

        * honorary_letters allow for common punctuation

        This approach is all you need against random bytes.
    """
    honorary_letters = " '.,"
    return len(set(text) - set(string.letters + honorary_letters))


def letter_freq_score(text, english_proportion_map=get_letter_proportion_map()):
    """ Score based on character frequency

        For each letter in `text` + the alphabet, assess how it's number
        of occurences differs from that of English language.

        This approach may be need when plaintexts are jumbled letter
        phrases (as opposed to random bytes).
    """
    n = len(text)
    text = text.upper()
    text = re.sub(r' ', '', text)
    character_domain = set(string.uppercase) | set(text)
    NON_LETTER_SCORE = 1
    # sum of squares of differences between expected letter counts and actual
    letter_score_map = {
        letter: (
            text.count(letter) -
            n * english_proportion_map.get(letter, NON_LETTER_SCORE)
        )**2
        for letter in character_domain
    }
    return sum(letter_score_map.values())

def select_most_englishest(texts, score_func=letter_freq_score):
    """ Simply pick the text with the lowest score.
    """
    score_map = {
        text: score_func(text) for text in texts
    }
    best_text, score = min(score_map.items(), key=itemgetter(1))
    return best_text


@pytest.yield_fixture
def reproducible_randomness():
    """
    Tests using this fixture will produce consistent random values
    """
    some_previous_randomness = random.random()
    random.seed('make things predictable.')
    yield
    random.seed(some_previous_randomness)


def test_score_worded_text(reproducible_randomness):
    def random_phrase():
        make_word = lambda: ''.join(
            random.choice(string.lowercase)
            for _ in xrange(int(random.gauss(5, 1))))
        return ' '.join(
            make_word()
            for _ in xrange(random.randint(5, 15))
        )
    real_text = 'Hello this is honestly some real text'
    plaintexts = (
        real_text,
        random_phrase(),  # ihqs vrvu izivnu zqsj qfw oiuhot fack qiuwq xlscc
        random_phrase(),  # odgkyc rfoboode bxlcck eznn nbplf zgbo wmzq xhlmv jvvc tfaa gqzbia cfiwb
        random_phrase(),  # ybcr dbns tkri kb yrd obovdm jbhc'
        'Mmmmmm mmmmmm mm mmmmm mmm mmmmm mmmmm mmmmmmm mmmm',
        'Zzzzzz zzzzzz zz zzzzz zzz zzzzz zzzzz zzzzzzz zzzz',
    )
    assert select_most_englishest(plaintexts) == real_text

def test_score_random_bytes(reproducible_randomness):
    def random_bytes():
        return ''.join(
            chr(random.randint(0, 255))
            for _ in xrange(37)
        )
    real_text = 'Hello this is honestly some real text'
    plaintexts = (
        real_text,
        random_bytes(),
        random_bytes(),
        random_bytes(),
        random_bytes(),
    )
    selected = select_most_englishest(plaintexts, score_func=simple_score)
    assert selected == real_text

def test_find_plaintext_example():
    input_hex = (
        '1b37373331363f78151b7f2b783431333d7'
        '8397828372d363c78373e783a393b3736')
    letter, plaintext = find_xor_plaintext(input_hex)
    assert letter == 'X'
    assert plaintext == "Cooking MC's like a pound of bacon"
    n = len(decode_hex(input_hex))
    assert decode_hex(hex_xor(input_hex, b16encode(n * 'X'))) == plaintext
