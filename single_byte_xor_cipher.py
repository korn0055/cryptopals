from collections import Counter
import string
import binascii
from bit_utils import bytes_xor
import itertools

def decrypt(ciphertext : bytes, key : bytes):
    assert isinstance(ciphertext, bytes)
    if isinstance(key, int):
        key = bytes([key])
    return bytes([c ^ k for c, k in zip(ciphertext, itertools.cycle(key)) ])

def key_from_most_commmon(ciphertext : bytes, plaintext_most_commont = ' '.encode('ascii')):
    # assume the most common ciphertext char corresponds to plaintext_most_common   
    counter = Counter(ciphertext)
    most_common_ct = counter.most_common()[0][0]
    indices = [i for i, b in enumerate(ciphertext) if b == most_common_ct]
    key = bytes_xor([most_common_ct][0], plaintext_most_commont[0])
    # print(f"most common: ct={most_common_ct} indices={indices} key={key}")
    return key

english_text_distribution = {
    ' ' : 18,
    'e' : 10,
    't' : 7,
    'a' : 6,
    'o' : 6,
    'i' : 5,
    'n' : 5,
    's' : 5,
    'r' : 5,
    'h' : 5,
    'l' : 3,
    'd' : 3,
    'c' : 2,
    'u' : 2,
    'm' : 2,
    'f' : 2,
    'p' : 1,
    'w' : 1,
    'y' : 1,
    'b' : 1,
    # '$' : -10,
    # '@' : -10,
    # '#' : -10,
    # '*' : -10
    #  t a o i n s r h l d c u m g f p w y b , . v k ' " - x 0 j 1 q 2 z ) ( : ! ? 5 ; 3 4 9 / 8 6 7 [ ] % $ | * = _ + > \ < & ^ # @ ` ~ { }]

}

def create_score_values():
    d = {}
    for ch, freq in english_text_distribution.items():
        d[ch.lower().encode('ascii')] = freq
        d[ch.upper().encode('ascii')] = freq
    print(f"Score values={d}")
    return d

def calc_score(text : bytes, scoringValues = create_score_values()):
    assert isinstance(text, bytes)
    return sum([scoringValues.get(bytes([ch]), 0) for ch in text])
    
def score_over_keyspace(ciphertext : bytes, return_dict=False):
    scores = []
    scores_dict = {}
    for key in range(256):
        score = 0
        decrypted = decrypt(ciphertext, key)
        score = calc_score(decrypted)
        scores.append(score)
        scores_dict[key] = score
    
    if return_dict:
        return scores_dict
    else:
        return scores    

def format_decrypted_bytes(b : bytes, printable=set(string.printable) - set('\x0b\x0c')):
    if b.isascii() and set(b.decode('ascii')).issubset(printable):
        return '(str) ' + b.decode('ascii')
    else:
        return '(hex) ' + b.hex()

if __name__ == "__main__":
    ct = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

    key = key_from_most_commmon(ct)
    print(f"Key is 0x{key.hex()}")

    for k in range(256):
        most_common_char = "Error"
        decrypted_bytes = decrypt(ct, bytes([k]))
        most_common_bytes = bytes([Counter(decrypted_bytes).most_common()[0][0]])
        score = calc_score(decrypted_bytes)
        print(f"key={k:#02x}, top={format_decrypted_bytes(most_common_bytes)} pt={format_decrypted_bytes(decrypted_bytes)}")
