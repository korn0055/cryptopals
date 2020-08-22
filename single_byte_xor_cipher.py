from collections import Counter
import string
import binascii



def decrypt(ciphertext, key):
    ct_bytes = bytes.fromhex(ciphertext)
    plaintext_bytes = bytes([c ^ key for c in ct_bytes])
    return plaintext_bytes.decode('ascii')

def key_from_most_commmon(ciphertext, plaintext_most_commont = ' '.encode('ascii')):    
    ct_bytes = bytes.fromhex(ct)
    counter = Counter(ct_bytes)
    most_common_ct = counter.most_common()[0][0]
    indices = [i for i, b in enumerate(ct_bytes) if b == most_common_ct]
    key = bytes([most_common_ct])[0] ^ plaintext_most_commont[0]
    # print(f"most common: ct={most_common_ct} indices={indices} key={key}")
    return key

def calc_score(text, scoringValues = {' ': 1}):
    return sum([scoringValues.get(ch, 0) for ch in text])
    
def score_over_keyspace(ct):
    scores = []
    for key in range(256):
        score = 0
        try:
            decrypted = decrypt(ct, key)
            score = calc_score(decrypted)
        except UnicodeDecodeError:
            pass
        finally:
            scores.append(score)
    return scores

if __name__ == "__main__":
    ct = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    key = key_from_most_commmon(ct)
    print(f"Key is {key} {hex(key)}")

    printable = set(string.ascii_letters) | set(' ')


    for k in range(256):
        try:
            most_common_char = "Error"
            decrypted = decrypt(ct, k)
            most_common_bytes = Counter(decrypted).most_common()[0][0]
            pt = ''.join(filter(lambda x: x in printable, decrypted))
            score = calc_score(pt)
            if most_common_bytes in printable:
                most_common_char = most_common_bytes

                print(f"key={k}, score={score} top='{most_common_char}' pt={pt}")
            
        except UnicodeDecodeError:
            pt = "**Non-ascii**"

        # print(f"key={k}, top={most_common_char} pt={pt}")
