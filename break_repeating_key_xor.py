from bit_utils import hamming_distance, chunkify
from single_byte_xor_cipher import key_from_most_commmon, decrypt
import base64

def find_keysize_hamming_distance(ciphertext : bytes, keysize, blocks_to_average=1):
    assert isinstance(ciphertext, bytes)
    # For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, 
    # and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    chunks = chunkify(ciphertext, keysize)
    return sum([hamming_distance(next(chunks), next(chunks)) for _ in range(blocks_to_average)]) / (blocks_to_average*keysize)

def load_ciphertext_from_file(path):
    with open(path, 'rb') as f:
        return base64.decodebytes(f.read())

def keysizes_to_try(ciphertext):
    index = [(keysize, find_keysize_hamming_distance(ciphertext, keysize, blocks_to_average=1),
        find_keysize_hamming_distance(ciphertext, keysize, blocks_to_average=2)) for keysize in range(2, 40)]

    likely_keysizes = []

    print("Top 3 using average")
    for line, _ in zip(sorted(index, key=lambda x: x[2], reverse=True), range(3)):
        likely_keysizes.append(line[0])
        print(line)

    print("Top 3 without average")
    for line, _ in zip(sorted(index, key=lambda x: x[1], reverse=True), range(3)):
        if line[0] not in likely_keysizes:
            likely_keysizes.append(line[0])
        print(line)

    return likely_keysizes

if __name__ == "__main__":
    ct = load_ciphertext_from_file("set1challenge6_ct.txt")

    print(keysizes_to_try(ct))
