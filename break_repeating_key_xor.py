from bit_utils import hamming_distance, chunkify
from single_byte_xor_cipher import key_from_most_commmon, decrypt, score_over_keyspace, calc_score, format_decrypted_bytes
import base64
from collections import defaultdict
import os
import itertools

def find_keysize_hamming_distance(ciphertext : bytes, keysize, blocks_to_average):
    assert isinstance(ciphertext, bytes)
    if blocks_to_average is None:
        blocks_to_average = len(ciphertext) // ( 2*  keysize) - 1
        print(f"averaging {blocks_to_average} blocks")
    # For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, 
    # and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    chunks = chunkify(ciphertext, keysize)
    return sum([hamming_distance(next(chunks), next(chunks)) for _ in range(blocks_to_average)]) / (blocks_to_average*keysize)

def load_ciphertext_from_file(path):
    with open(path, 'rb') as f:
        return base64.decodebytes(f.read())

def test_load_ciphertext_from_file():
    from_file = load_ciphertext_from_file("test_base64.txt")
    expected = bytes.fromhex('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'*2)
    print(f"loaded: {from_file.hex()}")
    assert from_file == expected
    print("test_load_ciphertext_from_file Passed.")


def keysizes_to_try(ciphertext):
    index = [(keysize, find_keysize_hamming_distance(ciphertext, keysize, blocks_to_average=1),
        find_keysize_hamming_distance(ciphertext, keysize, blocks_to_average=None)) for keysize in range(2, 40)]

    likely_keysizes = []

    print("Top 3 using average")
    for line, _ in zip(sorted(index, key=lambda x: x[2], reverse=False), range(2)):
        likely_keysizes.append(line[0])
        print(line)

    print("Top 3 without average")
    for line, _ in zip(sorted(index, key=lambda x: x[1], reverse=False), range(0)):
        if line[0] not in likely_keysizes:
            likely_keysizes.append(line[0])
        print(line)

    return likely_keysizes

def transpose(ciphertext : bytes, keysize):
    return [bytes(ciphertext[i::keysize]) for i in range(keysize)]

if __name__ == "__main__":
    ct = load_ciphertext_from_file("set1challenge6_ct.txt")
    # ct = bytes.fromhex('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')

    # print(keysizes_to_try(ct))

    solutions = []
    for keysize in keysizes_to_try(ct):
        transposed = transpose(ct, keysize)

        # total_score = sum([sorted(score_over_keyspace(block, return_dict=True), key=scores.get, reverse=True)[0] for block in enumerate(transposed)]
        total_score = {}
        print(f"keysize={keysize}")

        keys_by_block = []
        for block in transposed:
            scores = score_over_keyspace(block, return_dict=True)
            keys_by_block.append(sorted(scores, key=scores.get, reverse=True)[:1])
        
        print(f"keys by block: {keys_by_block}")

        key_candidates = itertools.product(*keys_by_block)

        for key_candidate, _ in zip(key_candidates, range(10000000)):
            key_candidate = bytes(key_candidate)
            decrypted = decrypt(ct, key_candidate)
            score = calc_score(decrypted)
            solutions.append((key_candidate, score, decrypted))
            # print(f"key={format_decrypted_bytes(key_candidate)} score={score} pt={format_decrypted_bytes(decrypted)}")
        
    sorted_solutions = sorted(solutions, key=lambda x: x[1], reverse=True)
    print(f"{len(sorted_solutions)} solutions")
    for solution in sorted_solutions[:30]:
        print(f"keysize={len(solution[0])} key={format_decrypted_bytes(solution[0])} score={solution[1]} pt={solution[2]}")