from pydoc import plain
import aes_custom
import base64
from break_repeating_key_xor import score_over_keyspace
import numpy as np
import random
import bit_utils

def vertical_slices(x):
    test_vals = [bytes(list(range(random.randint(6,20)))) for i in range(10)]
    print(test_vals)

    max_len = max(map(len, test_vals))
    print(f"max_len={max_len}")
    return list(zip(*test_vals))

    


if __name__ == "__main__":
    ct = open('set3challenge19_ct.txt', 'rb').readlines()
    print('\n'.join([x.hex() for x in ct]))
    
    # slice the ciphertexts by keystream position/counter value
    # try all keysteam values and calculate a score
    keys_by_slice = []
    # slices = vertical_slices(ct)
    slices = list(zip(*ct))
    # print(slices)
    for slice in slices:
        slice_bytes = bytes(slice)
        print(f"slice={slice_bytes.hex()}")
        scores = score_over_keyspace(bytes(slice_bytes), return_dict=True)
        # print(f"scores={scores}")
        keys_by_slice.append(sorted(scores, key=scores.get, reverse=True)[:1])

    keystream = bytes(list(zip(*keys_by_slice))[0])
    print(f"keystream={keystream}")
    for line in ct:
        plaintext = bit_utils.bytes_xor(line, keystream)
        print(plaintext.decode('ascii'))