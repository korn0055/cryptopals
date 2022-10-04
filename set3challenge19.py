from pydoc import plain
import base64
from break_repeating_key_xor import score_over_keyspace
import random
import bit_utils
import itertools
import os

HINT_FILE_PATH = 'set3challenge19_hints.txt'

# just some sanity checking to make sure things are being sliced correctly
def test_vertical_slices():
    test_vals = ["ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:random.randint(6,27)] for i in range(10)]
    print('\n'.join([x for x in test_vals]))

    max_len = max(map(len, test_vals))
    print(f"max_len={max_len}")
    # the output of standard zip is only as long as the shortest input, zip_longest pads with None
    slices = list(itertools.zip_longest(*test_vals))
    trimmed = [ [v for v in slice if v is not None] for slice in slices]

    for s, t in zip(slices, trimmed):
        print(f"slice={s}")
        print(f"trim ={[v for v in s if v is not None]}")
        print(f"trim2={t}")

# we know that each line of the ciphertext is is encrypted with CTR mode and uses the same nonce
# this means the keystream byte that is xor-ed with the plaintext is the same for each "column"
# plan is to slice the ciphertext into columns and do letter frequency analysis along each column
# the rows not being the same lenght makes it a little trickier - some may not have enough ciphertext
# for frequency analysis to be useful
if __name__ == "__main__":
    # test_vertical_slices()

    ct = []
    with open('set3challenge19_ct.txt', 'rb') as f:
        for line in f:
            ct_line = base64.decodebytes(line)
            # print(f"ct_line_len={len(ct_line)}")
            ct += [ct_line]

    hints =[]
    if os.path.exists(HINT_FILE_PATH):
        with open(HINT_FILE_PATH, 'rb') as f:
            for hint_line in f:
                stripped = hint_line.strip(b'\r\n')
                hint_line = stripped
                print(f"hint_line='{hint_line}'")
                hints += [hint_line]
    hint_slices = list(itertools.zip_longest(*hints))
    hint_slices = [ [v for v in slice if v is not None] for slice in hint_slices]
    print(f"hint_slices={hint_slices}")
    
    
    # slice the ciphertexts by keystream position/counter value
    keys_by_slice = []
    slices = list(itertools.zip_longest(*ct))
    # remove None values
    slices = [ [v for v in slice if v is not None] for slice in slices]
    for i, slice in enumerate(slices):
        # making this useful would actually be a bit more complicated because
        # we need to account for the lines that don't have a hint
        # currently, they get mashed together an it throws the whole hint slice matching off
        hint_slice_bytes = bytes(hint_slices[i]) if i < len(hint_slices) else None
        
        print(f"i={i}\tlen_slice={len(slice)},\thint_slice={hint_slice_bytes}")
        # try all key values and calculate a score
        slice_bytes = bytes(slice)
        # print(f"slice={slice_bytes.hex()}")
        scores = score_over_keyspace(slice_bytes, return_dict=True, hint_plaintext=hint_slice_bytes)
        # print(f"scores={sorted(scores, key=scores.get, reverse=True)}")
        keys_by_slice.append(sorted(scores, key=scores.get, reverse=True))

    # print(f"keys_by_slice={keys_by_slice}")
    keystream = bytes(list(zip(*keys_by_slice))[0])
    print(f"keystream={keystream}")
    with open('set3challenge19_out.txt', 'wb') as f:
        for line in ct:
            plaintext_bytes = bit_utils.bytes_xor(line, keystream)
            sanitized = bytes([b if b in range(128) else '@'.encode('ascii')[0] for b in plaintext_bytes])
            plaintext_ascii = sanitized.decode('ascii')
            print(plaintext_ascii)
            f.writelines([plaintext_bytes])
            f.write(b'\n')
        
