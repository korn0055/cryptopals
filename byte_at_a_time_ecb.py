import aes_custom as aes
import bit_utils
import random, os, base64

key = os.urandom(16)
oracle_request_counter = 0

def encryption_oracle(plaintext):
    global oracle_request_counter, key

    UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".encode('ascii')
    append = base64.decodebytes(UNKNOWN_STRING)
    # check that the unknown string was copied correctly
    append.decode('ascii')
    padded_plaintext = aes.pad_pkcs7(plaintext + append)
    ciphertext = aes.encrypt_ecb(padded_plaintext, key)
    oracle_request_counter += 1
    return ciphertext

def test_encryption_oracle():
    pt = b'send this a bunch of times to tset the bla'
    ct = encryption_oracle(pt)
    for i in range(36000):
        assert ct == encryption_oracle(pt)
    print("test_encryption_oracle() passed.")



def determine_ecb_block_size(encryption_oracle_func, max=64):
    for i in range(max):
        block_size = i + 1
        input = b'A' * 2 * block_size
        output = encryption_oracle_func(input)
        if output[:block_size] == output[block_size:2*block_size]:
            return block_size

def generate_dict(encryption_oracle_func, block_size, known_bytes = bytes()):
    d = {}
    # remove a dummy byte for each known byte and use the known bytes in the input
    fixed_input = known_bytes[-(block_size-1):].rjust(block_size-1, b'A')
    print(f"  dict_fixed_input={fixed_input}")
    for i in range(256):
        input = fixed_input + bytes([i])
        d[encryption_oracle_func(input)[:block_size]] = input
    return d

if __name__ == "__main__":
    # test_encryption_oracle()

    block_size = determine_ecb_block_size(encryption_oracle)
    print(f"block_size={block_size}")
    unknown_string_len = len(encryption_oracle(b'A'*(block_size))) - block_size
    print(f"unknown_string_len={unknown_string_len}")
    known_bytes = bytes()

    prev_found_byte = None
    while len(known_bytes) < unknown_string_len:
        block_index = len(known_bytes) // block_size
        print(f"block_index={block_index}")
        # send a input string that is 1 byte less than the block size
        target_input_block = b'A'*(block_size*(block_index+1)-len(known_bytes)-1)
        print(f"target_input_block={target_input_block} len={len(target_input_block)}")
        # get ciphertext block we want to match
        ciphertext = encryption_oracle(target_input_block)
        # last block will contain padding, so ciphertext will change
        ciphertext_to_match = ciphertext[block_index*block_size:(block_index+1)*block_size]
        # assert(len(ciphertext_to_match) >= 2*block_size)
        print(f"ciphertext_to_match={ciphertext_to_match.hex()}")
        # get the ciphertext for all values of the last byte
        lookup = generate_dict(encryption_oracle, block_size, known_bytes)
        # print('\n'.join([f"{k.hex()}:{v.hex()}" for k, v in lookup.items()]))
        # find which byte value generated the matching ciphertext
        matching_input = lookup.get(ciphertext_to_match, None)
        print(f"    matching_input={matching_input}")
        if matching_input:
            known_bytes += matching_input[-1:]
            print(f"       known_bytes={known_bytes} len={len(known_bytes)}")
            print('')
        elif known_bytes:
            print('checking for padding')
            last_byte_incremented = known_bytes[:-1] + bytes([known_bytes[-1] + 1])
            lookup = generate_dict(encryption_oracle, block_size, last_byte_incremented)
            matching_input = lookup[ciphertext_to_match]
            known_bytes = known_bytes[:-1]
            print('padding found!')
            print(f"decrypted={known_bytes}")
            break


