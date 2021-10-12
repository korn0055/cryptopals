import aes_custom as aes
import bit_utils
import random, os, base64
import functools

from profiles import format_profile

key = os.urandom(16)
oracle_request_counter = 0
random_prefix = os.urandom(random.randint(0, 16))

def encryption_oracle(plaintext, use_random_prefix):
    global oracle_request_counter, key

    UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".encode('ascii')

    prefix = random_prefix if use_random_prefix else b''
    append = base64.decodebytes(UNKNOWN_STRING)
    # check that the unknown string was copied correctly
    append.decode('ascii')
    padded_plaintext = aes.pad_pkcs7(prefix + plaintext + append)
    ciphertext = aes.encrypt_ecb(padded_plaintext, key)
    oracle_request_counter += 1
    return ciphertext

def test_encryption_oracle():
    pt = b'send this a bunch of times to tset the bla'
    ct = encryption_oracle(pt)
    for i in range(36000):
        assert ct == encryption_oracle(pt)
    print("test_encryption_oracle() passed.")

def determine_ecb_block_size(encryption_oracle_func, min_block_size=2, max_block_size=64):
    for block_size in range(min_block_size, max_block_size):
        # use 3 blocks to make sure there are two full blocks
        input = os.urandom(block_size) * 3
        output = encryption_oracle_func(input)

        for offset in range(len(output) - 2*block_size):
            # try different random inputs with the same size and offset to confirm match wasn't a coincidence
            for check_number in range(10):
                if output[offset:offset+block_size] == output[offset+block_size:offset+2*block_size]:
                    output = encryption_oracle_func(os.urandom(block_size) * 3)
                else:
                    break
            else:
                return block_size

def generate_dict(encryption_oracle_func, block_size, known_bytes, offset, pad_size):
    d = {}
    # remove a dummy byte for each known byte and use the known bytes in the input
    fixed_input = known_bytes[-(block_size-1):].rjust(block_size-1, b'A')
    print(f"  dict_fixed_input={fixed_input}")
    for i in range(256):
        input = fixed_input + bytes([i])
        d[encryption_oracle_func(b'P'*pad_size + input)[offset:block_size+offset]] = input
    return d

def determine_prefix_length(encryption_oracle_func, block_size):
    for pad_size in range(block_size):
        nonce = os.urandom(block_size)
        input = b'A'*pad_size + nonce * 2
        print(f'input={input}')
        output = encryption_oracle_func(input)

        for offset in range(len(output) - 2*block_size):
            # try different random inputs with the same size and offset to confirm match wasn't a coincidence
            for check_number in range(10):
                if output[offset:offset+block_size] == output[offset+block_size:offset+2*block_size]:
                    output = encryption_oracle_func(os.urandom(block_size) * 3)
                else:
                    break
            else:
                return pad_size, offset



def challenge_12(encryption_oracle_func):
    block_size = determine_ecb_block_size(encryption_oracle_func)
    print(f"block_size={block_size}")
    unknown_string_len = len(encryption_oracle_func(b'A'*(block_size))) - block_size
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
        ciphertext = encryption_oracle_func(target_input_block)
        # last block will contain padding, so ciphertext will change
        ciphertext_to_match = ciphertext[block_index*block_size:(block_index+1)*block_size]
        # assert(len(ciphertext_to_match) >= 2*block_size)
        print(f"ciphertext_to_match={ciphertext_to_match.hex()}")
        # get the ciphertext for all values of the last byte
        lookup = generate_dict(encryption_oracle_func, block_size, known_bytes, offset=0, pad_size=0)
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
            lookup = generate_dict(encryption_oracle_func, block_size, last_byte_incremented, offset=0, pad_size=0)
            matching_input = lookup[ciphertext_to_match]
            known_bytes = known_bytes[:-1]
            print('padding found!')
            print(f"decrypted={known_bytes}")
            break

def challenge_14(encryption_oracle_func):
    block_size = determine_ecb_block_size(encryption_oracle_func)
    print(f"block_size={block_size}")
    pad_size, offset = determine_prefix_length(encryption_oracle_func, block_size)
    print(f"pad_size={pad_size}, offset={offset}, actual_prefix_len={len(random_prefix)}")

    unknown_string_len = len(encryption_oracle_func(b'A'*(block_size + pad_size))) - block_size - offset
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
        ciphertext = encryption_oracle_func(b'P'*pad_size + target_input_block)
        # last block will contain padding, so ciphertext will change
        ciphertext_to_match = ciphertext[block_index*block_size+offset:(block_index+1)*block_size+offset]
        # assert(len(ciphertext_to_match) >= 2*block_size)
        print(f"ciphertext_to_match={ciphertext_to_match.hex()}")
        # get the ciphertext for all values of the last byte
        lookup = generate_dict(encryption_oracle_func, block_size, known_bytes, offset=offset, pad_size=pad_size)
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
            lookup = generate_dict(encryption_oracle_func, block_size, last_byte_incremented, offset=offset, pad_size=pad_size)
            matching_input = lookup[ciphertext_to_match]
            known_bytes = known_bytes[:-1]
            print('padding found!')
            print(f"decrypted={known_bytes}")
            break


if __name__ == "__main__":
    challenge_12(encryption_oracle_func=lambda x : encryption_oracle(x, use_random_prefix=False))
    # challenge_14(encryption_oracle_func=lambda x : encryption_oracle(x, use_random_prefix=True))

