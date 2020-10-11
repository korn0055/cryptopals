import aes_custom as aes
import bit_utils
import random, os, base64

key = os.urandom(16)


def encryption_oracle(plaintext):
    UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".encode('ascii')
    append = base64.decodebytes(UNKNOWN_STRING)
    padded_plaintext = aes.pad_pkcs7(plaintext + append)
    ciphertext = aes.encrypt_ecb(padded_plaintext, key)
    return ciphertext

def determine_ecb_block_size(encryption_oracle_func, max=64):
    for i in range(max):
        block_size = i + 1
        input = b'A' * 2 * block_size
        output = encryption_oracle_func(input)
        if output[:block_size] == output[block_size:2*block_size]:
            return block_size

def generate_dict(encryption_oracle_func, block_size, known_bytes = bytes()):
    d = {}
    fixed_input = known_bytes[-(block_size-1):].rjust(block_size-1, b'A')
    for i in range(256):
        input = fixed_input + bytes([i])
        d[encryption_oracle_func(input)[:block_size]] = input
    return d

if __name__ == "__main__":
    block_size = determine_ecb_block_size(encryption_oracle)
    print(f"block_size={block_size}")

    ciphertext_to_match = encryption_oracle(b'A'*(block_size-1))[:block_size]
    print(f"ciphertext_to_match={ciphertext_to_match.hex()}")
    lookup = generate_dict(encryption_oracle, block_size)
    print('\n'.join([f"{k.hex()}:{v.hex()}" for k, v in lookup.items()]))
    known_bytes = bytes(lookup[ciphertext_to_match][-1:])
    print(f"known_bytes={known_bytes.hex()}")

    target_input_block = lookup[ciphertext_to_match][:block_size-2]
    print(f"target_input_block={target_input_block}")
    ciphertext_to_match = encryption_oracle(target_input_block)[:block_size]
    print(f"ciphertext_to_match={ciphertext_to_match.hex()}")
    lookup = generate_dict(encryption_oracle, block_size, known_bytes)
    print('\n'.join([f"{k.hex()}:{v.hex()}" for k, v in lookup.items()]))
    known_bytes += bytes(lookup[ciphertext_to_match][-1:])
    print(f"known_bytes={known_bytes.hex()}")
