import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import bit_utils
import os
import random
import math

RANDOM_AES_KEY = os.urandom(16)
RANDOM_CBC_IV = os.urandom(16)

def load_ciphertext_from_file(path):
    with open(path, 'rb') as f:
        return base64.decodebytes(f.read())

def save_ciphertext_to_file(path, ciphertext_bytes):
    encoded = base64.encodebytes(ciphertext_bytes)
    with open(path, 'wb') as f:
        f.write(encoded)
    return encoded

def decrypt_ecb(ciphertext, key):
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_ecb(plaintext, key):
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def test_ecb1():
    pt = "Here's some random text that I'm going to encrypt.  I want it to have a couple 16-byte blocks worth."[:32].encode('ascii')
    key = "YELLOW SUBMARINE".encode('ascii')
    ct = encrypt_ecb(pt, key=key)
    decrypted = decrypt_ecb(ct, key)
    assert pt == decrypted
    print("test_ecb1() passed.")

def test_ecb2():
    key = 'YELLOW SUBMARINE'.encode('ascii')
    # note this file happens to fit nicely into 16-byte blocks
    with open('estranged.txt', 'rb') as f:
        pt = f.read()
        print(f"encrypting {len(pt)} plaintext bytes")
        ct = encrypt_ecb(pt, key)
        print(f"decrypting {len(ct)} ciphertext bytes")
        decrypted = decrypt_ecb(ct, key)
        assert pt == decrypted
        print("test_ecb2() passed.")

def pad_pkcs7(bytestring, block_size=16):
    # should block be added if it's an even multiple of block_size?
    pad_value = bytes([block_size - (len(bytestring) % block_size)])
    if pad_value == 0:
        pad_value = block_size
    output_block_count = math.ceil(len(bytestring)/block_size)
    return bytestring.ljust(output_block_count*block_size, pad_value)

def unpad_pkcs7(bytestring, block_size=16):
    pad_value = bytestring[-1]
    assert all([b == pad_value for b in bytestring[-pad_value:]])
    return bytestring[:-pad_value]

def test_unpad_pkcs7():
    print(unpad_pkcs7(set2challenge10()))

def test_pad_pkcs7():
    assert pad_pkcs7("YELLOW SUBMARINE".encode('ascii'), 20) == "YELLOW SUBMARINE\x04\x04\x04\x04".encode('ascii')
    print("test_pad_pkcs7() passed.")

def encrypt_cbc(plaintext, key, iv):
    BLOCK_SIZE = 16
    assert len(iv) == BLOCK_SIZE
    assert len(plaintext) % BLOCK_SIZE == 0

    pt_blocks = bit_utils.chunkify(plaintext, BLOCK_SIZE)
    prev_ct_block = iv
    ciphertext = bytes(0)
    for pt_block in pt_blocks:
        ecb_in = bit_utils.bytes_xor(pt_block, prev_ct_block)
        prev_ct_block = encrypt_ecb(ecb_in, key)
        ciphertext += prev_ct_block
    return ciphertext

def decrypt_cbc(ciphertext, key, iv):
    BLOCK_SIZE = 16
    assert len(iv) == BLOCK_SIZE
    assert len(ciphertext) % BLOCK_SIZE == 0

    ct_blocks = bit_utils.chunkify(ciphertext, BLOCK_SIZE)
    prev_ct = iv
    plaintext = bytes(0)
    for ct_block in ct_blocks:
        ecb_out = decrypt_ecb(ct_block, key)
        plaintext += bit_utils.bytes_xor(ecb_out, prev_ct)
        prev_ct = ct_block
    return plaintext


def test_cbc():
    pt = "Here's some random text that I'm going to encrypt.  I want it to have a couple 16-byte blocks worth."[:32].encode('ascii')
    key = "YELLOW SUBMARINE".encode('ascii')
    iv='0123456789ABCDEF'.encode('ascii')
    ct = encrypt_cbc(pt, key, iv)
    decrypted = decrypt_cbc(ct, key, iv)
    assert pt == decrypted
    print("test_cbc() passed.")


def set1challenge7():
    ct = load_ciphertext_from_file('set1challenge7.txt')
    key = 'YELLOW SUBMARINE'.encode('ascii')
    pt = decrypt_ecb(ct, key)
    print(pt)

def set2challenge10():
    ct = load_ciphertext_from_file('set1challenge10.txt')
    key = 'YELLOW SUBMARINE'.encode('ascii')
    pt = decrypt_cbc(ct, key, b'\x00'*16)
    print(pt)
    return pt

def encryption_oracle(plaintext):
    key = os.urandom(16)
    mode = 'ecb' if random.randint(0, 1) == 0 else 'cbc'
    prepend = os.urandom(random.randint(5, 10))
    append = os.urandom(random.randint(5, 10))
    padded_plaintext = pad_pkcs7(prepend + plaintext + append)
    if mode == 'cbc':
        iv = os.urandom(16)
        ciphertext = encrypt_cbc(padded_plaintext, key, iv)
    elif mode == 'ecb':
        ciphertext = encrypt_ecb(padded_plaintext, key)
    else:
        assert False
    return ciphertext, mode

def detect_oracle_mode(oracle_func):
    # create a plaintext with repeated blocks and look for repeated blocks in ciphertext
    plaintext = 'REPEAT THE BLOCK'.encode('ascii') * 10
    ciphertext, mode = oracle_func(plaintext)
    ecb_detected = not are_blocks_unique(ciphertext)
    return ecb_detected, mode, plaintext, ciphertext

def are_blocks_unique(bytestring, block_size=16):
    blocks = list(bit_utils.chunkify(bytestring, block_size))
    unique_blocks = len(set(blocks))
    return unique_blocks == len(blocks)

def test_detect_oracle_mode(verbose=False):
    TEST_TRIALS = 1000
    pass_count = 0
    summary = {'ecb':0, 'cbc':0}
    for i in range(TEST_TRIALS):
        is_ecb, actual_mode, _, ciphertext = detect_oracle_mode(encryption_oracle)
        detected_mode = 'ecb' if is_ecb else 'cbc'
        is_pass = detected_mode == actual_mode
        if is_pass:
            pass_count += 1
        if verbose:
            print(f"{'PASS' if is_pass else 'FAIL'} iteartion={i} actual mode={actual_mode} ecb_detected={is_ecb}")
            for block in bit_utils.chunkify(ciphertext.hex(), 16):
                print(block)
        summary[actual_mode] += 1
        assert detected_mode == actual_mode
    print(f"test_detect_oracle_mode() passed {pass_count} of {TEST_TRIALS} test trials. Actual mode counts={summary}")
   

if __name__ == "__main__":
    test_ecb1()
    test_ecb2()
    test_pad_pkcs7()
    test_cbc()
    # set2challenge10()
    # test_unpad_pkcs7()
    # print(encryption_oracle("some bla bla bla to encrypt".encode('ascii')))
    test_detect_oracle_mode()
