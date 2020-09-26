import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import bit_utils

def load_ciphertext_from_file(path):
    with open(path, 'rb') as f:
        return base64.decodebytes(f.read())

def decrypt_ecb(ciphertext, key):
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_ecb(plaintext, key):
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def test_ecb():
    pt = "Here's some random text that I'm going to encrypt.  I want it to have a couple 16-byte blocks worth."[:32].encode('ascii')
    key = "YELLOW SUBMARINE".encode('ascii')
    ct = encrypt_ecb(pt, key=key)
    decrypted = decrypt_ecb(ct, key)
    assert pt == decrypted
    print("test_ecb() passed.")

def pad_pkcs7(b, block_size=16):
    # should block be added if it's an even multiple of block_size?
    pad_value = bytes([block_size - (len(b) % block_size)])
    return b.ljust(block_size, pad_value)

def unpad_pkcs7():
    pass

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


if __name__ == "__main__":
    test_ecb()
    test_pad_pkcs7()
    test_cbc()
    set2challenge10()
