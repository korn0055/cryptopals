from sympy import false, true
import aes_custom as aes
import base64
import os
import random

def get_random_encrypted_line():
    iv = os.urandom(16)
    # key is created once
    fixed_key = aes.RANDOM_AES_KEY

    with open("set3challenge17.txt", 'rb') as f:
        lines = f.readlines()
        random_line = random.choice(lines)
        plaintext = base64.decodebytes(random_line)
        padded_plaintext = aes.pad_pkcs7(plaintext)
        encrypted = aes.encrypt_cbc(padded_plaintext, fixed_key, iv)
        return encrypted, iv

def padding_oracle(ciphertext, iv):
    decrypted = aes.decrypt_cbc(ciphertext, aes.RANDOM_AES_KEY, iv)
    try:
        aes.unpad_pkcs7(decrypted)
        return true
    except:
        return false


if __name__ == "__main__":
    print("set3, challenge 17 - CBC Padding Oracle")
    ciphertext, iv = get_random_encrypted_line()
    print(f"ciphertext={ciphertext.hex()}, iv={iv.hex()}")
    is_padding_valid = padding_oracle(ciphertext, iv)
    print(f"is_padding_valid={is_padding_valid}")
