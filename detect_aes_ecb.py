import itertools
import bit_utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def check(ciphertext):
    blocks = list(bit_utils.chunkify(ciphertext, 16))
    unique_blocks = len(set(blocks))
    return unique_blocks != len(blocks)

def decrypt(ct):
    key = 'YELLOW SUBMARINE'.encode('ascii')
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

if __name__ == "__main__":
    with open('set1challenge8.txt') as f:
        for line in f:
            ct = bytes.fromhex(line)
            if check(ct):
                print(line)
                print(decrypt(ct))
