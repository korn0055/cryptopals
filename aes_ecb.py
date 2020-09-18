import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def load_ciphertext_from_file(path):
    with open(path, 'rb') as f:
        return base64.decodebytes(f.read())

if __name__ == "__main__":
    ct = load_ciphertext_from_file('set1challenge7.txt')
    key = 'YELLOW SUBMARINE'.encode('ascii')
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    print(pt)
