import aes_custom
import base64

if __name__ == "__main__":
    with open('set3challenge19_pt.txt', 'rb') as f_in, open('set3challenge19_ct.txt', 'wb') as f_out:
        for line in f_in:
            f_out.write(base64.encodebytes(aes_custom.encrypt_ctr(base64.decodebytes(line), key=aes_custom.RANDOM_AES_KEY, nonce=0)))
        
    with open('set3challenge19_pt.txt', 'rb') as f_pt, open('set3challenge19_ct.txt', 'rb') as f_ct:
        for pt, ct in zip(f_pt, f_ct):
            ciphertext = base64.decodebytes(ct)
            decrypted = aes_custom.encrypt_ctr(ciphertext, key=aes_custom.RANDOM_AES_KEY, nonce=0)
            b64decrypted = base64.encodebytes(decrypted)
            assert decrypted == base64.decodebytes(pt)
        