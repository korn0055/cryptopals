import aes_custom
import base64

if __name__ == "__main__":
    with open('set3challenge19_pt.txt', 'rb') as f_in, open('set3challenge19_ct.txt', 'wb') as f_out:
        for line in f_in:
            f_out.write(base64.encodebytes(aes_custom.encrypt_ctr(base64.decodebytes(line), key=aes_custom.RANDOM_AES_KEY, nonce=0)))