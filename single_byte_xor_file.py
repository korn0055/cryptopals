import single_byte_xor_cipher
import string



if __name__ == "__main__":
    with open('set1challenge4.txt') as f:
        for i, ciphertext in enumerate(f):
            scores = enumerate(single_byte_xor_cipher.score_over_keyspace(ciphertext))
            # top_scores = filter(scores, key=lambda x: x[1], reverse=True)
            top_scores = tuple(filter(lambda x: x[1] > 4, scores))
            for top in top_scores:
                key = top[0]
                decrypted = single_byte_xor_cipher.decrypt(ciphertext, key)
                pt = ''.join(filter(lambda x: x in set(string.ascii_letters) | set(' '), decrypted))
                print(f"line={i} score={top[1]} key={key} ct={ciphertext} pt={pt}")