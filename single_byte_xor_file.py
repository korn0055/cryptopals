import single_byte_xor_cipher
import string

if __name__ == "__main__":
    with open('set1challenge4.txt') as f:
        for i, text in enumerate(f):
            ciphertext = bytes.fromhex(text)
            scores = enumerate(single_byte_xor_cipher.score_over_keyspace(ciphertext))
            top_scores = tuple(filter(lambda x: x[1] > 100, scores))
            for top in top_scores:
                key = top[0]
                decrypted = single_byte_xor_cipher.decrypt(ciphertext, key)
                print(f"line={i} score={top[1]} key={key:#02x} ct={ciphertext.hex()} pt={single_byte_xor_cipher.format_decrypted_bytes(decrypted)}")