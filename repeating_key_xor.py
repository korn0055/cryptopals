import binascii
import string
import itertools

def encrypt(plaintext, key):
    key_stream = itertools.cycle(key)
    ciphertext = [b ^ k for b, k in zip(plaintext, key_stream)]
    return bytes(ciphertext)


if __name__ == "__main__":
    key = "ICE".encode("ascii")
    pt = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".encode("ascii")

    ct_expected = bytes.fromhex('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')


    ct=encrypt(pt, key)
    print(f"pt len={len(pt)}:")
    print(pt)
    print(f"my CT len={len(ct)}:")
    print(ct)
    print(f"expected CT len={len(ct_expected)}:")
    print(ct_expected)

    if ct == ct_expected:
        print("Cipher texts match!!")
    else:
        lines = [''.join([f"{x:<10}" for x in (tuple(chr(t[1])) + t)] + ([] if t[2]==t[3] else ['!!!']) ) for t in zip(range(len(pt)), pt, ct, ct_expected)]
        print('\n'.join(lines))
