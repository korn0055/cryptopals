import aes_custom as aes
import bit_utils
import random, os, base64


def format_and_pad_and_encrypt(user_data):
    if not isinstance(user_data, bytes):
        user_data = user_data.encode('ascii')
    prefix = "comment1=cooking%20MCs;userdata=".encode("ascii")
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon".encode("ascii")
    plaintext_bytes = prefix + user_data.replace(';'.encode("ascii"), "\";\"".encode("ascii")).replace('='.encode("ascii"), "\"=\"".encode("ascii")) + suffix
    # print(f"plaintext={plaintext}")
    print(f"PLAINTEXT:{plaintext_bytes[80:80+16]}")
    padded_bytes = aes.pad_pkcs7(plaintext_bytes)
    # print(padded_bytes)
    cbc_encrypted = aes.encrypt_cbc(padded_bytes, aes.RANDOM_AES_KEY, aes.RANDOM_CBC_IV)
    # print(cbc_encrypted.hex())
    return cbc_encrypted

def is_admin(ciphertext):
    decrypted = aes.decrypt_cbc(ciphertext, aes.RANDOM_AES_KEY, aes.RANDOM_CBC_IV)
    print(f"decrypted={decrypted}")
    depadded = aes.unpad_pkcs7(decrypted)
    print(f"depadded={depadded}")
    return "admin=true".encode('ascii') in depadded

def test_bit_flipping():
    target = b'THISISWHATIWANTTOSEE'
    fixed =  b'THISCANNOTBECHANGED!'
    attacker = bit_utils.bytes_xor(fixed, target)
    result = bit_utils.bytes_xor(fixed, attacker)
    print(f"target={target}")
    print(f"fixed={fixed}")
    print(f"attacker={attacker}")
    print(f"result={result}")

def attempt_priviledge_escalation(user_data):
    if not isinstance(user_data, bytes):
        user_data = user_data.encode('ascii')
    print(f"user_data={user_data} {user_data.hex()} len={len(user_data)}")
    print(f"is_admin={is_admin(format_and_pad_and_encrypt(user_data))}")

if __name__ == "__main__":
    ciphertext_no_user_data = format_and_pad_and_encrypt("")
    # print(f"ciphertext_no_user_data={ciphertext_no_user_data.hex()} len={len(ciphertext_no_user_data)})")

    # make sure this doesn't work
    # attempt_priviledge_escalation('admin=true')
    empty_user_data_len = len(ciphertext_no_user_data)
    # make our plaintext as long as the prefix and suffix so we can guess were it is in the ciphertext
    # using all zeros here eliminates one XOR operation
    attacker_plaintext = b'\ff'*empty_user_data_len
    original_ciphertext = bytearray(format_and_pad_and_encrypt(attacker_plaintext))
    target_plaintext = 'admin=true      '.encode('ascii')
    print("original ciphertext:")
    bit_utils.print_hex_block(original_ciphertext)
    print(f"target_plaintext: {target_plaintext}")
    bit_utils.print_hex_block(target_plaintext)
    # modify ciphertext block that will be XORed with attacker_plaintext so that the result is target_plaintext
    # [A=ecb(a^iv)][B=ecb(b^A)][C=ecb(c^B)][D=ecb(d^C)]
    original_prev_block_ciphertext = original_ciphertext[empty_user_data_len:empty_user_data_len+16]
    mod_prev_block_ciphertext = bit_utils.bytes_xor(original_prev_block_ciphertext, bit_utils.bytes_xor(target_plaintext, attacker_plaintext))
    attacker_ciphertext = bytearray(original_ciphertext)
    attacker_ciphertext[empty_user_data_len:empty_user_data_len+16] = mod_prev_block_ciphertext
    print("modified ciphertext:")
    bit_utils.print_hex_block(attacker_ciphertext)
    print(f"is_admin={is_admin(attacker_ciphertext)}")