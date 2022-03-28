import aes_custom as aes
import base64
import os
import random
import bit_utils

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
        return True
    except:
        return False

def find_last_byte_padding_match(ciphertext, iv, fn_check_padding):
    # a single last by of 0x01 is valid padding
    # in CBC mode, the plaintext is XOR-ed with the previous cipher block,
    # so for decryption, the decrypted block is the XOR-ed with the previous cipher block to get the plaintext
    # we can corrupt the last byte of the previous block with random values until we have valid padding, which means the tampered ciphertext decrypts as 0x01
    # we can then use that to get the actual plaintext value (...I think)
    # the block we've modified is corrupt, but because the padding is on the last block and the padding oracle doesn't actually check the plaintext before reporting if the padding is good or bad,
    # a corrupt block in the middle is not an issue (I think this is the essense of the vulnerability)

    print("--- find_last_byte_padding_match() ---")
    assert len(ciphertext) % 16 == 0, "ciphertext must be multiple of block size (16)"
    ciphertext_buffer = bytearray(ciphertext)
    original_ciphertext_value = ciphertext[17]
    print(f"original_ciphertext_value={hex(original_ciphertext_value)}")
    matches = []
    plaintext = []
    
    for b in range(255):
        # change the last byte of the second-last block
        ciphertext_buffer[-17] = b
        tampered_ciphertext = bytes(ciphertext_buffer)
        is_padding_valid = fn_check_padding(tampered_ciphertext, iv)
        if is_padding_valid:
            matches += [b]
            plaintext += [0x01 ^ b ^ original_ciphertext_value]
        # print(f"b={hex(b)}\tis_padding_valid={is_padding_valid}\t{tampered_ciphertext.hex()}")
    
    # more than one match will occur if the original ciphertext has padding, since it will match 0x01 and whatever the padding is
    # if the value is 0x01, it will match regardless of other bytes in the block
    # use that to figure out which match results in a plaintext of 0x01 in the last byte of the block
    return matches, plaintext

def find_second_last_byte_padding_match(ciphertext, iv, fn_check_padding, last_byte_tamper_value):
    print("--- find_second_last_byte_padding_match() ---")
    assert len(ciphertext) % 16 == 0, "ciphertext must be multiple of block size (16)"
    ciphertext_buffer = bytearray(ciphertext)
    original_ciphertext_value = ciphertext[18]
    ciphertext_buffer[-17] = last_byte_tamper_value
    matches = []
    plaintext = []
    
    for b in range(255):
        # change the last byte of the second-last block
        ciphertext_buffer[-18] = b
        tampered_ciphertext = bytes(ciphertext_buffer)
        is_padding_valid = fn_check_padding(tampered_ciphertext, iv)
        if is_padding_valid:
            matches += [b]
            plaintext += [0x01 ^ b ^ original_ciphertext_value]
        # print(f"b={hex(b)}\tis_padding_valid={is_padding_valid}\t{tampered_ciphertext.hex()}")
    
    # more than one match will occur if the original ciphertext has padding, since it will match 0x01 and whatever the padding is
    return matches, plaintext



if __name__ == "__main__":
    print("set3, challenge 17 - CBC Padding Oracle")
    ciphertext, iv = get_random_encrypted_line()
    print(f"ciphertext={ciphertext.hex()}, iv={iv.hex()}")
    is_padding_valid = padding_oracle(ciphertext, iv)
    print(f"is_padding_valid={is_padding_valid}")
    last_matches, last_plaintext = find_last_byte_padding_match(ciphertext, iv, padding_oracle)
    print(f"{len(last_matches)} matches={','.join([hex(x) for x in last_matches])}")
    print(f"plaintext={','.join([hex(x) for x in last_plaintext])}")
    for last_byte_tamper_value in last_matches:
        print(f"--- last_byte_tamper_value={last_byte_tamper_value} ---")
        sec_last_matches, sec_last_plaintext = find_second_last_byte_padding_match(ciphertext, iv, padding_oracle, last_byte_tamper_value)
        print(f"{len(sec_last_matches)} matches={','.join([hex(x) for x in sec_last_matches])}")
        print(f"plaintext={','.join([hex(x) for x in sec_last_plaintext])}")


    aes.unpad_pkcs7(bytes([14]*16))
