from math import floor
from pydoc import plain
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

def decrypt(ciphertext, iv, fn_check_padding):
    print(f"--- decrypt() ---")
    assert len(ciphertext) % 16 == 0, "ciphertext must be multiple of block size (16)"

    rev_iter = 0
    tamper_values = []
    plaintext = bytearray(len(ciphertext))
    pre_xor_val = bytearray(len(ciphertext))
    
    for i in range(len(ciphertext)):
        rev_iter += 1
        print(f"rev_iter={rev_iter}")
        # starting with the last byte in the block, look for the tamper value that gives valid padding
        pad_value = rev_iter % (aes.BLOCK_SIZE + 1)
        
        # ciphertext_buffer = bytearray(ciphertext[:-(rev_iter // aes.BLOCK_SIZE)*aes.BLOCK_SIZE])
        ciphertext_buffer = bytearray(ciphertext)

        for j in range(1, rev_iter):
                ciphertext_buffer[-(j + aes.BLOCK_SIZE)] = pre_xor_val[-j] ^ pad_value
                assert ciphertext_buffer[-(j + aes.BLOCK_SIZE)] ^ pre_xor_val[-j] == pad_value
                # print(f"x={ciphertext_buffer[-(j + aes.BLOCK_SIZE)]}, j={j}, pre_xor={pre_xor_val[-j]}")
        for tamper_value in range(255):
            # changing this will modify plaintext at rev_iter
            ciphertext_buffer[-(rev_iter + aes.BLOCK_SIZE)] = tamper_value

            if fn_check_padding(ciphertext_buffer, iv):
                # make sure the success padding isn't a fluke
                for x in range(255):
                    ciphertext_buffer[-(rev_iter + aes.BLOCK_SIZE)-1] = x
                    if fn_check_padding(ciphertext_buffer, iv):
                        continue
                else:
                    tamper_values += [tamper_value]
                    pre_xor_val[-rev_iter] = tamper_value ^ pad_value
                    plaintext[-rev_iter] = pre_xor_val[-rev_iter] ^ ciphertext[-(rev_iter + aes.BLOCK_SIZE)]
                    break

        else:
            print(f"no valid padding found for ciphertext_buffer rev_iter={rev_iter}")
            break

        print(f"pre_xor_val\t={pre_xor_val.hex()}")
        print(f"plaintext\t={plaintext.hex()}")
        print(f"tamper_values\t={' '.join([hex(x) for x in tamper_values])}")
        print(f"plaintext\t{plaintext[-rev_iter:].decode('ascii')}")






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
    original_ciphertext_value = ciphertext[-17]
    print(f"original_ciphertext_value={hex(original_ciphertext_value)}")
    matches = []
    plaintext = []
    
    for tamper_value in range(255):
        # clear any mods to other bytes
        ciphertext_buffer = bytearray(ciphertext)
        # change the last byte of the second-last block
        ciphertext_buffer[-17] = tamper_value
        tampered_ciphertext = bytes(ciphertext_buffer)
        is_padding_valid = fn_check_padding(tampered_ciphertext, iv)
        if is_padding_valid:
            print(f"tamper_value={tamper_value} has valid padding")
            for prev_tamper_value in range(255):
                ciphertext_buffer[-18] = prev_tamper_value
                tampered_ciphertext = bytes(ciphertext_buffer)
                if not fn_check_padding(tampered_ciphertext, iv):
                    print(f"tamper_value={tamper_value} has invalid padding with prev_tamper_value={prev_tamper_value}")
                    break
            else:
                print(f"tamper_value={tamper_value} has valid padding for all n-1 values")
                matches += [tamper_value]
                plaintext += [tamper_value ^ original_ciphertext_value ^ 0x01]
                continue
            break
            
    
    # more than one match will occur if the original ciphertext has padding, since it will match 0x01 and whatever the padding is
    # if the value is 0x01, it will match regardless of other bytes in the block
    # use that to figure out which match results in a plaintext of 0x01 in the last byte of the block
    return matches, plaintext

def find_second_last_byte_padding_match(ciphertext, iv, fn_check_padding, last_byte_tamper_value):
    print("--- find_second_last_byte_padding_match() ---")
    assert len(ciphertext) % 16 == 0, "ciphertext must be multiple of block size (16)"
    original_ciphertext_value = ciphertext[18]
    matches = []
    plaintext = []
    
    for tamper_value in range(255):
        ciphertext_buffer = bytearray(ciphertext)
        # set plaintext of the last byte to 0x02
        ciphertext_buffer[-17] = 0x02 ^ last_byte_tamper_value ^ 0x01
        # change the last byte of the second-last block
        ciphertext_buffer[-18] = tamper_value
        tampered_ciphertext = bytes(ciphertext_buffer)
        is_padding_valid = fn_check_padding(tampered_ciphertext, iv)
        if is_padding_valid:
            print(f"tamper_value={tamper_value} has valid padding")
            for prev_tamper_value in range(255):
                ciphertext_buffer[-19] = prev_tamper_value
                tampered_ciphertext = bytes(ciphertext_buffer)
                if not fn_check_padding(tampered_ciphertext, iv):
                    print(f"tamper_value={tamper_value} has invalid padding with prev_tamper_value={prev_tamper_value}")
                    break
            else:
                print(f"tamper_value={tamper_value} has valid padding for all n-1 values")
                matches += [tamper_value]
                plaintext += [tamper_value ^ original_ciphertext_value ^ 0x01]
                continue
            break
        # print(f"b={hex(b)}\tis_padding_valid={is_padding_valid}\t{tampered_ciphertext.hex()}")
    
    # more than one match will occur if the original ciphertext has padding, since it will match 0x01 and whatever the padding is
    return matches, plaintext



if __name__ == "__main__":
    print("set3, challenge 17 - CBC Padding Oracle")
    ciphertext, iv = get_random_encrypted_line()
    print(f"ciphertext={ciphertext.hex()}, iv={iv.hex()}")
    is_padding_valid = padding_oracle(ciphertext, iv)
    print(f"is_padding_valid={is_padding_valid}")
    # last_matches, last_plaintext = find_last_byte_padding_match(ciphertext, iv, padding_oracle)
    # print(f"{len(last_matches)} matches={','.join([hex(x) for x in last_matches])}")
    # print(f"plaintext={','.join([hex(x) for x in last_plaintext])}")
    # for last_byte_tamper_value in last_matches:
    #     print(f"--- last_byte_tamper_value={last_byte_tamper_value} ---")
    #     sec_last_matches, sec_last_plaintext = find_second_last_byte_padding_match(ciphertext, iv, padding_oracle, last_byte_tamper_value)
    #     print(f"{len(sec_last_matches)} matches={','.join([hex(x) for x in sec_last_matches])}")
    #     print(f"plaintext={','.join([hex(x) for x in sec_last_plaintext])}")
    decrypt(ciphertext, iv, padding_oracle)
