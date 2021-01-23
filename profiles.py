import string, os
import aes_custom

key = os.urandom(16)

def parse(input):
    d = dict([pair.split('=') for pair in input.split('&')])
    if 'uid' in d:
        d['uid'] = int(d['uid'])
    return d

def test_parse():
    input = 'foo=bar&baz=qux&zap=zazzle'
    expected_output = {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}
    output = parse(input)
    print(output)
    assert expected_output == output
    print("test_parse() passed.")

def profile_for(email_address : str):
    sanitized_email_address = email_address.replace('&','').replace('=','')
    return {'email': sanitized_email_address, 'uid': 10, 'role': 'user'}

def encrypt_profile(email_address : str):
    profile = profile_for(email_address)
    formatted = format_profile(profile)
    padded = aes_custom.pad_pkcs7(formatted.encode('ascii'))
    encrypted = aes_custom.encrypt_ecb(padded, key)
    return encrypted, profile

def decrypt_profile(ciphertext : bytes):
    padded = aes_custom.decrypt_ecb(ciphertext, key)
    formatted = aes_custom.unpad_pkcs7(padded).decode('ascii')
    profile = parse(formatted)
    return profile

def crack_admin(oracle_fn):

    # get the oracle to encrypt a block that only include 'admin' + padding
    # this block will be pasted to the end of the ciphertext that includes the attacker email
    offset = 16 - len('email=')
    padded_admin_pt = aes_custom.pad_pkcs7('admin'.encode('ascii')).decode('ascii')
    offset_padded_admin_pt = 'x'*offset + padded_admin_pt
    print(f"offset_padded_admin_pt={offset_padded_admin_pt}, len={len(offset_padded_admin_pt)}")
    admin_block_ct, _ = oracle_fn(offset_padded_admin_pt)
    print(f"admin_block_ct={admin_block_ct}, len={len(admin_block_ct)}")
    admin_plus_pad_ct = admin_block_ct[16:32]
    print(f"admin_plus_pad_ct={admin_plus_pad_ct}, len={len(admin_plus_pad_ct)}")

    # select email length so that the role field is on its own block (the last block)
    required_email_len = 32 - len('email=&uid=10&role=')
    email = 'foo@email.com'
    print(f"required_email_len={required_email_len}, actual={len(email)}")
    ciphertext, _ = oracle_fn(email)
    print(f"ciphertext={ciphertext.hex()}")
    # replace last block with ciphertext for 'admin' + padded
    modified_ct = ciphertext[:-16] + admin_plus_pad_ct
    print(f"modified_ct={modified_ct}, len={len(modified_ct)}")
    # unmodified profile
    decrypted_profile = decrypt_profile(ciphertext)
    print(f"decrypted_profile={decrypted_profile}")
    # hacked profile
    decrypted_modified_profile = decrypt_profile(modified_ct)
    print(f"decrypted_modified_profile={decrypted_modified_profile}")
    assert decrypted_modified_profile['role'] == 'admin'
    print(f"\n{decrypted_modified_profile['email']} is now admin!!! :-P")



def test_crypto():
    input = "foo@bar.com" 
    ciphertext, profile = encrypt_profile(input)
    print(f"ciphertext={ciphertext.hex()}")
    output = decrypt_profile(ciphertext)
    assert profile == output
    print("test_crypto() passed.")

def format_profile(profile : dict):
    return '&'.join(f"{k}={v}" for k,v in profile.items())

def test_profile():
    profile = profile_for("foo@bar.com")
    print(profile)
    profile_str = format_profile(profile)
    print(profile_str)
    assert profile_str == "email=foo@bar.com&uid=10&role=user"
    print("test_profile() passed.")

def test_sanitization():
    profile = profile_for('foo@bar.com&role=admin')
    print(profile)
    assert profile['role'] == 'user'
    print("test_sanitization() passed.")

if __name__ == "__main__":
    # test_parse()
    # test_profile()
    # test_crypto()
    # test_sanitization()
    
    crack_admin(oracle_fn=encrypt_profile)




