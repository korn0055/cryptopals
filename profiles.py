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

    ciphertext, _ = oracle_fn("bla@thisisntit.com")
    print(f"ciphertext={ciphertext.hex()}")
    decrypted_profile = decrypt_profile(ciphertext)
    print(f"decrypted_profile={decrypted_profile}")
    # assert decrypted_profile['role'] == 'admin'



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




