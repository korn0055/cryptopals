import binascii

def hex_xor(a, b):
    a = bytes.fromhex(a)
    b = bytes.fromhex(b)

    out = bytes([x ^ y for x, y in zip(a, b)])

    return binascii.hexlify(out).decode("ascii")

test_a = "1c0111001f010100061a024b53535009181c"
test_b = "686974207468652062756c6c277320657965"
test_out = "746865206b696420646f6e277420706c6179"

out = (hex_xor(test_a, test_b))
print(out)

assert test_out == out
