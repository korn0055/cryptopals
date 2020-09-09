import os

def bit_iterator(byte_string : bytes):
    for byte in byte_string:
        for i in range(8):
            yield (byte >> i) & 1

def test_bit_iterator(iterations):
    test_bytes = os.urandom(iterations)
    bits = bit_iterator(test_bytes)

    print(f"Comparing {len(test_bytes)} random bytes")
    for b in test_bytes:
        bits_list_str = ''.join(reversed([str(next(bits)) for _ in range(8)]))
        # print(f"{b}={bin(b)}={bits_list_str}")
        assert int(b) == int(bits_list_str, 2)
    else:
        print("test_bit_iterator passed.")

def hamming_distance(a : bytes, b : bytes):
    assert len(a) == len(b)
    return sum([a_bit != b_bit for a_bit, b_bit in zip(bit_iterator(a), bit_iterator(b))])

def test_hamming_distance():
    a_test = "this is a test".encode("ascii")
    b_test = "wokka wokka!!!".encode("ascii")
    assert hamming_distance(a_test, b_test) == 37
    print("test_hamming_distance passed.")

def chunkify(iterable, size):
    while iterable:
        yield iterable[:size]
        iterable = iterable[size:]

def bytes_xor(x : bytes, y : bytes):
    # assert isinstance(x, bytes)
    # assert isinstance(y, bytes)
    if isinstance(x, int):
        x = bytes([x])
    if isinstance(y, int):
        y = bytes([y])
    return bytes([a ^ b for a, b, in zip(x, y)])

def test_bytes_xor():
    x = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    y = bytes.fromhex('686974207468652062756c6c277320657965')
    z = bytes.fromhex('746865206b696420646f6e277420706c6179')
    assert bytes_xor(x, y) == z

    assert bytes_xor(120, 88) == bytes([32])
    print("test_bytes_xor passed.")

def test_chunkify():
    print("test_chunkify()")
    x = list(range(30))
    chunks = chunkify(x, 5)
    for chunk in chunks:
        print(chunk)

if __name__ == "__main__":
    test_bytes_xor()
    test_chunkify()
    test_bit_iterator(100)
    test_hamming_distance()
