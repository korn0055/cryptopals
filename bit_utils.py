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
        print(f"{b}={bin(b)}={bits_list_str}")
        assert int(b) == int(bits_list_str, 2)
    else:
        print("All iterations passed.")

def hamming_distance(a : bytes, b : bytes):
    assert len(a) == len(b)
    return sum([a_bit != b_bit for a_bit, b_bit in zip(bit_iterator(a), bit_iterator(b))])

def test_hamming_distance():
    a_test = "this is a test".encode("ascii")
    b_test = "wokka wokka!!!".encode("ascii")
    assert hamming_distance(a_test, b_test) == 37
    print("test_hamming_distance passed.")


if __name__ == "__main__":
    test_bit_iterator(100)
    test_hamming_distance()
