import itertools


def hex_to_base64(hex_string):
    
    raw_ints = []
    print('len(hexstring)', len(hex_string))
    i = 0
    while len(hex_string) > 0:
        raw_ints += [int(hex_string[:2], 16)]
        hex_string = hex_string[2:]

    raw_bytes = bytes(raw_ints)
    print(len(raw_bytes))
    print('bytes:', raw_bytes)

    def get_bit(x):
        for b in x:
            for i in range(8):
                bit = (b >> (7-i)) & 1
                yield bit

    def get_next_6bit(iterable):
        iterator = iter(iterable)
        try:
            while True:
                table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
                bits = [next(iterator) << (5-i) for i in range(6)]
                yield table[sum(bits)]
        except StopIteration:
            pass
    
    return ''.join(list(get_next_6bit(get_bit(raw_bytes))))

if __name__ == "__main__":
    input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"



    output = hex_to_base64(input)
    print('input:', input)
    print(output)
    print(f"Match={expected == output}")
