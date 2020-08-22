s = "some\x00string. with\x15 funny characters"
import string
printable = set(string.printable)
output = ''.join(filter(lambda x: x in printable, s))
print(output)
