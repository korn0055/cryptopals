import string

nums = list(range(10))
letters = [chr(ord('A') + x) for x in nums]

print(nums)
print(letters)
zipped = zip(nums, letters)

for n, l in zipped:
    print(f"n={n}, l={l}")