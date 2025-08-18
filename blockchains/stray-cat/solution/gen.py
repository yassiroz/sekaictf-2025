ADDRESS = "0xe518b603c9f181442989230F9225aB54df59d183"
from Crypto.Hash import keccak
k = keccak.new(digest_bits=256)
k.update(b"Purr()")
TARGET = k.digest()
from rlp import encode
target_address = bytes.fromhex(ADDRESS.replace("0x", ""))
thing = encode([[target_address, [TARGET], b""]])
print(list(thing))
