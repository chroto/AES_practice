AES_BLOCK_SIZE = 16
from Crypto import Random


def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


def xor(a, b):
    if len(a) > len(b):
        return bytes([x ^ y for x, y in zip(a[:len(b)], b)])
    else:
        return bytes([x ^ y for x, y in zip(a, b[:len(a)])])


def random(size=AES_BLOCK_SIZE):
    return Random.new().read(size)


def padding(block, size=AES_BLOCK_SIZE):
    pad = bytes([size - len(block)])
    return pad * (size - len(block))
