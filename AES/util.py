AES_BLOCK_SIZE = 16
from Crypto import Random


def determine_padding_and_remove(msg):
    """
    Translates the padding bytes in the last block and removes it from
    plaintext
    """
    padded_block = msg[-1]
    truncate = padded_block[-1]
    msg[-1] = padded_block[:-truncate]
    return msg


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


def blockify(msg, add_padding=False, block_size=AES_BLOCK_SIZE):
    """
    Transforms a byte string into a list of blocks of size block_size
    """
    default_pad = int.to_bytes(block_size, 1, 'big') * block_size
    blocks = []
    block = b''
    for byte in msg:
        block += bytes([byte])
        if len(block) == block_size:
            blocks.append(block)
            block = b''
    if len(block) == 0:
        if not add_padding:
            return blocks
        blocks.append(default_pad)
        return blocks

    if add_padding:
        block += padding(block)

    blocks.append(block)
    return blocks
