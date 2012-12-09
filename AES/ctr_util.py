import struct
from util import xor, AES_BLOCK_SIZE, padding


def blockify(msg, block_size=AES_BLOCK_SIZE):
    """
    Transforms a byte string into a list of blocks of size block_size
    """
    blocks = []
    block = b''
    for byte in msg:
        block += bytes([byte])
        if len(block) % block_size == 0:
            blocks.append(block)
            block = b''
    if len(block) != 0:
        block += padding(block)
        blocks.append(block)
    return blocks


def determine_padding_and_remove(msg):
    """
    Translates the padding bytes in the last block and removes it from
    plaintext
    """
    padded_block = msg[-1]
    truncate = padded_block[-1]
    msg[-1] = padded_block[:-truncate]
    return msg


def encrypt_block(msg_block, cipher, iv, count):
    """
    Takes a block and XORs it with a block cipher based on its order in the
    message indicated by count.
    """
    counter = iv[8:]  # last 8 are counter
    iv = bytes(iv[:8])
    counter = struct.unpack('>Q', counter)[0] + count
    iv = iv + struct.pack('>Q', counter)
    return xor(msg_block, cipher.encrypt(iv))

decrypt_block = encrypt_block  # decrypting and encrypting are the same.
