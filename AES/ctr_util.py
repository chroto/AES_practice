import struct
from .util import xor


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
