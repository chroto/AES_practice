"""
Week 2: Intro to cryptography

AES Stream cipher implementations:

    CBC Mode
"""
from Crypto.Cipher import AES
AESCipher = AES.AESCipher
from Crypto.Cipher.AES import AESCipher

from util import *


def encrypt(msg, key, iv=random(), cipher_class=AESCipher):
    cipher = cipher_class(key)
    msg_blocks = []
    block = b''
    for byte in msg:
        block += byte.to_bytes(1, byteorder='big')
        if len(block) % AES_BLOCK_SIZE == 0:
            msg_blocks.append(block)
            block = b''
    if len(block) != 0:
        block += padding(block)
        msg_blocks.append(block)

    prev_cipher = iv
    c = []
    for m in msg_blocks:
        prev_cipher = cipher.encrypt(xor(prev_cipher, m))
        c.append(prev_cipher)
    return iv + b''.join(c)


def decrypt(cipher_text, key, cipher_class=AESCipher):
    cipher = cipher_class(key)
    assert len(cipher_text) >= 2
    cipher_blocks = []
    block = b''
    for byte in cipher_text:
        block += byte.to_bytes(1, byteorder='big')
        if len(block) % AES_BLOCK_SIZE == 0:
            cipher_blocks.append(block)
            block = b''

    prev_cipher = cipher_blocks.pop(0)  # IV
    msg = []
    for block in cipher_blocks:
        pre_msg = cipher.decrypt(block)
        msg.append(xor(cipher.decrypt(block), prev_cipher))
        prev_cipher = block

    padded_block = msg[-1]
    truncate = padded_block[-1]
    msg[-1] = padded_block[:-truncate]
    return b''.join(msg)
