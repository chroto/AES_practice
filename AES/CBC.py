from Crypto.Cipher import AES
AESCipher = AES.AESCipher
from Crypto.Cipher.AES import AESCipher

from util import blockify, random, xor, determine_padding_and_remove


def encrypt(msg, key, iv=random(), cipher_class=AESCipher):
    """
    Encrypt a byte string using CBC mode
    """
    cipher = cipher_class(key)
    msg_blocks = blockify(msg)

    prev_cipher = iv
    c = []
    for m in msg_blocks:
        prev_cipher = cipher.encrypt(xor(prev_cipher, m))
        c.append(prev_cipher)
    return iv + b''.join(c)


def decrypt(cipher_text, key, cipher_class=AESCipher):
    """
    Decrypt a byte string using CBC mode
    """
    cipher = cipher_class(key)
    cipher_blocks = blockify(cipher_text)

    prev_cipher = cipher_blocks.pop(0)  # IV
    msg = []
    for block in cipher_blocks:
        msg.append(xor(cipher.decrypt(block), prev_cipher))
        prev_cipher = block

    return b''.join(determine_padding_and_remove(msg))
