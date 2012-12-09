from Crypto.Cipher import AES
AESCipher = AES.AESCipher
from Crypto.Cipher.AES import AESCipher

from util import random, determine_padding_and_remove, blockify
from ctr_util import encrypt_block, decrypt_block


def encrypt(msg, key, iv=random(), cipher_class=AESCipher):
    """
    Encrypt a byte string using CTR mode
    """
    cipher = cipher_class(key)
    msg_blocks = blockify(msg)

    c = [iv]
    for count, m in enumerate(msg_blocks):
        c.append(encrypt_block(m, cipher, iv, count))
    return b''.join(c)


def decrypt(cipher_text, key, cipher_class=AESCipher):
    """
    Decrypt a byte string using CTR mode
    """
    cipher = cipher_class(key)
    cipher_blocks = blockify(cipher_text)

    iv = cipher_blocks.pop(0)
    msg = []
    for count, c in enumerate(cipher_blocks):
        msg.append(decrypt_block(c, cipher, iv, count))
    return b''.join(determine_padding_and_remove(msg))
