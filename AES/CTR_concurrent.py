"""
Concurrent implementation of AES in CTR mode
"""
import gevent
from Crypto.Cipher import AES
AESCipher = AES.AESCipher
from Crypto.Cipher.AES import AESCipher

from util import random
from ctr_util import (
    encrypt_block,
    decrypt_block,
    determine_padding_and_remove,
    blockify
)


def encrypt(msg, key, iv=random(), cipher_class=AESCipher):
    """
    Encrypt a byte string using CTR mode
    """
    cipher = cipher_class(key)
    msg_blocks = blockify(msg)

    threads = [
        gevent.spawn(encrypt_block, m, cipher, iv, count) for count, m in enumerate(msg_blocks)
    ]
    gevent.joinall(threads)
    return b''.join([iv] + [x.get() for x in threads])


def decrypt(cipher_text, key, cipher_class=AESCipher):
    """
    Decrypt a byte string using CTR mode
    """
    cipher = cipher_class(key)
    cipher_blocks = blockify(cipher_text)
    iv = cipher_blocks.pop(0)
    threads = [
        gevent.spawn(decrypt_block, block, cipher, iv, count) for count, block in enumerate(cipher_blocks)
    ]
    gevent.joinall(threads)
    msg = [x.get() for x in threads]

    return b''.join(determine_padding_and_remove(msg))
