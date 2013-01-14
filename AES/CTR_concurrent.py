"""
Concurrent implementation of AES in CTR mode
"""
import multiprocessing
from Crypto.Cipher import AES
AESCipher = AES.AESCipher
from Crypto.Cipher.AES import AESCipher

from .util import random, determine_padding_and_remove, blockify
from .ctr_util import encrypt_block, decrypt_block


def encrypt_worker(queue, *args):
    queue.put((encrypt_block(*args), args[3],))


def decrypt_worker(queue, *args):
    queue.put((decrypt_block(*args), args[3],))


def encrypt(msg, key, iv=random(), cipher_class=AESCipher):
    """
    Encrypt a byte string using CTR mode
    """
    cipher = cipher_class(key)
    msg_blocks = blockify(msg, add_padding=True)
    q = multiprocessing.JoinableQueue()

    processes = [
        multiprocessing.Process(
            target=encrypt_worker,
            args=(q, m, cipher, iv, count,)
        ) for count, m in enumerate(msg_blocks)
    ]
    for p in processes:
        p.start()
    for p in processes:
        p.join()

    cipher_blocks = [None] * len(msg_blocks)
    while not q.empty():
        res = q.get()
        cipher_blocks[res[1]] = res[0]
    return b''.join([iv] + cipher_blocks)


def decrypt(cipher_text, key, cipher_class=AESCipher):
    """
    Decrypt a byte string using CTR mode
    """
    cipher = cipher_class(key)
    cipher_blocks = blockify(cipher_text)
    q = multiprocessing.JoinableQueue()
    iv = cipher_blocks.pop(0)

    processes = [
        multiprocessing.Process(
            target=decrypt_worker,
            args=(q, b, cipher, iv, count,)
        ) for count, b in enumerate(cipher_blocks)
    ]

    for p in processes:
        p.start()
    for p in processes:
        p.join()

    msg = [None] * len(cipher_blocks)
    while not q.empty():
        res = q.get()
        msg[res[1]] = res[0]

    return b''.join(determine_padding_and_remove(msg))
