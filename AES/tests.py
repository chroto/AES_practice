def test_blockify_under_block_size_without_padding():
    from .util import blockify
    assert [b'foo'] == blockify(b'foo', block_size=16)


def test_blockify_under_block_size_with_padding():
    from .util import blockify
    assert [b'foo' + (b'\x0d' * 13)] == blockify(b'foo', add_padding=True, block_size=16)


def test_blockify_with_block_size():
    from .util import blockify
    bs = 16
    assert [b'a' * bs] == blockify(b'a' * bs, block_size=bs)


def test_blockify_with_block_size_and_padding():
    from .util import blockify
    bs = 16
    assert [b'a' * bs, b'\x10' * 16] == blockify(b'a' * bs, add_padding=True, block_size=bs)


def test_blockify_over_block_size():
    from .util import blockify
    bs = 16
    assert [b'a' * bs, b'a'] == blockify(b'a' * (bs + 1), block_size=bs)


def test_blockify_over_block_size_and_padding():
    from .util import blockify
    bs = 16
    assert [b'a' * bs, b'a' + b'\x0f' * 15] == blockify(b'a' * (bs + 1), add_padding=True, block_size=bs)


## Functional Tests
def test_ctr_concurrent():
    from .CTR_concurrent import encrypt, decrypt
    bs = 16
    msg = b'foo'
    key = '\x00' * bs
    assert msg == decrypt(encrypt(msg, key), key)


def test_ctr():
    from .CTR import encrypt, decrypt
    bs = 16
    msg = b'foo'
    key = '\x00' * bs
    assert msg == decrypt(encrypt(msg, key), key)


def test_cbc():
    from .CBC import encrypt, decrypt
    bs = 16
    msg = b'foo'
    key = '\x00' * bs
    assert msg == decrypt(encrypt(msg, key), key)
