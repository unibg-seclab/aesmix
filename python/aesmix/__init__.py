from aesmix import keyreg
from aesmix._aesmix import lib as _lib, ffi


def _mixprocess(data, key, iv, fn, to_string, threads=1):
    assert len(key) == 16, "key must be 16 bytes long"
    assert len(iv) == 16, "iv must be 16 bytes long"
    assert threads >= 1, "you must use at least one thread"
    assert len(data) % _lib.MACRO_SIZE == 0, \
        "plaintext size must be a multiple of %d" % _lib.MACRO_SIZE

    _data = ffi.new("unsigned char[]", data)
    _out = ffi.new("unsigned char[]", len(data))
    _size = ffi.cast("unsigned long", len(data))
    _thr = ffi.cast("unsigned int", threads)
    _key = ffi.new("unsigned char[]", key)
    _iv = ffi.new("unsigned char[]", iv)

    if threads == 1:
        fn(_data, _out, _size, _key, _iv)
    else:
        fn(_thr, _data, _out, _size, _key, _iv)

    res = ffi.buffer(_out, len(data))
    return res[:] if to_string else res


def mixencrypt(data, key, iv, to_string=True):
    """Encrypts the data using Mix&Slice (mixing phase).

    Args:
        data (bytestr): The data to encrypt. Must be a multiple of MACRO_SIZE.
        key (bytestr): The key used for AES encryption. Must be 16 bytes long.
        iv (bytestr): The iv used for AES encryption. Must be 16 bytes long.
        to_string (bool): returns a bytestr if true, ffi.buffer otherwise.

    Returns:
        An encrypted bytestr if to_string is true, ffi.buffer otherwise.
    """
    return _mixprocess(data, key, iv, _lib.mixencrypt, to_string)


def mixdecrypt(data, key, iv, to_string=True):
    """Decrypts the data using Mix&Slice (mixing phase).

    Args:
        data (bytestr): The data to decrypt. Must be a multiple of MACRO_SIZE.
        key (bytestr): The key used for AES decryption. Must be 16 bytes long.
        iv (bytestr): The iv used for AES decryption. Must be 16 bytes long.
        to_string (bool): returns a bytestr if true, ffi.buffer otherwise.

    Returns:
        A decrypted bytestr if to_string is true, ffi.buffer otherwise.
    """
    return _mixprocess(data, key, iv, _lib.mixdecrypt, to_string)


def t_mixencrypt(data, key, iv, threads, to_string=True):
    """Encrypts the data using Mix&Slice (mixing phase) using multiple threads.

    Args:
        data (bytestr): The data to encrypt. Must be a multiple of MACRO_SIZE.
        key (bytestr): The key used for AES encryption. Must be 16 bytes long.
        iv (bytestr): The iv used for AES encryption. Must be 16 bytes long.
        threads (int): The number of threads used for encryption.
        to_string (bool): returns a bytestr if true, ffi.buffer otherwise.

    Returns:
        An encrypted bytestr if to_string is true, ffi.buffer otherwise.
    """
    return _mixprocess(data, key, iv, _lib.t_mixencrypt, to_string, threads)


def t_mixdecrypt(data, key, iv, threads, to_string=True):
    """Decrypts the data using Mix&Slice (mixing phase) using multiple threads.

    Args:
        data (bytestr): The data to decrypt. Must be a multiple of MACRO_SIZE.
        key (bytestr): The key used for AES decryption. Must be 16 bytes long.
        iv (bytestr): The iv used for AES decryption. Must be 16 bytes long.
        threads (int): The number of threads used for decryption.
        to_string (bool): returns a bytestr if true, ffi.buffer otherwise.

    Returns:
        A decrypted bytestr if to_string is true, ffi.buffer otherwise.
    """
    return _mixprocess(data, key, iv, _lib.t_mixdecrypt, to_string, threads)


