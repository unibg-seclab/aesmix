from aesmix._aesmix import lib as _lib, ffi

from multiprocessing import cpu_count as _cpu_count
from six.moves import xrange as _xrange


def _mixprocess(data, key, iv, fn, to_string, threads=None):
    threads = threads if threads is not None else _cpu_count()
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

    if fn in (_lib.mixencrypt, _lib.mixdecrypt):
        fn(_data, _out, _size, _key, _iv)
    elif fn in (_lib.t_mixencrypt, _lib.t_mixdecrypt):
        fn(_thr, _data, _out, _size, _key, _iv)
    else:
        raise Exception("unknown mix function %r" % fn)

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


def t_mixencrypt(data, key, iv, threads=None, to_string=True):
    """Encrypts the data using Mix&Slice (mixing phase) using multiple threads.

    Args:
        data (bytestr): The data to encrypt. Must be a multiple of MACRO_SIZE.
        key (bytestr): The key used for AES encryption. Must be 16 bytes long.
        iv (bytestr): The iv used for AES encryption. Must be 16 bytes long.
        threads (int): The number of threads used. (default: cpu count).
        to_string (bool): returns a bytestr if true, ffi.buffer otherwise.

    Returns:
        An encrypted bytestr if to_string is true, ffi.buffer otherwise.
    """
    return _mixprocess(data, key, iv, _lib.t_mixencrypt, to_string, threads)


def t_mixdecrypt(data, key, iv, threads=None, to_string=True):
    """Decrypts the data using Mix&Slice (mixing phase) using multiple threads.

    Args:
        data (bytestr): The data to decrypt. Must be a multiple of MACRO_SIZE.
        key (bytestr): The key used for AES decryption. Must be 16 bytes long.
        iv (bytestr): The iv used for AES decryption. Must be 16 bytes long.
        threads (int): The number of threads used. (default: cpu count).
        to_string (bool): returns a bytestr if true, ffi.buffer otherwise.

    Returns:
        A decrypted bytestr if to_string is true, ffi.buffer otherwise.
    """
    return _mixprocess(data, key, iv, _lib.t_mixdecrypt, to_string, threads)


def islice(data, mini_size=_lib.MINI_SIZE, macro_size=_lib.MACRO_SIZE):
    """Slices data into fragments using Mix&Slice (slicing phase).

    Args:
        data (bytestr): The data to slice. Must be a multiple of MACRO_SIZE.
        mini_size (int): The miniblock size. (default: provided by the lib).
        macro_size (int): The macroblock size. (default: provided by the lib).

    Yields:
        Generates the encrypted fragments one at a time.
    """
    assert len(data) % macro_size == 0, \
        "plaintext size must be a multiple of %d" % macro_size

    dataview = memoryview(data)
    for fragment_offset in _xrange(0, macro_size, mini_size):
        yield b"".join(
            dataview[mini_offset:mini_offset + mini_size]
            for mini_offset in _xrange(fragment_offset, len(data), macro_size))


def slice(data, mini_size=_lib.MINI_SIZE, macro_size=_lib.MACRO_SIZE):
    """Slices data into fragments using Mix&Slice (slicing phase).

    Args:
        data (bytestr): The data to slice. Must be a multiple of MACRO_SIZE.
        mini_size (int): The miniblock size. (default: provided by the lib).
        macro_size (int): The macroblock size. (default: provided by the lib).

    Returns:
        A list of encrypted fragments.
    """
    return list(islice(data, mini_size, macro_size))


def mix_and_slice(data, key, iv, threads=None,
                  mini_size=_lib.MINI_SIZE, macro_size=_lib.MACRO_SIZE):
    """Perform the whole Mix&Slice encryption (mixing and slicing phases).

    Args:
        data (bytestr): The data to decrypt. Must be a multiple of MACRO_SIZE.
        key (bytestr): The key used for AES encryption. Must be 16 bytes long.
        iv (bytestr): The iv used for AES encryption. Must be 16 bytes long.
        threads (int): The number of threads used. (default: cpu count).
        mini_size (int): The miniblock size. (default: provided by the lib).
        macro_size (int): The macroblock size. (default: provided by the lib).

    Returns:
        A list of encrypted fragments.
    """
    ciphertext = t_mixencrypt(data, key, iv, threads, to_string=False)
    return slice(ciphertext, mini_size, macro_size)


def unslice_and_unmix(fragments, key, iv, threads=None,
                      mini_size=_lib.MINI_SIZE, macro_size=_lib.MACRO_SIZE):
    """Perform the whole Mix&Slice decryption (mixing and slicing phases).

    Args:
        fragments (list[bytestr]): The fragments to decrypt.
        key (bytestr): The key used for AES decryption. Must be 16 bytes long.
        iv (bytestr): The iv used for AES decryption. Must be 16 bytes long.
        threads (int): The number of threads used. (default: cpu count).
        mini_size (int): The miniblock size. (default: provided by the lib).
        macro_size (int): The macroblock size. (default: provided by the lib).

    Returns:
        The decrypted bytestring.
    """
    frag_length = len(fragments[0])
    fragmentviews = list(map(memoryview, fragments))

    ciphertext = b"".join(
        fragmentview[mini_offset:mini_offset + mini_size]
        for mini_offset in _xrange(0, frag_length, mini_size)
        for fragmentview in fragmentviews)

    return t_mixdecrypt(ciphertext, key, iv, threads, to_string=True)
