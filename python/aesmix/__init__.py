from aesmix import keyreg
from aesmix._aesmix import lib as _lib, ffi


def _mixprocess(data, key, iv, fn, to_string):
    assert len(key) == 16, "key must be 16 bytes long"
    assert len(iv) == 16, "iv must be 16 bytes long"
    assert len(data) % _lib.MACRO_SIZE == 0, \
        "plaintext size must be a multiple of %d" % _lib.MACRO_SIZE

    _data = ffi.new("unsigned char[]", data)
    _out = ffi.new("unsigned char[]", len(data))
    _size = ffi.cast("unsigned long", len(data))
    _key = ffi.new("unsigned char[]", key)
    _iv = ffi.new("unsigned char[]", iv)

    fn(_data, _out, _size, _key, _iv)
    res = ffi.buffer(_out, len(data))
    return res[:] if to_string else res


def mixencrypt(data, key, iv, to_string=True):
    return _mixprocess(data, key, iv, _lib.mixencrypt, to_string)


def mixdecrypt(data, key, iv, to_string=True):
    return _mixprocess(data, key, iv, _lib.mixdecrypt, to_string)
