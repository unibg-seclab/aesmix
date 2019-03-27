from __future__ import print_function, division

from Crypto.Util import number as _number

import math as _math


class Padder(object):

    @staticmethod
    def get_padinfosize(max_paddable_bits):
        padinfosize = 1
        while _math.log(max_paddable_bits, 256) >= padinfosize:
            max_paddable_bits += 1
            padinfosize += 1
        return padinfosize

    def __init__(self, bytesize):
        self._bytesize = bytesize
        self._padinfosize = self.get_padinfosize(bytesize)

    def pad(self, data):
        padsize = self._padinfosize
        new_size = len(data) + padsize
        if new_size % self._bytesize != 0:
            zeros = self._bytesize - (new_size % self._bytesize)
            data += b'\x00' * zeros
            padsize += zeros

        data += _number.long_to_bytes(padsize, self._padinfosize)
        assert len(data) % self._bytesize == 0
        return data

    def unpad(self, data):
        padsize = _number.bytes_to_long(data[-self._padinfosize:])
        assert padsize >= self._padinfosize
        return data[:-padsize]


def _test(blocksize=256):
    print("Testing blocksize %d ... " % blocksize, end="")
    padder = Padder(blocksize)
    for size in (0, 1, blocksize - 2, blocksize - 1, blocksize):
        data = b"a" * max(0, size - 1) + (b"b" if size else b"")
        assert len(data) == size
        padded = padder.pad(data)
        assert len(padded) % blocksize == 0
        unpadded = padder.unpad(padded)
        assert unpadded == data
    print("OK")


if __name__ == "__main__":
    _test(blocksize=16)
    _test(blocksize=254)
    _test(blocksize=255)
    _test(blocksize=256)
    _test(blocksize=256*256)
