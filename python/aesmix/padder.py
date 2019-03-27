from __future__ import print_function, division

from Crypto.Util import number as _number

import math as _math


class Padder(object):
    """Padding class for Mix&Slice.

    Padder extends the ANSI.X923 padding and permits any blocksize.
    """

    @staticmethod
    def get_padinfosize(max_paddable_bits):
        """Returns how many bytes are needed to represent the padinfo.

        This takes into account the space required by the padding itself.

        Args:
            max_paddable_bits (int): how many bytes can be represented.

        Returns:
            The number of bytes required by the padinfo.
        """
        padinfosize = 1
        while _math.log(max_paddable_bits, 256) >= padinfosize:
            max_paddable_bits += 1
            padinfosize += 1
        return padinfosize

    def __init__(self, blocksize):
        """Initializes a Padder object.

        Args:
            blocksize (int): The size of the blocks.
        """
        self._blocksize = blocksize
        self._padinfosize = self.get_padinfosize(blocksize)

    def pad(self, data):
        """Pads the data to the blocksize and adds trailing padding info.

        Args:
            data (bytestr): the data to be padded.

        Returns:
            The padded bytestr.
        """
        padsize = self._padinfosize
        new_size = len(data) + padsize
        if new_size % self._blocksize != 0:
            zeros = self._blocksize - (new_size % self._blocksize)
            data += b'\x00' * zeros
            padsize += zeros

        data += _number.long_to_bytes(padsize, self._padinfosize)
        assert len(data) % self._blocksize == 0
        return data

    def unpad(self, data):
        """Unpads the data by removing the trailing padding data.

        Args:
            data (bytestr): the data to be unpadded.

        Returns:
            The unpadded bytestr.
        """
        padsize = _number.bytes_to_long(data[-self._padinfosize:])
        assert padsize >= self._padinfosize
        return data[:-padsize]


def _test(blocksize=256):
    """Tests one configuration of blocksize."""
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
