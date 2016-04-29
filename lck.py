#!/usr/bin/env python

from Crypto.Cipher import AES
import logging
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)

from math import log

class AESLCK:
    _CIPHER_BLOCK = 16

    def __init__(self, key, frag_size=4, frags_per_block=1024):
        self._FS = frag_size
        self._FPB = frags_per_block
        self._frags_per_cipher = self._CIPHER_BLOCK / self._FS
        self._block_size = self._FS * self._FPB
        self._digits = int(log(self._FPB, 2))   # fragment ID digits
        self._dof = int(log(self._frags_per_cipher, 2))  # free digits
        self._aes = AES.new(key, mode=AES.MODE_ECB)

    def _get_groups(self, step, start=0):
        #create #dof 1s, shift them to the left of round*dof
        unmask = (2**self._dof - 1) << (step * self._dof)
        dist = 2**(step * self._dof)
        while start < 2**self._digits:
            # and with the negation of unmask (the mask)
            start &= ~unmask
            yield [start + (dist * i) for i in xrange(self._frags_per_cipher)]
            start += unmask + 1

    def _step(self, block, step, fn):
        logging.debug('STEP #%d' % step)
        for group in self._get_groups(step):
            logging.debug('GROUP: ' + ','.join(map(str, group)))
            indexes = [(g*self._FS, (g+1)*self._FS) for g in group]
            CB = fn(''.join(str(block[idx[0]:idx[1]]) for idx in indexes))
            for i, idx in enumerate(indexes):
                data = CB[i*self._FS:(i+1)*self._FS]
                block[idx[0]:idx[1]] = CB[i*self._FS:(i+1)*self._FS]
        return block

    def _encryptblock(self, block):
        assert len(block) == self._block_size
        for step in xrange(self._digits / self._dof):
            block = self._step(block, step, self._aes.encrypt)
        return block

    def _decryptblock(self, block):
        assert len(block) == self._block_size
        for step in xrange(self._digits / self._dof - 1, -1, -1):
            block = self._step(block, step, self._aes.decrypt)
        return block

    def __shuffle(self, data, step):
        size = len(data)
        for block in xrange(step):
            yield bytearray(byte
                    for offset in xrange(block, size / self._FS, step)
                    for byte in data[offset*self._FS : (offset+1) * self._FS])

    def _shuffle(self, data):
        return self.__shuffle(data, len(data) / self._block_size)

    def _unshuffle(self, data):
        return self.__shuffle(data, self._FPB)

    def __process(self, data, fn):
        assert len(data) % self._block_size == 0
        result = bytearray()
        for i, block in enumerate(self._shuffle(data)):
            logging.debug('BLOCK #%d: %r' % (i, block))
            result.extend(fn(block))
        return ''.join(map(str, self._unshuffle(result)))

    def encrypt(self, data):
        return self.__process(data, self._encryptblock)

    def decrypt(self, data):
        return self.__process(data, self._decryptblock)
