#!/usr/bin/env python

from Crypto.Cipher import AES
import logging
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)

from math import log

class AESMIX:
    _BS = 16

    def __init__(self, key, mini_size=4, macro_num=1024):
        self._MIS = mini_size
        self._MIxMA = macro_num
        self._MIxB = self._BS / self._MIS
        self._MAS = self._MIS * self._MIxMA
        self._digits = int(log(self._MIxMA, 2))   # miniblock ID digits
        self._dof = int(log(self._MIxB, 2))  # free digits
        self._aes = AES.new(key, mode=AES.MODE_ECB)

    def _get_groups(self, step, start=0):
        #create #dof 1s, shift them to the left of round*dof
        unmask = (2**self._dof - 1) << (step * self._dof)
        dist = 2**(step * self._dof)  # distance of miniblock in same group
        groups = []
        while start < 2**self._digits:
            start &= ~unmask  # and with the negation of unmask (the mask)
            groups.append([start + (dist * i) for i in xrange(self._MIxB)])
            start += unmask + 1  # make the step
        return groups

    def _step(self, macro, step, fn):
        logging.debug('STEP #%d' % step)
        for group in self._get_groups(step):
            logging.debug('GROUP: ' + ','.join(map(str, group)))
            indexes = [(g*self._MIS, (g+1)*self._MIS) for g in group]
            CB = fn(''.join([str(macro[s:t]) for s,t in indexes]))
            for i, idx in enumerate(indexes):
                macro[idx[0]:idx[1]] = CB[i*self._MIS:(i+1)*self._MIS]
        return macro

    def _encryptmacroblock(self, macro):
        assert len(macro) == self._MAS
        for step in xrange(self._digits / self._dof):
            macro = self._step(macro, step, self._aes.encrypt)
        return macro

    def _decryptmacroblock(self, macro):
        assert len(macro) == self._MAS
        for step in xrange(self._digits / self._dof - 1, -1, -1):
            macro = self._step(macro, step, self._aes.decrypt)
        return macro

    def __process(self, data, fn):
        assert len(data) % self._MAS == 0
        data, result = bytearray(data), bytearray()
        for i in xrange(len(data) / self._MAS):
            macro = data[i*self._MAS:(i+1)*self._MAS]
            logging.debug('MACRO #%d: %r' % (i, macro))
            result.extend(fn(macro))
        return result

    def encrypt(self, data):
        return self.__process(data, self._encryptmacroblock)

    def decrypt(self, data):
        return self.__process(data, self._decryptmacroblock)
