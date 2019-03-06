#!/usr/bin/env python

"""
Implementation based on "Key Regression: Enabling Efficient Key Distribution
for Secure Distributed Storage" (https://eprint.iacr.org/2005/303.pdf).
"""

import abc
import six
import hashlib
import collections

from Crypto.Util import number
from Crypto.Random import random
from Crypto.PublicKey import RSA


@six.add_metaclass(abc.ABCMeta)
class _KeyReg():

    @abc.abstractmethod
    def wind(self):
        pass

    @abc.abstractmethod
    def unwind(self):
        pass

    @abc.abstractmethod
    def keyder(self):
        pass


class KeyRegRSA(_KeyReg):

    _K = 1024
    _size = 2014
    _STM = collections.namedtuple("_STM", "N e S")
    _STP = collections.namedtuple("_STP", "N e d S")

    def __init__(self, stm=None, stp=None):
        if stm or stp:
            self._stm = stm
            self._stp = stp
        else:
            Krsa = RSA.generate(self._size)
            S = random.randrange(3, Krsa.n)
            self._stm = None
            self._stp = self._STP(Krsa.n, Krsa.e, Krsa.d, S)

    def wind(self):
        if self._stp is None:
            raise AttributeError("No publisher state. Can only unwind.")
        N, e, d, S = self._stp.N, self._stp.e, self._stp.d, self._stp.S
        S1 = pow(S, d, N)
        stp1 = self._STP(N, e, d, S1)
        stm = self._STM(N, e, S)
        return KeyRegRSA(stm=None, stp=stp1), KeyRegRSA(stm=stm, stp=None)

    def unwind(self):
        if self._stm is None:
            raise AttributeError("No member state. Can only wind.")
        N, e, S = self._stm.N, self._stm.e, self._stm.S
        S1 = pow(S, e, N)
        stm1 = self._STM(N, e, S1)
        return KeyRegRSA(stm=stm1, stp=None)

    def keyder(self):
        if self._stm is None:
            raise AttributeError("Do not keyder from publisher state.")
        mS = number.long_to_bytes(self._stm.S, blocksize=self._K)
        return hashlib.sha1(mS).digest()


if __name__ == "__main__":
    iters = 5
    stp = KeyRegRSA()

    print("== WINDING ==")
    for i in range(iters):
        stp, stm = stp.wind()
        print("k%i: %r" % (i, stm.keyder()))

    print("\n== UNWINDING ==")
    for i in range(iters - 1, -1, -1):
        print("k%i: %r" % (i, stm.keyder()))
        stm = stm.unwind()
