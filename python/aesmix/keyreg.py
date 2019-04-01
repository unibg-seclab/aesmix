"""
Implementation based on "Key Regression: Enabling Efficient Key Distribution
for Secure Distributed Storage" (https://eprint.iacr.org/2005/303.pdf).
"""

import abc as _abc
import six as _six
import hashlib as _hashlib
import collections as _collections

from Crypto.Util import number as _number
from Crypto.Random import random as _random
from Crypto.PublicKey import RSA as _RSA


@_six.add_metaclass(_abc.ABCMeta)
class _KeyReg():

    @_abc.abstractmethod
    def wind(self):
        pass

    @_abc.abstractmethod
    def unwind(self):
        pass

    @_abc.abstractmethod
    def keyder(self):
        pass


class KeyRegRSA(_KeyReg):

    _K = 1024
    _size = 2014
    _STM = _collections.namedtuple("_STM", "N e S")
    _STP = _collections.namedtuple("_STP", "N e d S")

    def __init__(self, stm=None, stp=None, S=None):
        if stm or stp:
            self._stm = stm
            self._stp = stp
        else:
            Krsa = _RSA.generate(self._size)
            S = S or _random.randrange(3, Krsa.n)
            assert 3 <= S <= Krsa.n
            self._stm = None
            self._stp = self._STP(Krsa.n, Krsa.e, Krsa.d, S)

    @staticmethod
    def load(Krsa, S):
        """Loads a KeyRegRSA from a private/public key data and state S.

        Args:
            Krsa (Crypto.PublicKey.Rsa): the RSA key.
            S (long): the state of the KeyRegRSA.
        """
        if Krsa.has_private():
            stp = KeyRegRSA._STP(Krsa.n, Krsa.e, Krsa.d, S)
            return KeyRegRSA(stm=None, stp=stp)
        else:
            stm = KeyRegRSA._STM(Krsa.n, Krsa.e, S)
            return KeyRegRSA(stm=stm, stp=None)

    def get_state(self, private):
        if private:
            if self.is_publisher():
                return self._stp.S
            else:
                raise Exception("Can't save private state from STM.")
        else:
            if self.is_publisher():
                return self.unwind().get_state(private)
            else:
                return self._stm.S

    def get_rsakey(self, private):
        if private:
            if self.is_publisher():
                return _RSA.construct((self._stp.N, self._stp.e, self._stp.d))
            else:
                raise Exception("Can't save private state from STM.")
        else:
            stm = self._stp if self.is_publisher() else self._stm
            return _RSA.construct((stm.N, stm.e))

    def is_publisher(self):
        return self._stp is not None

    def wind(self):
        if self._stp is None:
            raise AttributeError("No publisher state. Can only unwind.")
        N, e, d, S = self._stp.N, self._stp.e, self._stp.d, self._stp.S
        S1 = pow(S, d, N)
        stp1 = self._STP(N, e, d, S1)
        stm = self._STM(N, e, S)
        return KeyRegRSA(stm=None, stp=stp1), KeyRegRSA(stm=stm, stp=None)

    def unwind(self):
        stm = self._stm or self._stp
        N, e, S = stm.N, stm.e, stm.S
        S1 = pow(S, e, N)
        stm1 = self._STM(N, e, S1)
        return KeyRegRSA(stm=stm1, stp=None)

    def keyder(self):
        if self._stm is None:
            raise AttributeError("Unwind before keyder from publisher state.")
        mS = _number.long_to_bytes(self._stm.S, blocksize=self._K)
        return _hashlib.sha1(mS).digest()


def _main():
    print("\n\ntest key regression using KeyRegRSA")
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


if __name__ == "__main__":
    _main()
