from Crypto.PublicKey import RSA as _RSA
from Crypto.Cipher import AES as _AES
from Crypto.Util import Counter as _Counter
from six.moves import xrange as _xrange

from aesmix.keyreg import KeyRegRSA as _KeyRegRSA
from aesmix.padder import Padder as _Padder
from aesmix._aesmix import lib as _lib
import aesmix as _aesmix

from base64 import b64encode as _b64encode, b64decode as _b64decode
import json as _json
import random as _random
import logging as _logging

# cryptographically secure PRNG
_random = _random.SystemRandom()


class _MixSliceMetadata(object):

    def __init__(self, key, iv, rsakey=None, order=None, state=None):
        """Instantiates a MixSliceMetadata.

        Args:
            key (bytestr): The key used for AES encryption (16 bytes long).
            iv (bytestr): initialization vector for the mixing phase.
            rsakey (bytestr): The rsakey used for key derivation. If None,
                a new rsa keypair is generated.
            order (list[int]): The list of fragment ids to which
                the layer of encryption was applied. The leftmost id is the
                innermost layer of encryption. If None, an empty list.
            state (bytestr): The last state for key derivation. If None,
                a random state is generated.

        Returns:
            The MixSliceMetadata object.
        """
        rsakey = rsakey or _RSA.generate(2048)
        order = order or []
        state = state or _random.randrange(3, rsakey.n)
        assert 3 <= state <= rsakey.n
        self._key = key
        self._iv = iv
        self._order = order
        self._keyreg = _KeyRegRSA.load(rsakey, state)

    @staticmethod
    def load_from_file(metadatafile):
        """Loads the metadata from a file.

        Args:
            metadatafile (path): The path for the metadatafile.

        Returns:
            The MixSliceMetadata object created from reading the file.
        """
        with open(metadatafile, "r") as fp:
            metadata = _json.load(fp)

        return _MixSliceMetadata(
            key=_b64decode(metadata["key"].encode("ascii")),
            iv=_b64decode(metadata["iv"].encode("ascii")),
            rsakey=_RSA.importKey(metadata["rsakey"].encode("ascii")),
            order=metadata["order"],
            state=metadata["state"])

    def save_to_file(self, metadatafile, private):
        """Saves the metadata to file.

        Args:
            metadatafile (path): The path for the metadatafile.
            private (bool): Save also the private key.
        """
        state = self._keyreg.get_state(private)
        rsakey = self._keyreg.get_rsakey(private)

        metadata = {
            "key": _b64encode(self._key).decode("ascii"),
            "iv": _b64encode(self._iv).decode("ascii"),
            "rsakey": rsakey.exportKey().decode("ascii"),
            "order": self._order,
            "state": state,
        }

        with open(metadatafile, "w") as fp:
            _json.dump(metadata, fp)

    def is_private(self):
        return self._rsakey.has_private()

    def add_encryption_step(self, fragment_id):
        self._order.append(fragment_id)
        self._keyreg, stm = self._keyreg.wind()
        return stm.keyder()

    def decryption_steps(self):
        keyreg = self._keyreg
        stm = keyreg.unwind() if keyreg.is_publisher() else keyreg
        for fragment_id in reversed(self._order):
            yield fragment_id, stm.keyder()
            stm = stm.unwind()


class MixSlice(object):

    def __init__(self, fragments, metadata):
        self._fragments = fragments
        self._metadata = metadata

    @staticmethod
    def encrypt(data, key, iv, threads=None, rsakey=None,
                state=None, padder=None):
        """Creates a MixSlice from plaintext data.

        Args:
            data (bytestr): The data to encrypt (multiple of MACRO_SIZE).
            key (bytestr): The key used for AES encryption (16 bytes long).
            iv (bytestr): The iv used for AES encryption (16 bytes long).
            threads (int): The number of threads used. (default: cpu count).
            rsakey (bytestr): The rsakey used for key derivation. If None,
                a new rsa keypair is generated.
            state (bytestr): The last state for key derivation. If None,
                a random state is generated.

        Returns:
            A new MixSlice that holds the encrypted fragments.
        """
        padder = padder or _Padder(blocksize=_lib.MACRO_SIZE)
        padded_data = padder.pad(data)
        fragments = _aesmix.mix_and_slice(data=padded_data, key=key,
                                          iv=iv, threads=threads)
        metadata = _MixSliceMetadata(key=key, iv=iv, order=None,
                                     rsakey=rsakey, state=state)
        return MixSlice(fragments, metadata)

    @staticmethod
    def load_from_file(datafile, metadatafile):
        """Load a MixSlice from data and metadata files.

        Args:
            datafile (path): The path to the encrypted file.
            metadatafile (path): The path to the metadatafile.

        Returns:
            A new MixSlice that holds the encrypted fragments.
        """
        with open(datafile, "rb") as fp:
            data = fp.read()

        size = len(data)
        assert (size % _lib.MINI_PER_MACRO == 0) \
            and (size % _lib.MACRO_SIZE == 0), \
            "datafile must be a multiple of MINI_PER_MACRO and MACRO_SIZE"

        frag_size = size // _lib.MINI_PER_MACRO
        dataview = memoryview(data)
        fragments = [dataview[offset:offset + frag_size]
                     for offset in _xrange(0, size, frag_size)]

        metadata = _MixSliceMetadata.load_from_file(metadatafile)
        return MixSlice(fragments, metadata)

    def save_to_files(self, datafile, public_metafile, private_metafile):
        with open(datafile, "wb") as fp:
            for fragment in self._fragments:
                fp.write(fragment)

        self._metadata.save_to_file(public_metafile, private=False)
        self._metadata.save_to_file(private_metafile, private=True)

    def step_encrypt(self, fragment_id=None):
        fragment_id = (fragment_id if fragment_id is not None
                       else _random.randrange(len(self._fragments)))
        key = self._metadata.add_encryption_step(fragment_id)
        ctr = _Counter.new(128)
        cipher = _AES.new(key[:16], mode=_AES.MODE_CTR, counter=ctr)
        self._fragments[fragment_id] = cipher.encrypt(
            self._fragments[fragment_id])
        _logging.info("Encrypting frag #%d (key: %r)" % (fragment_id, key))
        return fragment_id

    def decrypt(self, threads=None, padder=None):
        fragments = self._fragments
        for fragment_id, key in self._metadata.decryption_steps():
            _logging.info("Decrypting frag #%d (key: %r)" % (fragment_id, key))
            ctr = _Counter.new(128)
            cipher = _AES.new(key[:16], mode=_AES.MODE_CTR, counter=ctr)
            fragments[fragment_id] = cipher.decrypt(fragments[fragment_id])

        padded_data = _aesmix.unslice_and_unmix(
            fragments=fragments,
            key=self._metadata._key,
            iv=self._metadata._iv,
            threads=threads)

        padder = padder or _Padder(blocksize=_lib.MACRO_SIZE)
        return padder.unpad(padded_data)
