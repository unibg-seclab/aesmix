#!/usr/bin/env python

from __future__ import print_function

from six.moves import xrange

from aesmix import mixencrypt, mixdecrypt
from aesmix import t_mixencrypt, t_mixdecrypt
from aesmix import mix_and_slice, unslice_and_unmix
from aesmix import keyreg
from aesmix import MixSlice

import logging
logging.basicConfig(level=logging.DEBUG)


def test_single_thread():
    print("\n\nTest single thread")
    key = b"k" * 16
    iv = b"i" * 16

    plaintext = b"d" * 4096
    print("plaintext: %s ... %s" % (plaintext[:64], plaintext[-64:]))

    ciphertext = mixencrypt(plaintext, key, iv, to_string=True)
    print("ciphertext: %r ... %r" % (ciphertext[:64], ciphertext[-64:]))

    decrypted = mixdecrypt(ciphertext, key, iv, to_string=True)
    print("decrypted: %s ... %s" % (decrypted[:64], decrypted[-64:]))


def test_multi_thread():
    print("\n\nTest multi thread")
    key = b"k" * 16
    iv = b"i" * 16
    threads = 8

    plaintext = b"d" * (2 ** 20) * 128  # 128 MiB
    print("plaintext: %s ... %s" % (plaintext[:64], plaintext[-64:]))

    ciphertext = t_mixencrypt(plaintext, key, iv, threads, to_string=True)
    print("ciphertext: %r ... %r" % (ciphertext[:64], ciphertext[-64:]))

    decrypted = t_mixdecrypt(ciphertext, key, iv, threads, to_string=False)
    print("decrypted: %s ... %s" % (decrypted[:64], decrypted[-64:]))


def test_mix_and_slice():
    print("\n\nTest mix and slice")
    key = b"k" * 16
    iv = b"i" * 16

    plaintext = b"d" * (2 ** 20)  # 1 MiB
    print("plaintext: %s ... %s" % (plaintext[:64], plaintext[-64:]))

    fragments = mix_and_slice(plaintext, key, iv)
    print("num fragments: %s" % len(fragments))

    decrypted = unslice_and_unmix(fragments, key, iv)
    print("decrypted: %s ... %s" % (decrypted[:64], decrypted[-64:]))


def test_manager():
    print("\n\nTest mix and slice manager")
    data = b"d" * 117 + b"ata"
    key = b"k" * 16
    iv = b"i" * 16

    print("input: ", data)
    owner = MixSlice.encrypt(data, key, iv)
    owner.save_to_files("example.enc", "example.public", "example.private")

    owner = MixSlice.load_from_file("example.enc", "example.private")
    print("\nPolicy updates ...")
    for _ in xrange(int(10)):
        owner.step_encrypt()
    print("Let's also re-encrypt the same fragment")
    owner.step_encrypt(fragment_id=1)
    owner.step_encrypt(fragment_id=1)
    owner.save_to_files("example.enc", "example.public", "example.private")

    print("\nDecrypting ...")
    reader = MixSlice.load_from_file("example.enc", "example.public")
    print("\noutput: ", reader.decrypt())


if __name__ == "__main__":
    test_single_thread()
    test_multi_thread()
    test_mix_and_slice()
    keyreg._main()
    test_manager()
