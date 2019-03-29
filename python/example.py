#!/usr/bin/env python

from six.moves import xrange

from aesmix import mixencrypt, mixdecrypt
from aesmix import t_mixencrypt, t_mixdecrypt
from aesmix import slice
from aesmix import mix_and_slice, unslice_and_unmix
from aesmix import keyreg
from aesmix.manager import MixSlice

import logging
logging.basicConfig(level=logging.DEBUG)


def test_single_thread():
    print("\n\nTest single thread")
    key = b"k" * 16
    iv = b"i" * 16

    plaintext = b"d" * 4096
    print(b"plaintext: " + plaintext[:64] + b" ... " + plaintext[-64:])

    ciphertext = mixencrypt(plaintext, key, iv, to_string=True)
    print(b"ciphertext: " + ciphertext[:64] + b" ... " + ciphertext[-64:])

    decrypted = mixdecrypt(ciphertext, key, iv, to_string=True)
    print(b"decrypted: " + decrypted[:64] + b" ... " + decrypted[-64:])


def test_multi_thread():
    print("\n\nTest multi thread")
    key = b"k" * 16
    iv = b"i" * 16
    threads = 8

    plaintext = b"d" * (2 ** 20) * 128  # 128 MiB
    print(b"plaintext: " + plaintext[:64] + b" ... " + plaintext[-64:])

    ciphertext = t_mixencrypt(plaintext, key, iv, threads, to_string=True)
    print(b"ciphertext: " + ciphertext[:64] + b" ... " + ciphertext[-64:])

    decrypted = t_mixdecrypt(ciphertext, key, iv, threads, to_string=False)
    print(b"decrypted: " + decrypted[:64] + b" ... " + decrypted[-64:])


def test_slice():
    print("\n\nTest slice")
    mini_size = 4
    macro_size = 16
    num_macros = 4
    data = b"0123456789ABCDEF" * num_macros
    print("data: %s" % data)
    print("fragments: %s" % slice(data, mini_size, macro_size))


def test_mix_and_slice():
    print("\n\nTest mix and slice")
    key = b"k" * 16
    iv = b"i" * 16

    plaintext = b"d" * (2 ** 20)  # 1 MiB
    print(b"plaintext: " + plaintext[:64] + b" ... " + plaintext[-64:])

    fragments = mix_and_slice(plaintext, key, iv)
    print("num fragments: %s" % len(fragments))

    decrypted = unslice_and_unmix(fragments, key, iv)
    print(b"decrypted: " + decrypted[:64] + b" ... " + decrypted[-64:])


def test_manager():
    print("\n\nTest mix and slice manager")
    data = b"d" * 117 + b"ata"
    key = b"k" * 16
    iv = b"i" * 16

    print("input: ", data)
    owner = MixSlice.encrypt(data, key, iv)
    owner.save_to_files("example.out", "example.public", "example.private")

    owner = MixSlice.load_from_file("example.out", "example.private")
    print("\nPolicy updates ...")
    for _ in xrange(int(1024 ** 0.5 * 2)):
        owner.step_encrypt()
    owner.save_to_files("example.out", "example.public", "example.private")

    print("\nDecrypting ...")
    reader = MixSlice.load_from_file("example.out", "example.public")
    print("\noutput: ", reader.decrypt())


if __name__ == "__main__":
    test_single_thread()
    test_multi_thread()
    test_slice()
    test_mix_and_slice()
    keyreg._main()
    test_manager()
