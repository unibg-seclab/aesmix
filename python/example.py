#!/usr/bin/env python

from aesmix import mixencrypt, mixdecrypt, t_mixencrypt, t_mixdecrypt, slice


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

    plaintext = b"d" * (2 ** 30)  # 1 GiB
    print(b"plaintext: " + plaintext[:64] + b" ... " + plaintext[-64:])

    ciphertext = t_mixencrypt(plaintext, key, iv, threads, to_string=True)
    print(b"ciphertext: " + ciphertext[:64] + b" ... " + ciphertext[-64:])

    decrypted = t_mixdecrypt(ciphertext, key, iv, threads, to_string=False)
    print(b"decrypted: " + decrypted[:64] + b" ... " + decrypted[-64:])


def test_slice():
    mini_size = 4
    macro_size = 16
    num_macros = 4
    data = b"0123456789ABCDEF" * num_macros
    print("data: %s" % data)
    print("fragments: %s" % slice(data, mini_size, macro_size))


if __name__ == "__main__":
    test_single_thread()
    test_multi_thread()
    test_slice()
