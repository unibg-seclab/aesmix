#!/usr/bin/env python

from aesmix import mixencrypt, mixdecrypt, t_mixencrypt, t_mixdecrypt


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


if __name__ == "__main__":
    test_single_thread()
    test_multi_thread()
