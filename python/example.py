#!/usr/bin/env python

import aesmix

plaintext = b"d" * 4096
key = b"k" * 16
iv = b"i" * 16

print(b"plaintext: " + plaintext[:64] + b" ... " + plaintext[-64:])

ciphertext = aesmix.mixencrypt(plaintext, key, iv, to_string=True)
print(b"ciphertext: " + ciphertext[:64] + b" ... " + ciphertext[-64:])

decrypted = aesmix.mixdecrypt(ciphertext, key, iv, to_string=True)
print(b"decrypted: " + decrypted[:64] + b" ... " + decrypted[-64:])
