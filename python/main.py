#!/usr/bin/env python

from mix import AESMIX

with open('data/lipsum4096.txt') as f:
    data = f.read().strip()

print('PLAINTEXT: %s' % data)

key = 'keykeykeykeykeyk'
mix = AESMIX(key)

cipher = mix.encrypt(data)
print('CIPHERTEXT: %r' % cipher)

plain = mix.decrypt(cipher)
print('DECRYPTED: %s' % plain)
