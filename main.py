#!/usr/bin/env python

from lck import AESLCK

with open('lipsum4096.txt') as f:
    data = f.read().strip()

print('PLAINTEXT: %s' % data)

key = 'keykeykeykeykeyk'
lck = AESLCK(key)

cipher = lck.encrypt(data)
print('CIPHERTEXT: %r' % cipher)

plain = lck.decrypt(cipher)
print('DECRYPTED: %s' % plain)
