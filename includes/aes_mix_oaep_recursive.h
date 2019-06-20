#ifndef AES_MIX_OAEP_RECURSIVE_H
#define AES_MIX_OAEP_RECURSIVE_H

#include "aes_mix_oaep.h"

void mixencrypt_oaep_recursive (
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
);

void mixdecrypt_oaep_recursive (
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
);

#endif // AES_MIX_OAEP_RECURSIVE_H
